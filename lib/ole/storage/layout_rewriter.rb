# encoding: ASCII-8BIT

require 'digest/sha1'
require 'delegate'
require 'tempfile'

class Ole::Storage
	class LayoutConflict < StandardError
		attr_reader :conflicts
		def initialize(conflicts)
			super(conflicts.map { |item| item[:message] }.join('; '))
			@conflicts = conflicts
		end
	end

	class LayoutReadOnlyIO < SimpleDelegator
		def write_nonblock(*)
			raise IOError, 'read only'
		end

		def write(*)
			raise IOError, 'read only'
		end

		def truncate(*)
			raise IOError, 'read only'
		end
	end

	def rewrite_layout(output, order=[], options={})
		LayoutRewriter.new(self, order, options).write(output)
	end

	class LayoutRewriter
		EOC = AllocationTable::EOC
		FREE = AllocationTable::AVAIL
		FAT_MARK = AllocationTable::BAT
		DIFAT_MARK = AllocationTable::META_BAT
		CHUNK_SIZE = 1 << 16

		attr_reader :before, :after, :result

		def initialize(ole, order, options)
			@ole = ole
			@alignments = {}
			(options[:alignment] || options[:align] || {}).each do |path, alignment|
				@alignments[path_key(path)] = alignment
			end
			@requested = normalize_order(order)
			@conflicts = []
			collect_streams
			validate_requests
			raise LayoutConflict, @conflicts unless @conflicts.empty?
			assign_indices(@ole.root)
			@metadata_before = metadata_snapshot(ole)
			@before = physical_snapshot(ole)
			@plan = build_plan
		end

		def write(output)
			destination, owned = open_destination(output)
			temporary_path = nil
			@output = destination.string if destination.respond_to?(:string)
			begin
				write_document(destination)
				new_ole = Ole::Storage.new(LayoutReadOnlyIO.new(destination), :update_timestamps => false)
				verify(new_ole)
			ensure
				new_ole.close if new_ole
				destination.flush rescue nil
				destination.close if owned
			end
			temporary_path = destination.path if owned && destination.respond_to?(:path) && destination.path != output
			if temporary_path
				File.rename(temporary_path, output)
				File.chmod(0644, output)
			end
			@result
		end

		private
		def normalize_order(order)
			seen = {}
			Array(order).map do |item|
				if item.is_a?(Hash)
					path = item[:path] || item[:stream]
					alignment = item[:alignment] || item[:align]
				else
					path = item
					alignment = nil
				end
				path = path_key(path)
				if path.empty? || seen[path]
					message = seen[path] ? 'duplicate stream in priority order' : 'invalid stream reference'
					@conflicts << conflict(path, message)
				end
				seen[path] = true
				@alignments[path] = alignment if alignment
				path
			end
		end

		def path_key(path)
			return stream_path(path) if path.is_a?(Dirent)
			path = path.to_s
			path = '/' + path unless path[0] == ?/
			path.squeeze('/').sub(/\/$/, '')
		end

		def stream_path(dirent)
			parent = dirent.parent
			return '' if parent.nil?
			stream_path(parent) + '/' + dirent.name
		end

		def collect_streams
			@streams = collect_stream_specs(@ole)
			@streams_by_path = Hash.new { |hash, key| hash[key] = [] }
			@streams.each { |stream| @streams_by_path[stream[:path]] << stream }
		end

		def walk_streams(dirent, path='', &block)
			dirent.children.each do |child|
				child_path = path + '/' + child.name
				if child.file?
					yield child, child_path
				else
					walk_streams(child, child_path, &block)
				end
			end
		end

		def validate_requests
			@requested.each do |path|
				specs = @streams_by_path[path]
				if specs.empty?
					@conflicts << conflict(path, 'stream not found')
				elsif specs.length > 1
					@conflicts << conflict(path, 'ambiguous stream path')
				end
			end
			@alignments.each do |path, alignment|
				next if path.empty?
				unless @streams_by_path[path] && !@streams_by_path[path].empty?
					@conflicts << conflict(path, 'alignment references unknown stream', alignment)
					next
				end
				stream = @streams_by_path[path].first
				required_sector = stream && stream[:size] >= 4096 ? 512 : 64
				unless alignment.is_a?(Integer) && alignment > 0 && alignment % required_sector == 0
					@conflicts << conflict(path, "alignment must be a positive multiple of #{required_sector}", alignment)
				end
			end
			unless @ole.header.b_shift == 9 && @ole.header.s_shift == 6 && @ole.header.threshold == 4096
				@conflicts << conflict(nil, 'only the standard 512/64 byte sector layout is supported')
			end
		end

		def conflict(stream, message, alignment=nil)
			hash = {:stream => stream, :message => message}
			hash[:alignment] = alignment if alignment
			hash
		end

		def assign_indices(dirent, index=0)
			dirent.idx = index
			return 1 if dirent.file?
			offset = 1
			dirent.children.each do |child|
				assign_indices(child, index + offset)
				offset += dirent_count(child)
			end
			offset
		end

		def dirent_count(dirent)
			return 1 if dirent.file?
			1 + dirent.children.map { |child| dirent_count(child) }.inject(0, :+)
		end

		def build_plan
			@big_size = 1 << @ole.header.b_shift
			@small_size = 1 << @ole.header.s_shift
			@small_per_big = @big_size / @small_size
			@fat_entries_per_sector = @big_size / 4
			@dirents_per_sector = @big_size / Dirent::SIZE
			@cursor = 0
			@root_blocks = []
			@mini_fat = []
			@current_root_sector = nil
			@records = []
			@requested.each { |path| allocate_stream(@streams_by_path[path].first, true) }
			close_mini_tail
			remaining = @streams.reject { |stream| @requested.include?(stream[:path]) }
			remaining.select { |stream| big?(stream) }.each { |stream| allocate_stream(stream, false) }
			remaining.reject { |stream| big?(stream) }.each { |stream| allocate_stream(stream, false) }
			close_mini_tail
			finish_plan
		end

		def big?(stream)
			stream[:size] >= @ole.header.threshold
		end

		def allocate_stream(stream, hot)
			if big?(stream)
				allocate_big(stream, hot)
			else
				allocate_small(stream, hot)
			end
		end

		def allocate_big(stream, hot)
			close_mini_tail
			@current_root_sector = nil
			count = sector_count(stream[:size], @big_size)
			alignment = alignment_for(stream, @big_size)
			start = @cursor
			start += 1 until ((start + 1) * @big_size) % alignment == 0
			blocks = (start...(start + count)).to_a
			@cursor = start + count
			@records << record(stream, hot, :big, blocks)
		end

		def allocate_small(stream, hot)
			count = sector_count(stream[:size], @small_size)
			if count == 0
				@records << record(stream, hot, :small, [], 0)
				return
			end
			alignment = alignment_for(stream, @small_size)
			mini_start = @mini_fat.length
			blocks = contiguous_small_blocks(count, alignment)
			blocks.each_with_index do |block, index|
				@mini_fat << (index + 1 == blocks.length ? EOC : mini_start + index + 1)
			end
			@records << record(stream, hot, :small, blocks, mini_start)
		end

		def contiguous_small_blocks(count, alignment)
			mini_index = @mini_fat.length
			local_offset = 0
			if @current_root_sector
				root_sector = @current_root_sector
				used = mini_index % @small_per_big
				root_index = mini_index / @small_per_big
				physical_root_sector = root_sector + root_index
				local_offset = used % @small_per_big
				physical_offset = (physical_root_sector + 1) * @big_size + local_offset * @small_size
				remaining = @small_per_big - (used % @small_per_big)
				next_sector_available = physical_root_sector + 1 == @cursor
				if physical_offset % alignment == 0 && (count <= remaining || next_sector_available)
					local_offset = used % @small_per_big
					return small_blocks(root_sector, local_offset, count)
				end
				close_mini_tail
				@current_root_sector = nil
			end
			start = @cursor
			start += 1 until ((start + 1) * @big_size) % alignment == 0
			@current_root_sector = start
			small_blocks(start, 0, count)
		end

		def small_blocks(physical_start, local_offset, count)
			blocks = (0...count).map do |index|
				overall = local_offset + index
				[physical_start + overall / @small_per_big, overall % @small_per_big]
			end
			extend_root_chain(physical_start, local_offset, count)
			blocks
		end

		def extend_root_chain(physical_start, local_offset, count)
			((local_offset + count - 1) / @small_per_big).succ.times do |index|
				block = physical_start + index
				unless @root_blocks.include?(block)
					@root_blocks << block
					@cursor = block + 1
				end
			end
		end

		def close_mini_tail
			@mini_fat << FREE while @mini_fat.length % @small_per_big != 0
		end

		def alignment_for(stream, default)
			@alignments[stream[:path]] || default
		end

		def sector_count(size, sector_size)
			(size / sector_size.to_f).ceil
		end

		def record(stream, hot, kind, blocks, mini_start=nil)
			hash = {:stream => stream, :hot => hot, :kind => kind, :blocks => blocks}
			hash[:mini_start] = mini_start if mini_start
			hash
		end

		def finish_plan
			mini_fat_sectors = sector_count(@mini_fat.length, @fat_entries_per_sector)
			dirent_count = count_dirents(@ole.root)
			directory_sectors = sector_count(dirent_count, @dirents_per_sector)
			fat_sectors = 1
			difat_sectors = 0
			total_sectors = @cursor
			loop do
				difat_sectors = [((fat_sectors - 109).to_f / 127).ceil, 0].max
				candidate = @cursor + mini_fat_sectors + directory_sectors + fat_sectors + difat_sectors
				new_fat_sectors = sector_count(candidate, @fat_entries_per_sector)
				new_difat_sectors = [((new_fat_sectors - 109).to_f / 127).ceil, 0].max
				candidate = @cursor + mini_fat_sectors + directory_sectors + new_fat_sectors + new_difat_sectors
				new_total_fat = sector_count(candidate, @fat_entries_per_sector)
				break if new_total_fat == fat_sectors && new_difat_sectors == difat_sectors
				fat_sectors = new_total_fat
				difat_sectors = new_difat_sectors
				total_sectors = candidate
			end
			difat_sectors = [((fat_sectors - 109).to_f / 127).ceil, 0].max
			total_sectors = @cursor + mini_fat_sectors + directory_sectors + fat_sectors + difat_sectors
			mini_fat_start = @cursor
			directory_start = mini_fat_start + mini_fat_sectors
			fat_start = directory_start + directory_sectors
			difat_start = fat_start + fat_sectors
			{
				:root_blocks => @root_blocks, :mini_fat => @mini_fat, :records => @records,
				:root_size => @mini_fat.length * @small_size,
				:mini_fat_start => mini_fat_start, :mini_fat_sectors => mini_fat_sectors,
				:directory_start => directory_start, :directory_sectors => directory_sectors,
				:fat_start => fat_start, :fat_sectors => fat_sectors,
				:difat_start => difat_start, :difat_sectors => difat_sectors,
				:total_sectors => total_sectors, :dirent_count => dirent_count
			}
		end

		def count_dirents(dirent)
			dirent_count(dirent)
		end

		def open_destination(output)
			case output
			when :string, StringIO
				destination = output == :string ? StringIO.new(''.dup) : output
				destination.binmode if destination.respond_to?(:binmode)
				destination.rewind
				destination.truncate(0)
				[destination, output == :string]
			when String
				raise ArgumentError, 'output file already exists' if File.exist?(output)
				destination = Tempfile.new(['ole-layout', '.ole'], File.dirname(output))
				destination.binmode
				[destination, true]
			else
				raise ArgumentError, 'cannot rewrite into the source OLE container' if output.equal?(@ole.io)
				output.rewind
				output.truncate(0)
				[output, false]
			end
		end

		def write_document(destination)
			zero_fill(destination, @plan[:total_sectors] * @big_size)
			write_header(destination)
			write_mini_fat(destination)
			write_directory(destination)
			write_fat(destination)
			write_difat(destination)
			write_stream_data(destination)
			destination.seek(0, IO::SEEK_END)
		end

		def zero_fill(destination, size)
			destination.truncate(0)
			padding = 0.chr * CHUNK_SIZE
			written = 0
			while written < size
				chunk = [CHUNK_SIZE, size - written].min
				destination.write(padding[0, chunk])
				written += chunk
			end
		end

		def write_header(destination)
			header = @ole.header.to_a.dup
			header[8] = 0
			header[9] = @plan[:fat_sectors]
			header[10] = @plan[:directory_start]
			header[13] = @plan[:mini_fat_sectors].zero? ? EOC : @plan[:mini_fat_start]
			header[14] = @plan[:mini_fat_sectors]
			header[15] = @plan[:difat_sectors].zero? ? EOC : @plan[:difat_start]
			header[16] = @plan[:difat_sectors]
			fat_ids = (@plan[:fat_start]...(@plan[:fat_start] + @plan[:fat_sectors])).to_a
			fat_ids += [FREE] * (109 - fat_ids.length) if fat_ids.length < 109
			destination.seek(0)
			destination.write(Ole::Storage::Header.new(header).to_s + fat_ids.pack('V109'))
		end

		def write_mini_fat(destination)
			return if @plan[:mini_fat_sectors].zero?
			data = @plan[:mini_fat].pack('V*')
			data += [FREE].pack('V') * (@plan[:mini_fat_sectors] * @fat_entries_per_sector - @plan[:mini_fat].length)
			write_at(destination, (@plan[:mini_fat_start] + 1) * @big_size, data)
		end

		def write_directory(destination)
			dirents = @ole.root.flatten
			data = dirents.map { |dirent| serialize_dirent(dirent) }.join
			data += 0.chr * (@plan[:directory_sectors] * @big_size - data.length)
			write_at(destination, (@plan[:directory_start] + 1) * @big_size, data)
		end


		def serialize_dirent(dirent)
			values = dirent.to_a.dup
			if dirent.type == :root
				values[11] = @plan[:root_blocks].empty? ? EOC : @plan[:root_blocks].first
				values[12] = @plan[:root_size]
				values[13] = 0.chr * 4
			elsif dirent.file?
				directory_entry = find_record(dirent)
				blocks = directory_entry[:blocks]
				values[11] = blocks.empty? ? EOC : directory_entry[:mini_start]
				values[11] = blocks.first if directory_entry[:kind] == :big
				values[12] = dirent.size
				values[13] = 0.chr * 4
			else
				values[11] = Dirent::EOT
			end
			values.pack(Dirent::PACK)
		end

		def find_record(dirent)
			path = stream_path(dirent)
			record = @plan[:records].find { |item| item[:stream][:path] == path }
			raise FormatError, "missing layout record for #{path}" unless record
			record
		end

		def write_fat(destination)
			fat = [FREE] * @plan[:total_sectors]
			mark_chain(fat, @plan[:root_blocks]) unless @plan[:root_blocks].empty?
			mark_chain(fat, (@plan[:mini_fat_start]...(@plan[:mini_fat_start] + @plan[:mini_fat_sectors])).to_a)
			mark_chain(fat, (@plan[:directory_start]...(@plan[:directory_start] + @plan[:directory_sectors])).to_a)
			mark_chain(fat, (@plan[:fat_start]...(@plan[:fat_start] + @plan[:fat_sectors])).to_a, FAT_MARK)
			mark_chain(fat, (@plan[:difat_start]...(@plan[:difat_start] + @plan[:difat_sectors])).to_a, DIFAT_MARK)
			@plan[:records].select { |record| record[:kind] == :big }.each do |record|
				mark_chain(fat, record[:blocks])
			end
			data = fat.pack('V*')
			write_at(destination, (@plan[:fat_start] + 1) * @big_size, data)
		end

		def mark_chain(fat, blocks, terminal=EOC)
			blocks.each_with_index { |block, index| fat[block] = index + 1 == blocks.length ? terminal : blocks[index + 1] }
		end

		def write_difat(destination)
			return if @plan[:difat_sectors].zero?
			fat_ids = (@plan[:fat_start]...(@plan[:fat_start] + @plan[:fat_sectors])).to_a[109..-1]
			groups = fat_ids.each_slice(127).to_a
			groups.each_with_index do |group, index|
				next_sector = index + 1 == groups.length ? FREE : @plan[:difat_start] + index + 1
				values = group + [next_sector]
				values += [FREE] * (128 - values.length)
				write_at(destination, (@plan[:difat_start] + index + 1) * @big_size, values.pack('V*'))
			end
		end

		def write_stream_data(destination)
			@plan[:records].each do |record|
				dirent = record[:stream][:dirent]
				digest = Digest::SHA1.new
				if record[:kind] == :big
					copy_stream(dirent, @ole.bbat, destination, record[:blocks], @big_size, digest)
				else
					copy_small_stream(dirent, destination, record, digest)
				end
			end
		end

		def copy_small_stream(dirent, destination, record, digest)
			return if record[:blocks].empty?
			input = @ole.sbat.open(record[:stream][:dirent].first_block, dirent.size)
			write_stream_chunks(input, destination, record[:blocks], @big_size, @small_size, dirent.size, digest)
		end

		def copy_stream(dirent, bat, destination, blocks, sector_size, digest)
			input = bat.open(dirent.first_block, dirent.size)
			write_stream_chunks(input, destination, blocks, sector_size, sector_size, dirent.size, digest)
		end

		def write_stream_chunks(input, destination, blocks, sector_size, block_size, size, digest)
			offset = 0
			blocks.each do |block|
				if block.is_a?(Array)
					physical_block, small_offset = block
					position = (physical_block + 1) * sector_size + small_offset * block_size
				else
					position = (block + 1) * sector_size
				end
				remaining = size - offset
				break if remaining <= 0
				target_length = [block_size, remaining].min
				copied = 0
				while copied < target_length
					chunk = input.read([CHUNK_SIZE, target_length - copied].min)
					raise FormatError, 'unexpected end of stream' unless chunk && !chunk.empty?
					digest.update(chunk)
					write_at(destination, position + copied, chunk)
					copied += chunk.length
				end
				offset += target_length
			end
		end

		def write_at(destination, offset, data)
			destination.seek(offset)
			destination.write(data)
		end

		def metadata_snapshot(storage)
			snapshot = {}
			walk_dirents(storage.root) do |dirent, path|
				snapshot[path] = {
					:type => dirent.type,
					:name => dirent.name,
					:clsid => dirent.clsid.dup, :flags => dirent.flags,
					:create_time => dirent.create_time_str.to_s.dup,
					:modify_time => dirent.modify_time_str.to_s.dup,
					:size => dirent.size, :colour => dirent.colour
				}
			end
		snapshot
		end

		def walk_dirents(dirent, path='', &block)
			yield dirent, path
			return if dirent.file?
			dirent.children.each { |child| walk_dirents(child, path + '/' + child.name, &block) }
		end

		def physical_snapshot(storage)
			hashes = {}
			walk_streams(storage.root) do |dirent, path|
				digest = Digest::SHA1.new
				dirent.open { |io| io.rewind; copy_for_hash(io, digest) }
				hashes[path] = digest.hexdigest
			end
			stream_specs = collect_stream_specs(storage)
			streams = stream_specs.map do |stream|
				path = stream[:path]
				ranges = source_ranges(storage, stream[:dirent])
				{
					:path => path, :size => stream[:dirent].size,
					:ranges => ranges, :intervals => ranges.length,
					:sha1 => hashes[path]
				}
			end
			{
				:streams => streams,
				:total_intervals => streams.inject(0) { |sum, stream| sum + stream[:intervals] }
			}
		end

		def collect_stream_specs(storage)
			specs = []
			walk_streams(storage.root) { |dirent, path| specs << {:dirent => dirent, :path => path, :size => dirent.size} }
			specs
		end

		def copy_for_hash(io, digest)
			loop do
				chunk = io.read(CHUNK_SIZE)
				break unless chunk && !chunk.empty?
				digest.update(chunk)
			end
		end

		def source_ranges(storage, dirent)
			return [] if dirent.size == 0
			if dirent.size >= storage.header.threshold
				chain = storage.bbat.chain(dirent.first_block)
				ranges = chain.map { |block| [(block + 1) * big_size(storage), big_size(storage)] }
			else
				mini_chain = storage.sbat.chain(dirent.first_block)
				root_chain = storage.bbat.chain(storage.root.first_block)
				ranges = mini_chain.map do |mini_block|
					root_block = root_chain[mini_block / small_per_big(storage)]
					offset = mini_block % small_per_big(storage)
					[(root_block + 1) * big_size(storage) + offset * small_size(storage), small_size(storage)]
				end
			end
			trim_ranges(merge_ranges(ranges), dirent.size)
		end

		def big_size(storage)
			1 << storage.header.b_shift
		end

		def small_size(storage)
			1 << storage.header.s_shift
		end

		def small_per_big(storage)
			big_size(storage) / small_size(storage)
		end

		def merge_ranges(ranges)
			merged = []
			ranges.each do |offset, length|
				if merged.last && merged.last[0] + merged.last[1] == offset
					merged.last[1] += length
				else
					merged << [offset, length]
				end
			end
			merged
		end

		def trim_ranges(ranges, size)
			return ranges if ranges.empty?
			excess = ranges.inject(0) { |sum, range| sum + range[1] } - size
			if excess > 0
				ranges.last[1] -= excess
			end
			ranges
		end

		def verify(new_ole)
			after = physical_snapshot(new_ole)
			after[:streams].each do |stream|
				raise FormatError, "hash mismatch for #{stream[:path]}" unless stream[:sha1] == @before[:streams].find { |item| item[:path] == stream[:path] }[:sha1]
			end
			verify_metadata(new_ole)
			verify_hot_layout(after)
			@after = after
			@result = {
				:before => @before, :after => after,
				:plan => @plan, :conflicts => [], :output => @output
			}
		end

		def verify_metadata(new_ole)
			walk_dirents(new_ole.root) do |dirent, path|
				expected = @metadata_before[path]
				raise FormatError, "metadata mismatch for #{path}" unless expected
				raise FormatError, "metadata mismatch for #{path}" unless
					expected[:type] == dirent.type &&
					expected[:name] == dirent.name &&
					expected[:clsid] == dirent.clsid &&
					expected[:flags] == dirent.flags &&
					expected[:create_time] == dirent.create_time_str.to_s &&
					expected[:modify_time] == dirent.modify_time_str.to_s &&
					(dirent.type == :root || expected[:size] == dirent.size) &&
					expected[:colour] == dirent.colour
			end
		end

		def verify_hot_layout(snapshot)
			hot = @requested.map do |path|
				snapshot[:streams].find { |stream| stream[:path] == path }
			end.reject { |stream| stream[:ranges].empty? }
			hot.each_cons(2) do |first, second|
				first_end = first[:ranges].map { |range| range[0] + range[1] }.max
				second_start = second[:ranges].first[0]
				raise FormatError, "hot streams not placed in requested order: #{first[:path]} #{second[:path]}" if second_start < first_end
			end
		end
	end
end
