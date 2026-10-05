# encoding: ASCII-8BIT

module Ole
	class Storage
		class AllocationIssue < Struct.new(:code, :message, :sectors, :mini_sectors, :objects)
			def initialize code, message, sectors=[], mini_sectors=[], objects=[]
				super code, message, Array(sectors), Array(mini_sectors), Array(objects)
			end

			def to_h
				members.zip(values).inject({}) { |h, (k, v)| h[k] = v; h }
			end
		end

		class AllocationReport < Struct.new(:sector_size, :mini_sector_size, :sector_count, :fat, :owners, :mini_owners, :chains, :issues)
			def valid?
				issues.empty?
			end

			def to_h
				h = {}
				members.each { |k| h[k] = self[k] }
				h[:valid] = valid?
				h
			end
		end

		class AllocationValidator
			HEADER_PACK = 'a8 a16 v2 a2 v2 a6 V3 a4 V5'
			MAGIC = "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
			DIRECTORY_ENTRY_SIZE = 128

			attr_reader :issues

			def initialize io
				@io = io
				@issues = []
				@owners = {}
				@mini_owners = {}
				@chains = []
				@chain_end_sectors = {}
				@cross_linked_sectors = {}
				@cross_linked_mini_sectors = {}
				@fat = []
				@fat_sectors = []
				@difat_sectors = []
			end

			def validate
				saved_pos = @io.pos rescue nil
				@io.rewind if @io.respond_to?(:rewind)
				begin
					run
				ensure
					@io.pos = saved_pos if saved_pos && @io.respond_to?(:pos=)
				end
				report
			end

			private

			def run
				header = @io.read(512)
				if !header || header.length < 512
					issue :truncated_header, 'header is shorter than 512 bytes'
					return
				end

				values = header.unpack(HEADER_PACK)
				@magic, @clsid, @minor_version, @major_version, @byte_order, @sector_shift, @mini_shift,
					@reserved, @reserved_sectors, @fat_count, @directory_start, @transaction_signature,
					@mini_cutoff, @minifat_start, @minifat_count, @difat_start, @difat_count = values

				if @magic != MAGIC
					issue :invalid_signature, 'OLE2 signature is invalid'
				end
				if @byte_order != "\xfe\xff"
					issue :invalid_byte_order, 'byte order must be 0xfffe'
				end
				unless [9, 12].include?(@sector_shift)
					issue :invalid_sector_size, "sector shift must be 9 or 12, was #{@sector_shift.inspect}"
					return
				end

				@sector_size = 1 << @sector_shift
				@mini_sector_size = @mini_shift == 6 ? 64 : (1 << @mini_shift rescue nil)
				unless @mini_sector_size == 64
					issue :invalid_mini_sector_size, "mini sector size must be 64 bytes, was #{@mini_sector_size.inspect}"
					@mini_sector_size = 64
				end
				if @mini_cutoff != 4096
					issue :invalid_mini_cutoff, "mini stream cutoff must be 4096, was #{@mini_cutoff.inspect}"
				end

				file_size = @io.size
				if file_size < @sector_size
					issue :truncated_file, "file is shorter than one #{@sector_size}-byte sector"
					@sector_count = 0
				else
					@sector_count = (file_size - @sector_size) / @sector_size
					remainder = (file_size - @sector_size) % @sector_size
					if remainder != 0
						issue :partial_sector, "file has #{remainder} trailing bytes after the last complete sector"
					end
				end

				parse_difat header
				parse_fat
				parse_directory
				parse_minifat
				parse_streams
				check_fat_markers
				check_mini_markers
			end

			def report
				AllocationReport.new @sector_size, @mini_sector_size, @sector_count, @fat.dup, @owners.dup, @mini_owners.dup, @chains.dup, @issues.dup
			end

			def issue code, message, sectors=[], mini_sectors=[], objects=[]
				@issues << AllocationIssue.new(code, message, sectors, mini_sectors, objects)
			end

			def special? value
				value && value >= AllocationTable::META_BAT
			end

			def regular? value
				value.is_a?(Integer) && value < AllocationTable::META_BAT
			end

			def read_sector sector
				return nil unless regular?(sector) && sector < @sector_count
				@io.seek @sector_size * (sector + 1)
				data = @io.read @sector_size
				data && data.length == @sector_size ? data : nil
			end

			def parse_difat header
				entries = []
				difat_entries = []
				seen = {}
				chain_seen = {}
				next_sector = @difat_start

				(0...@difat_count).each do |chain_index|
					if chain_seen[next_sector]
						issue :chain_cycle, "DIFAT chain is cyclic at sector #{next_sector}", [next_sector], [], [object(:difat)]
						return
					end
				if special?(next_sector)
					issue :invalid_difat_pointer, "DIFAT chain #{chain_index} uses special pointer 0x#{next_sector.to_s(16)}", [next_sector].select { |v| regular?(v) }
					return
				elsif !regular?(next_sector) || next_sector >= @sector_count
					issue :sector_out_of_bounds, "DIFAT sector #{next_sector} is outside the file", [], [], [object(:difat)]
					return
				end

				chain_seen[next_sector] = true
				@difat_sectors << next_sector

				data = read_sector(next_sector)
				unless data
					issue :truncated_sector, "DIFAT sector #{next_sector} cannot be read", [next_sector], [], [object(:difat)]
					return
				end

				values = data.unpack('V*')
				entries.concat values[0, values.length - 1]
				difat_entries.concat values[0, values.length - 1]
				next_sector = values.last
			end

				header_entries = header[Header::SIZE, 109 * 4].unpack('V*')
				header_entries[@fat_count, 109 - @fat_count].to_a.each_with_index do |marker, offset|
					index = @fat_count + offset
					next if index >= 109 || marker == AllocationTable::AVAIL || marker == 0
					issue :invalid_fat_pointer, "unused header DIFAT slot #{index} must be FREESECT, not 0x#{marker.to_s(16)}"
				end
				entries = header_entries[0, @fat_count].to_a + entries

				if @difat_count == 0 && ![AllocationTable::EOC, AllocationTable::AVAIL].include?(@difat_start)
					issue :invalid_difat_terminator, "DIFAT start must be ENDOFCHAIN or FREESECT when no DIFAT sectors are declared"
				elsif @difat_count > 0 && next_sector != AllocationTable::EOC
					issue :invalid_difat_terminator, "DIFAT chain terminates with 0x#{next_sector.to_s(16)} instead of ENDOFCHAIN", @difat_sectors, [], [object(:difat)]
				end

				active_entries = entries[0, @fat_count] || entries
				if @difat_count > 0 && regular?(next_sector) && next_sector != @difat_start && active_entries.include?(next_sector)
					issue :cross_linked_sector, "DIFAT next pointer #{next_sector} points to a FAT sector", [next_sector], [], [object(:difat), object(:fat)]
				end
				@difat_sectors.each { |sector| claim sector, object(:difat) }
				active_entries.each_with_index do |sector, index|
					if sector == AllocationTable::AVAIL
						issue :invalid_fat_pointer, "DIFAT slot #{index} must reference a FAT sector, not FREESECT"
					elsif sector == AllocationTable::EOC
						issue :invalid_fat_pointer, "DIFAT slot #{index} must reference a FAT sector, not ENDOFCHAIN"
						next
					end
					if !regular?(sector)
						issue :invalid_fat_pointer, "DIFAT slot #{index} contains special marker 0x#{sector.to_s(16)}"
					elsif sector >= @sector_count
						issue :sector_out_of_bounds, "FAT sector #{sector} referenced by DIFAT is outside the file", [], [], [object(:fat)]
					elsif seen[sector]
						issue :duplicate_fat_sector, "FAT sector #{sector} is referenced more than once by DIFAT", [sector], [], [object(:fat)]
					else
						seen[sector] = true
						@fat_sectors << sector
						claim sector, object(:fat)
					end
				end

				active = active_entries.find_all { |v| v != AllocationTable::AVAIL && v != AllocationTable::EOC }.length
				if active != @fat_count
					issue :difat_count_mismatch, "header declares #{@fat_count} FAT sectors but DIFAT lists #{active}", @fat_sectors
				end
				unused_count = entries.length - @fat_count - @difat_count
				extra_entries = difat_entries
				extra_active_count = [@fat_count - 109, 0].max
				extra_entries[extra_active_count..-1].to_a.each_with_index do |marker, offset|
					next if marker == AllocationTable::AVAIL || marker == 0
					index = 109 + extra_active_count + offset
					issue :invalid_fat_pointer, "unused DIFAT slot #{index} must be FREESECT, not 0x#{marker.to_s(16)}"
				end
				@chains << {:owner => object(:difat), :sectors => @difat_sectors.dup}
			end

			def parse_fat
				@fat_sectors.each do |sector|
					data = read_sector(sector)
					if data
						@fat.concat data.unpack('V*')
					else
						issue :truncated_sector, "FAT sector #{sector} cannot be read", [sector], [], [object(:fat)]
						@fat.concat [AllocationTable::AVAIL] * (@sector_size / 4)
					end
				end
				@chains << {:owner => object(:fat), :sectors => @fat_sectors.dup}
			end

			def object kind, extra={}
				{:kind => kind.to_s}.merge(extra)
			end

			def claim sector, owner
				existing = @owners[sector]
				if existing && existing != owner
					issue :cross_linked_sector, "sector #{sector} is claimed by #{owner_name(existing)} and #{owner_name(owner)}", [sector], [], [existing, owner]
					@cross_linked_sectors[sector] = true
					return false
				end
				@owners[sector] = owner unless existing
				true
			end

			def owner_name owner
				owner[:name] ? "#{owner[:kind]}:#{owner[:name]}" : owner[:kind]
			end

			def follow_chain start, owner, expected=nil
				sectors = []
				seen = {}
				current = start
				terminated = false

				if special?(current)
					if expected == 0 && [AllocationTable::EOC, AllocationTable::AVAIL].include?(current)
						terminated = true
					else
						issue :invalid_start_marker, "#{owner_name(owner)} starts with special marker 0x#{current.to_s(16)}", [], [], [owner]
					end
				elsif !regular?(current)
					issue :invalid_pointer, "#{owner_name(owner)} starts with invalid pointer #{current.inspect}", [], [], [owner]
				elsif current >= @sector_count
					issue :sector_out_of_bounds, "#{owner_name(owner)} starts outside the file at sector #{current}", [], [], [owner]
				end

				while regular?(current)
					if current >= @sector_count
						issue :sector_out_of_bounds, "#{owner_name(owner)} points outside the file at sector #{current}", sectors, [], [owner]
						break
					elsif seen[current]
						issue :chain_cycle, "#{owner_name(owner)} is cyclic at sector #{current}", sectors + [current], [], [owner]
						sectors << current
						break
					end

					seen[current] = true
					claimed = claim(current, owner)
					sectors << current
					break unless claimed

					pointer = @fat[current]
					if pointer.nil?
						issue :fat_truncated, "FAT has no entry for allocated sector #{current}", [current], [], [owner]
						break
					elsif pointer == AllocationTable::EOC
						@chain_end_sectors[current] = owner
						terminated = true
						break
					elsif pointer == AllocationTable::AVAIL
						issue :chain_terminated_early, "#{owner_name(owner)} reaches FREESECT at sector #{current}", sectors, [], [owner]
						break
					elsif special?(pointer)
						issue :invalid_special_marker, "#{owner_name(owner)} sector #{current} points to special marker 0x#{pointer.to_s(16)}", sectors, [], [owner]
						@chain_end_sectors.delete(sectors.first) if sectors.length > 1
						break
					end

					current = pointer
				end

				if expected
					if sectors.length < expected
						issue :declared_length_too_short, "#{owner_name(owner)} declares #{expected} sectors but reaches #{sectors.length}", sectors, [], [owner]
					elsif sectors.length > expected && terminated
						issue :declared_length_too_long, "#{owner_name(owner)} declares #{expected} sectors but reaches #{sectors.length}", sectors, [], [owner]
					end
				end

				@chains << {:owner => owner, :sectors => sectors}
				sectors
			end

			def parse_directory
				owner = object(:directory)
				sectors = follow_chain @directory_start, owner
				data = sectors.map { |sector| read_sector(sector) }.join
				@directory_entries = []

				offset = 0
				while offset + DIRECTORY_ENTRY_SIZE <= data.length
					raw = data[offset, DIRECTORY_ENTRY_SIZE]
					values = raw.unpack(Dirent::PACK)
					type_id = values[2]
					break if type_id == 0
					directory_index = offset / DIRECTORY_ENTRY_SIZE

				entry = {
					:index => directory_index,
					:raw => values,
					:type_id => type_id,
					:first_block => values[11],
					:size_low => values[12],
					:size_reserved => values[13],
					:name => decode_directory_name(values[0], values[1])
				}
				size_high = @major_version == 4 ? entry[:size_reserved].unpack('V').first : 0
				entry[:size] = entry[:size_low] + (size_high << 32)
				if @major_version != 4 && entry[:size_reserved] != 0.chr * 4
					issue :invalid_stream_size, "directory entry #{entry[:index]} has non-zero reserved stream size field", sectors, [], [stream_owner(entry)]
				end
					@directory_entries << entry

					unless Dirent::TYPE_MAP.key?(type_id)
						issue :invalid_directory_type, "directory entry #{entry[:index]} has unsupported type #{type_id}", sectors, [], [object('directory_entry', :index => entry[:index], :name => entry[:name])]
					end
					offset += DIRECTORY_ENTRY_SIZE
				end

				roots = @directory_entries.find_all { |entry| entry[:type_id] == 5 }
				if roots.length != 1
					issue :invalid_root_entry, "expected exactly one root directory entry, found #{roots.length}", sectors
				end
				@root_entry = roots.first

				@directory_entries.each do |entry|
					next unless entry[:type_id] == 1
					unless entry[:first_block] == Dirent::EOT
						issue :invalid_storage_pointer, "storage #{entry[:name].inspect} must not have a starting sector", sectors, [], [stream_owner(entry)]
					end
				end
			end

			def decode_directory_name raw, length
				length = [length.to_i, 64].min
				name = raw.byteslice(0, length).to_s
				name = name.byteslice(0, name.bytesize - 2) if name.bytesize >= 2 && name.byteslice(-2, 2) == "\x00\x00"
				if name.respond_to?(:encode)
					name.encode('UTF-8', 'UTF-16LE', :invalid => :replace, :undef => :replace).delete("\x00")
				else
					name
				end
			end

			def stream_owner entry, kind=:stream
				object kind, :name => entry[:name], :directory_entry => entry[:index]
			end

			def parse_minifat
				owner = object(:minifat)
				sectors = follow_chain @minifat_start, owner, @minifat_count
				@minifat = sectors.map { |sector| read_sector(sector) }.join.unpack('V*')
			end

			def parse_streams
				return unless @root_entry

				root_owner = object(:root_mini_stream, :name => @root_entry[:name], :directory_entry => 0)
				expected_root_sectors = (@root_entry[:size].to_f / @sector_size).ceil
				root_sectors = follow_chain @root_entry[:first_block], root_owner, expected_root_sectors
				@root_sectors = root_sectors
				@root_capacity = root_sectors.length * @sector_size
				@mini_per_big_sector = @sector_size / @mini_sector_size

				@directory_entries.each do |entry|
					next unless entry[:type_id] == 2
					if entry[:size] < @mini_cutoff
						follow_mini_stream entry
					else
						follow_big_stream entry
					end
				end
			end

			def follow_big_stream entry
				owner = stream_owner(entry, :stream)
				expected = (entry[:size].to_f / @sector_size).ceil
				if entry[:size] == 0 && special?(entry[:first_block]) && ![AllocationTable::EOC, AllocationTable::AVAIL].include?(entry[:first_block])
					issue :invalid_start_marker, "empty stream #{entry[:name].inspect} starts with special marker 0x#{entry[:first_block].to_s(16)}", [], [], [owner]
				end
				follow_chain entry[:first_block], owner, expected
			end

			def follow_mini_stream entry
				owner = stream_owner(entry, :mini_stream)
				expected = (entry[:size].to_f / @mini_sector_size).ceil
				current = entry[:first_block]
				mini_sectors = []
				seen = {}

				if expected == 0
					unless [AllocationTable::EOC, AllocationTable::AVAIL].include?(current)
						issue :invalid_start_marker, "empty mini stream #{entry[:name].inspect} must start with ENDOFCHAIN or FREESECT", [], [], [owner]
					end
					@chains << {:owner => owner, :mini_sectors => []}
					return
				elsif special?(current) || !regular?(current)
					issue :invalid_start_marker, "mini stream #{entry[:name].inspect} starts with invalid marker 0x#{current.to_s(16)}", [], [], [owner]
					@chains << {:owner => owner, :mini_sectors => []}
					return
				end

				while regular?(current)
					if current >= @minifat.length
						issue :mini_sector_out_of_bounds, "mini stream #{entry[:name].inspect} indexes miniFAT entry #{current} beyond the miniFAT", mini_sectors, [], [owner]
						break
					elsif seen[current]
						issue :chain_cycle, "mini stream #{entry[:name].inspect} is cyclic at mini sector #{current}", [], mini_sectors + [current], [owner]
						mini_sectors << current
						break
				end

				seen[current] = true
				claimed = claim_mini_sector(current, owner)
				mini_sectors << current
				break unless claimed

				pointer = @minifat[current]
					if pointer == AllocationTable::EOC
						break
					elsif pointer == AllocationTable::AVAIL
						issue :chain_terminated_early, "mini stream #{entry[:name].inspect} reaches FREESECT at mini sector #{current}", [], mini_sectors, [owner]
						break
					elsif special?(pointer)
						issue :invalid_special_marker, "mini stream #{entry[:name].inspect} points to special marker 0x#{pointer.to_s(16)} at mini sector #{current}", [], mini_sectors, [owner]
						break
					end

					current = pointer
				end

				if mini_sectors.length < expected
					issue :declared_length_too_short, "mini stream #{entry[:name].inspect} declares #{expected} mini sectors but reaches #{mini_sectors.length}", [], mini_sectors, [owner]
				elsif mini_sectors.length > expected
					issue :declared_length_too_long, "mini stream #{entry[:name].inspect} declares #{expected} mini sectors but reaches #{mini_sectors.length}", [], mini_sectors, [owner]
				end

				@chains << {:owner => owner, :mini_sectors => mini_sectors}
			end

			def claim_mini_sector mini_sector, owner
				existing = @mini_owners[mini_sector]
				if existing && existing != owner
					issue :cross_linked_mini_sector, "mini sector #{mini_sector} is claimed by #{owner_name(existing)} and #{owner_name(owner)}", [], [mini_sector], [existing, owner]
					@cross_linked_mini_sectors ||= {}
					@cross_linked_mini_sectors[mini_sector] = true
					@mini_owners[mini_sector] = {:kind => 'conflict', :mini_sector => mini_sector}
					return false
				end
				@mini_owners[mini_sector] = owner unless existing

				if mini_sector * @mini_sector_size >= @root_capacity
					issue :mini_sector_outside_root, "mini sector #{mini_sector} is outside the allocated root mini stream", [], [mini_sector], [owner, object(:root_mini_stream, :name => @root_entry[:name])]
					return false
				end

				big_sector = @root_sectors[mini_sector / @mini_per_big_sector]
				if big_sector
					offset = (mini_sector % @mini_per_big_sector) * @mini_sector_size
					@mini_owners[mini_sector] = owner.merge(:big_sector => big_sector, :offset => offset)
				end
				true
			end

			def check_fat_markers
				(0...@sector_count).each do |sector|
					marker = @fat[sector]
					owner = @owners[sector]

					case marker
					when nil
						issue :fat_truncated, "allocated sector #{sector} is not covered by the FAT", [sector], [], owner ? [owner] : []
					when AllocationTable::BAT
						unless owner && (owner[:kind] == 'fat' || @cross_linked_sectors[sector])
							issue :invalid_special_marker, "sector #{sector} is marked FAT but is #{owner ? owner_name(owner) : 'unclaimed'}", [sector], [], owner ? [owner, object(:fat)] : [object(:fat)]
						end
					when AllocationTable::META_BAT
						unless owner && (owner[:kind] == 'difat' || @cross_linked_sectors[sector])
							issue :invalid_special_marker, "sector #{sector} is marked DIFAT but is #{owner ? owner_name(owner) : 'unclaimed'}", [sector], [], owner ? [owner, object(:difat)] : [object(:difat)]
						end
					when AllocationTable::AVAIL
						if owner
							issue :invalid_special_marker, "sector #{sector} is claimed by #{owner_name(owner)} but marked FREESECT", [sector], [], [owner]
						end
					when AllocationTable::EOC
						if owner && !@cross_linked_sectors[sector] && @chain_end_sectors[sector] != owner
							issue :invalid_special_marker, "sector #{sector} is claimed by #{owner_name(owner)} but marked ENDOFCHAIN without terminating its chain", [sector], [], [owner]
						end
					else
						if owner && (owner[:kind] == 'fat' || owner[:kind] == 'difat')
							issue :invalid_special_marker, "#{owner_name(owner)} sector #{sector} must use its special FAT marker", [sector], [], [owner]
						elsif !owner
							issue :unreachable_sector, "allocated sector #{sector} is not reachable from any FAT, DIFAT, directory, miniFAT, root or stream chain", [sector]
						end
					end
				end
			end

			def check_mini_markers
				root_capacity_in_mini = @root_capacity.to_i / @mini_sector_size
				(0...@minifat.length).each do |mini_sector|
					marker = @minifat[mini_sector]
					owner = @mini_owners[mini_sector]
					if regular?(marker) && mini_sector >= root_capacity_in_mini
						issue :mini_sector_outside_root, "miniFAT allocates mini sector #{mini_sector} outside the root mini stream", [], [mini_sector], owner ? [owner] : []
						next
					end
					next if mini_sector >= root_capacity_in_mini

					case marker
					when nil
						issue :minifat_truncated, "allocated mini sector #{mini_sector} is not covered by the miniFAT", [], [mini_sector], owner ? [owner] : []
					when AllocationTable::AVAIL
						if owner
							issue :invalid_special_marker, "mini sector #{mini_sector} is claimed by #{owner_name(owner)} but marked FREESECT", [], [mini_sector], [owner]
						end
					when AllocationTable::EOC
						if owner && !@cross_linked_mini_sectors[mini_sector] && !mini_chain_ends_at?(mini_sector)
							issue :invalid_special_marker, "mini sector #{mini_sector} is claimed by #{owner_name(owner)} but marked ENDOFCHAIN without terminating its chain", [], [mini_sector], [owner]
						end
					when AllocationTable::BAT, AllocationTable::META_BAT
						issue :invalid_special_marker, "mini sector #{mini_sector} uses reserved big-sector marker 0x#{marker.to_s(16)}", [], [mini_sector], owner ? [owner] : []
					else
						unless owner || marker >= @minifat.length
							issue :unreachable_mini_sector, "allocated mini sector #{mini_sector} is not reachable from any mini stream", [], [mini_sector]
						end
					end
				end
			end

			def mini_chain_ends_at? mini_sector
				@chains.any? do |chain|
					chain[:mini_sectors] && chain[:mini_sectors].last == mini_sector
				end
			end
		end
	end
	end
