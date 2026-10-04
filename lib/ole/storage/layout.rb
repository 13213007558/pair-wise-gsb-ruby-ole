# encoding: ASCII-8BIT

require 'digest/sha1'

require 'ole/storage/base'

module Ole
	class Storage
		#
		# = Introduction
		#
		# +Layout+ rewrites the physical layout of an Ole::Storage document
		# into a new file. It exists for archival tools that want a known set
		# of "hot" streams stored contiguously, so that later reads of those
		# streams become sequential rather than scattered across the file.
		#
		# The caller nominates the hot streams in priority order, and may
		# additionally request per stream alignment (in blocks). All other
		# streams keep their logical content; the storage hierarchy, CLSIDs,
		# state bits and timestamps are preserved. Streams at or over the
		# mini stream cutoff are stored in regular sectors, smaller ones in
		# the mini stream, and empty streams stay empty.
		#
		# The directory, FAT, DIFAT, mini stream and MiniFAT are all
		# regenerated from scratch in the output file.
		#
		# If the requested constraints cannot be satisfied, a
		# Layout::ConflictError is raised before anything is written - the
		# rewriter never silently falls back to an arbitrary layout.
		#
		# = Example
		#
		#   ole = Ole::Storage.open('archive.ole', 'rb')
		#   report = ole.rewrite_layout 'archive.repacked.ole',
		#     :order => %w[WordDocument SummaryInformation],
		#     :align => { 'WordDocument' => 8 }
		#   puts report.fragments_before, report.fragments_after
		#
		class Layout
			# thrown when the requested layout constraints cannot be satisfied.
			class ConflictError < StandardError
			end

			# thrown when the rewritten file fails verification.
			class VerifyError < StandardError
			end

			# number of difat entries that fit directly in the header block.
			HEADER_DIFAT = 109

			EOT = Dirent::EOT
			EOC = AllocationTable::EOC
			AVAIL = AllocationTable::AVAIL
			BAT = AllocationTable::BAT
			META_BAT = AllocationTable::META_BAT

			# hash and physical range details for a single stream, captured
			# on both sides of the rewrite.
			class StreamInfo < Struct.new(
				:path, :size, :space, :first_block_after,
				:sha1_before, :sha1_after, :ranges_before, :ranges_after
			)
				# number of separate physical byte ranges the stream
				# occupies, before and after the rewrite.
				def fragments_before
					ranges_before.length
				end

				def fragments_after
					ranges_after.length
				end

				def ok?
					sha1_before == sha1_after
				end
			end

			# the result of a successful rewrite.
			class Report
				attr_reader :streams

				def initialize streams, order, align
					@streams = streams
					@order = order
					@align = align
				end

				def [] path
					@streams.find { |s| s.path == path }
				end

				# total number of contiguous physical ranges occupied by
				# stream data, before and after the rewrite.
				def fragments_before
					@streams.inject(0) { |n, s| n + s.fragments_before }
				end

				def fragments_after
					@streams.inject(0) { |n, s| n + s.fragments_after }
				end

				def ok?
					@streams.all?(&:ok?)
				end

				# verify hashes, contiguity, ordering and alignment of the
				# rewritten streams. raises VerifyError on any problem.
				def verify!
					@streams.each do |s|
						unless s.ok?
							raise VerifyError, "data mismatch for stream #{s.path.inspect}"
						end
						next if s.space == :empty
						unless s.fragments_after == 1
							raise VerifyError, "stream #{s.path.inspect} is fragmented after rewrite"
						end
						if (n = @align[s.path]) && s.first_block_after % n != 0
							raise VerifyError, "stream #{s.path.inspect} violates alignment #{n}"
						end
					end
					# hot streams must come out in the requested order, within
					# their respective block spaces.
					by_path = {}
					@streams.each { |s| by_path[s.path] = s }
					[:big, :mini].each do |space|
						hot = @order.map { |path| by_path[path] }.select { |s| s && s.space == space }
						hot.each_cons 2 do |a, b|
							unless a.first_block_after < b.first_block_after
								raise VerifyError, "hot streams out of order: #{a.path.inspect}, #{b.path.inspect}"
							end
						end
					end
					true
				end
			end

			# internal planning record for one directory entry.
			class Entry # :nodoc:
				attr_accessor :src, :path, :children, :idx, :prev, :next, :child,
					:first_block, :size, :sha1_before, :ranges_before
			end

			attr_reader :ole, :params

			def self.rewrite ole, out, params={}
				new(ole, params).rewrite out
			end

			def initialize ole, params={}
				@ole = ole
				@params = {:order => [], :align => {}}.merge(params)
			end

			# rewrite +ole+ to +out+ (a filename or io), returning a Report.
			def rewrite out
				if String === out && File === @ole.io && @ole.io.path &&
						File.expand_path(out) == File.expand_path(@ole.io.path)
					raise ArgumentError, 'output must be a different file from the source'
				end
				if out.equal? @ole.io
					raise ArgumentError, 'output must be a different io from the source'
				end
				# plan (and thus validate all constraints) before touching the
				# output, so that a conflict never leaves a half written file
				# masquerading as a successful rewrite.
				plan = build_plan
				data = nil
				if String === out
					File.open(out, 'wb+') { |io| write plan, io }
					data = File.open(out, 'rb') { |f| f.read }
				else
					write plan, out
					out.rewind
					data = out.read
				end
				data = data.dup.force_encoding Encoding::ASCII_8BIT
				verify plan, data
			end

			private

			# snapshot the source, validate the constraints, and compute the
			# exact position of every chain in the output file.
			def build_plan
				header = @ole.header
				@bsize = 1 << header.b_shift
				@ssize = 1 << header.s_shift
				@threshold = header.threshold

				order = @params[:order]
				align = @params[:align]

				root = snapshot @ole.root, nil
				entries = []
				link_tree root, entries
				streams = entries.select { |e| e.src.file? }

				validate_constraints order, align, entries

				empty, rest = streams.partition { |e| e.src.size == 0 }
				empty.each { |e| e.first_block = EOC }
				big, small = rest.partition { |e| e.src.size >= @threshold }

				# hot streams first, in the requested order; the rest keep
				# their original relative order.
				priority = {}
				order.each_with_index { |path, i| priority[path] = i }
				position = {}
				streams.each_with_index { |e, i| position[e.path] = i }
				by_priority = lambda { |e| [priority[e.path] || streams.length, position[e.path]] }
				big.sort_by!(&by_priority)
				small.sort_by!(&by_priority)

				# lay out the mini stream: small streams in order, aligned in
				# mini blocks. padding mini blocks are left free in the sbat.
				sbat = []
				small.each do |e|
					pad_to sbat, align[e.path] || 1
					e.first_block = sbat.length
					sbat.concat chain_entries(sbat.length, num_blocks(e.src.size, @ssize))
				end
				mini_size = sbat.length * @ssize

				# lay out the big block space: directory, sbat, mini stream,
				# then the big streams (hot ones first, aligned), with the bat
				# and mbat sectors tacked on the end.
				bbat = []
				ndir = num_blocks entries.length * Dirent::SIZE, @bsize
				dirent_start = allocate bbat, ndir
				nsbat = num_blocks sbat.length * 4, @bsize
				sbat_start = nsbat > 0 ? allocate(bbat, nsbat) : EOC
				nmini = num_blocks mini_size, @bsize
				mini_start = nmini > 0 ? allocate(bbat, nmini) : EOC
				big.each do |e|
					pad_to bbat, align[e.path] || 1
					e.first_block = bbat.length
					allocate bbat, num_blocks(e.src.size, @bsize)
				end

				# size the bat and mbat. this is a fixpoint, as the bat and
				# mbat blocks themselves need bat entries.
				nbat = nmbat = 0
				loop do
					total = bbat.length + nbat + nmbat
					new_nbat = num_blocks total * 4, @bsize
					new_nmbat = new_nbat <= HEADER_DIFAT ? 0 :
						num_blocks((new_nbat - HEADER_DIFAT) * 4, @bsize - 4)
					break if new_nbat == nbat && new_nmbat == nmbat
					nbat, nmbat = new_nbat, new_nmbat
				end
				bat_start = bbat.length
				bbat.concat [BAT] * nbat
				mbat_start = nmbat > 0 ? bbat.length : EOC
				bbat.concat [META_BAT] * nmbat

				# fill in the sizes, and the root's mini stream details.
				entries.each do |e|
					if e.src.type == :root
						e.first_block = mini_start
						e.size = mini_size
					elsif e.src.dir?
						e.first_block = EOT
						e.size = 0
					else
						e.size = e.src.size
					end
				end

				# capture hashes and physical ranges of the source streams.
				streams.each do |e|
					e.sha1_before = Digest::SHA1.hexdigest('') if e.src.size == 0
					e.ranges_before = physical_ranges @ole, e.src
				end

				{
					:entries => entries, :streams => streams,
					:order => order, :align => align,
					:header => build_header(ndir, dirent_start, sbat_start, nsbat, nbat, mbat_start, nmbat),
					:bbat => bbat, :sbat => sbat,
					:ndir => ndir, :dirent_start => dirent_start,
					:nsbat => nsbat, :sbat_start => sbat_start,
					:mini_start => mini_start,
					:nbat => nbat, :bat_start => bat_start,
					:mbat_start => mbat_start,
					:bat_blocks => (bat_start...bat_start + nbat).to_a,
					:mbat_blocks => nmbat > 0 ? (mbat_start...mbat_start + nmbat).to_a : []
				}
			end

			def snapshot src, parent_path
				entry = Entry.new
				entry.src = src
				entry.path = parent_path
				entry.children = []
				if src.dir?
					src.children.each do |child|
						path = parent_path ? "#{parent_path}/#{child.name}" : child.name
						entry.children << snapshot(child, path)
					end
				end
				entry
			end

			# flatten the tree pre-order, and rebuild the sibling links the
			# same way Dirent.flatten does.
			def link_tree root, entries
				walk = lambda do |e|
					e.idx = entries.length
					entries << e
					e.children.each { |c| walk.call c }
				end
				walk.call root
				link = nil
				link = lambda do |list|
					return EOT if list.empty?
					i = list.length / 2
					this = list[i]
					this.prev = link.call list[0...i]
					this.next = link.call list[i + 1..-1]
					this.idx
				end
				apply = nil
				apply = lambda do |e|
					if e.src.file?
						e.prev = e.next = e.child = EOT
					else
						e.children.each { |c| apply.call c }
						e.child = link.call e.children
					end
				end
				apply.call root
				root.prev = root.next = EOT
			end

			def validate_constraints order, align, entries
				unless Array === order
					raise ConflictError, "order must be an array of stream paths, got #{order.inspect}"
				end
				unless Hash === align
					raise ConflictError, "align must be a hash of stream path to alignment, got #{align.inspect}"
				end
				by_path = {}
				entries.each { |e| by_path[e.path] = e if e.path }
				seen = {}
				order.each do |path|
					raise ConflictError, "duplicate stream in order: #{path.inspect}" if seen[path]
					seen[path] = true
					validate_stream_path by_path, path
				end
				align.each do |path, n|
					entry = validate_stream_path by_path, path
					unless Integer === n && n >= 1
						raise ConflictError, "invalid alignment #{n.inspect} for #{path.inspect}"
					end
					if entry.src.size == 0
						raise ConflictError, "cannot align empty stream #{path.inspect}"
					end
				end
			end

			def validate_stream_path by_path, path
				entry = by_path[path] or
					raise ConflictError, "stream not found: #{path.inspect}"
				entry.src.file? or
					raise ConflictError, "not a stream: #{path.inspect}"
				entry
			end

			def build_header ndir, dirent_start, sbat_start, nsbat, nbat, mbat_start, nmbat
				src = @ole.header
				header = Header.new
				header.clsid = src.clsid
				header.minor_ver = src.minor_ver
				header.major_ver = src.major_ver
				header.b_shift = src.b_shift
				header.s_shift = src.s_shift
				header.threshold = src.threshold
				header.transacting_signature = src.transacting_signature
				header.csectdir = header.major_ver >= 4 ? ndir : 0
				header.num_bat = nbat
				header.dirent_start = dirent_start
				header.sbat_start = sbat_start
				header.num_sbat = nsbat
				header.mbat_start = mbat_start
				header.num_mbat = nmbat
				header
			end

			# serialize a dirent, preserving everything from the source entry
			# except the tree links and the data location, which come from
			# the plan.
			def serialize_dirent e
				src = e.src
				name = Types::Variant.dump Types::VT_LPWSTR, src.name
				name = name[0, 62] if name.length > 62
				name += 0.chr * 2
				create_time = src.create_time_str
				modify_time = src.modify_time_str
				if src.file?
					create_time ||= Types::Variant.dump Types::VT_FILETIME, src.create_time || Types::FileTime.now
					modify_time ||= Types::Variant.dump Types::VT_FILETIME, src.modify_time || Types::FileTime.now
				else
					create_time ||= 0.chr * 8
					modify_time ||= 0.chr * 8
				end
				type_id = Dirent::TYPE_MAP.to_a.find { |id, _| src.type == _ }.first
				[
					name + 0.chr * (64 - name.length), name.length,
					type_id, src.colour, e.prev, e.next, e.child,
					src.clsid, src.flags, create_time, modify_time,
					e.first_block, e.size, src.reserved
				].pack Dirent::PACK
			end

			# serialize the whole plan to +io+.
			def write plan, io
				io.truncate 0
				difat = plan[:bat_blocks][0, HEADER_DIFAT]
				difat += [AVAIL] * (HEADER_DIFAT - difat.length)
				io.seek 0
				io.write plan[:header].to_s + difat.pack('V*')
				io.write 0.chr * (@bsize - 512) if @bsize > 512

				write_blocks = lambda do |start, data|
					io.seek (start + 1) * @bsize
					io.write data
				end

				dir_data = plan[:entries].map { |e| serialize_dirent e }.join
				dir_data += 0.chr * (plan[:ndir] * @bsize - dir_data.length)
				write_blocks.call plan[:dirent_start], dir_data

				if plan[:nsbat] > 0
					sbat_data = plan[:sbat].pack 'V*'
					sbat_data += [AVAIL].pack('V') * (plan[:nsbat] * @bsize / 4 - plan[:sbat].length)
					write_blocks.call plan[:sbat_start], sbat_data
				end

				# stream data. small streams land inside the mini stream, big
				# ones in their own sectors. hashes of the source data are
				# captured as it is copied.
				plan[:streams].each do |e|
					next if e.src.size == 0
					offset = if e.src.size >= @threshold
						(e.first_block + 1) * @bsize
					else
						(plan[:mini_start] + 1) * @bsize + e.first_block * @ssize
					end
					io.seek offset
					e.sha1_before = copy_stream e.src, io
				end

				bbat_data = plan[:bbat].pack 'V*'
				bbat_data += [AVAIL].pack('V') * (plan[:nbat] * @bsize / 4 - plan[:bbat].length)
				write_blocks.call plan[:bat_start], bbat_data

				unless plan[:mbat_blocks].empty?
					per_mbat = @bsize / 4 - 1
					rest = plan[:bat_blocks][HEADER_DIFAT..-1] || []
					plan[:mbat_blocks].each_with_index do |block, i|
						chunk = rest[i * per_mbat, per_mbat] || []
						chunk += [AVAIL] * (per_mbat - chunk.length)
						chunk << (plan[:mbat_blocks][i + 1] || EOC)
						write_blocks.call block, chunk.pack('V*')
					end
				end
				io.flush
			end

			# copy one stream's data from the source document to +io+ (already
			# positioned), returning the sha1 of the data copied.
			def copy_stream src, io
				sha = Digest::SHA1.new
				src.open do |src_io|
					until src_io.eof?
						buf = src_io.read 65536
						break if buf.empty?
						sha.update buf
						io.write buf
					end
				end
				sha.hexdigest
			end

			# reparse the rewritten document, checking every stream's hash and
			# new physical ranges against the source, and build the report.
			def verify plan, data
				new_ole = Storage.new StringIO.new(data)
				streams = plan[:streams].map do |e|
					d = find_dirent new_ole, e.path or
						raise VerifyError, "stream #{e.path.inspect} missing from rewritten file"
					d.size == e.src.size or
						raise VerifyError, "stream #{e.path.inspect} changed size in rewrite"
					space = d.size == 0 ? :empty : (d.size >= @threshold ? :big : :mini)
					StreamInfo.new e.path, d.size, space, d.first_block,
						e.sha1_before, hash_stream(d), e.ranges_before,
						physical_ranges(new_ole, d)
				end
				report = Report.new streams, plan[:order], plan[:align]
				report.verify!
				report
			end

			def hash_stream dirent
				return Digest::SHA1.hexdigest('') if dirent.size == 0
				sha = Digest::SHA1.new
				dirent.open do |io|
					until io.eof?
						buf = io.read 65536
						break if buf.empty?
						sha.update buf
					end
				end
				sha.hexdigest
			end

			# the physical byte ranges a stream's data occupies in +ole+,
			# with physically adjacent ranges merged. small streams are
			# mapped through the mini stream to real file offsets.
			def physical_ranges ole, dirent
				return [] if dirent.size == 0
				bsize = ole.bbat.block_size
				ranges = if dirent.size >= ole.header.threshold
					ole.bbat.ranges dirent.first_block, dirent.size
				else
					ssize = ole.sbat.block_size
					mini_chain = ole.bbat.chain ole.root.first_block
					count = (dirent.size.to_f / ssize).ceil
					ole.sbat.chain(dirent.first_block)[0, count].map do |mb|
						offset = mb * ssize
						[(mini_chain[offset / bsize] + 1) * bsize + offset % bsize, ssize]
					end
				end
				trimmed = []
				remaining = dirent.size
				ranges.each do |pos, len|
					len = remaining if len > remaining
					trimmed << [pos, len]
					remaining -= len
				end
				merged = []
				trimmed.each do |pos, len|
					if merged.last && merged.last[0] + merged.last[1] == pos
						merged.last[1] += len
					else
						merged << [pos, len]
					end
				end
				merged
			end

			def find_dirent ole, path
				d = ole.root
				path.split('/').each do |name|
					d = d / name
					return nil unless d
				end
				d
			end

			def num_blocks size, block_size
				(size.to_f / block_size).ceil
			end

			# the table entries for a chain of +n+ blocks starting at +start+.
			def chain_entries start, n
				(0...n).map { |i| i == n - 1 ? EOC : start + i + 1 }
			end

			# append a chain of +n+ blocks to +bbat+, returning its head.
			def allocate bbat, n
				start = bbat.length
				bbat.concat chain_entries(start, n)
				start
			end

			# append free blocks to +table+ until its length is a multiple of
			# +alignment+.
			def pad_to table, alignment
				table << AVAIL while table.length % alignment != 0
			end
		end

		# Rewrite the physical layout of this document into +out+ (a
		# filename or io), placing the given hot streams contiguously.
		# Returns a Layout::Report. See Layout for details.
		def rewrite_layout out, params={}
			Layout.rewrite self, out, params
		end
	end
end
