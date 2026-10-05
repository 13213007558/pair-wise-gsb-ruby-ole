# encoding: ASCII-8BIT

module Ole # :nodoc:
	class Storage
		#
		# Read-only validation of the sector allocation of a whole compound
		# file. +arg+ can be a filename or a seekable IO object.
		#
		# Returns an AllocationValidator::Report holding a single ownership
		# map covering the FAT, DIFAT, directory chain, streams, miniFAT and
		# the root mini-stream, plus a list of any problems found. The file
		# is never modified, and no attempt is made to repair the problems.
		#
		# Unlike Ole::Storage.new, this does not need the file to be
		# loadable, so it can be used on corrupted files.
		#
		def self.validate_allocation arg
			if String === arg
				File.open(arg, 'rb') { |io| AllocationValidator.new(io).validate }
			else
				AllocationValidator.new(arg).validate
			end
		end

		# Read-only validation of this storage's underlying io. See
		# Ole::Storage.validate_allocation.
		def validate_allocation
			AllocationValidator.new(@io).validate
		end

		#
		# Walks the FAT, DIFAT, directory chain, streams, miniFAT and the
		# root mini-stream of a compound file, recording the owner of every
		# sector in a single Report. Both sector sizes the format allows
		# (512 and 4096 bytes) are supported.
		#
		# The checks performed are:
		#
		# * every chain (FAT and miniFAT based) is followed with loop
		#   detection,
		# * sectors claimed by more than one object are reported
		#   (:cross_ownership),
		# * chains that provide fewer sectors than the declared stream size
		#   requires are reported (:chain_too_short),
		# * misuse of the special sector markers FREESECT, ENDOFCHAIN,
		#   FATSECT and DIFSECT is reported (:invalid_marker),
		# * sectors allocated in the FAT/miniFAT that are not reachable from
		#   any object are reported (:unreachable).
		#
		# Mini sector problems are reported together with the big sector of
		# the root mini-stream they physically live in.
		#
		class AllocationValidator
			AT = AllocationTable

			FREESECT   = AT::AVAIL
			ENDOFCHAIN = AT::EOC
			FATSECT    = AT::BAT
			DIFSECT    = AT::META_BAT
			MAXREGSECT = 0xfffffffa

			MARKER_NAMES = {
				FREESECT => 'FREESECT', ENDOFCHAIN => 'ENDOFCHAIN',
				FATSECT => 'FATSECT', DIFSECT => 'DIFSECT'
			}

			# A single problem found by the validator. +category+ is one of
			# :header, :difat, :cycle, :cross_ownership, :chain_too_short,
			# :invalid_marker, :out_of_range or :unreachable. +sectors+ lists
			# the big sectors involved (mini sectors are translated to the
			# big sector of the mini-stream that contains them) and
			# +streams+ the names of the streams involved, if any.
			Issue = Struct.new(:category, :message, :sectors, :streams) do
				def to_s
					"[#{category}] #{message}"
				end
			end

			# flattened directory entry, as used by the validator
			SDirent = Struct.new(:index, :name, :type, :first_block, :size)

			# The result of a validation run: a single ownership report for
			# the whole file, plus the list of problems found.
			class Report
				# all problems found, in the order they were discovered
				attr_reader :issues
				# big sector number => array of owning object descriptions
				attr_reader :owners
				# mini sector number => array of owning object descriptions
				attr_reader :mini_owners
				attr_accessor :sector_size, :mini_sector_size
				# the big sectors that make up the root mini-stream, in order
				attr_accessor :mini_stream_chain

				def initialize
					@issues = []
					@owners = {}
					@mini_owners = {}
					@mini_stream_chain = []
				end

				# true if no problems were found
				def ok?
					@issues.empty?
				end

				# all problems of the given +category+
				def issues_for category
					@issues.select { |issue| issue.category == category }
				end

				# file offset at which big sector +idx+ starts
				def sector_file_offset idx
					(idx + 1) * @sector_size
				end

				# where mini sector +idx+ physically lives, as [big sector,
				# byte offset within that sector], or nil if it falls outside
				# the mini-stream.
				def mini_sector_location idx
					per_sector = @sector_size / @mini_sector_size
					big = @mini_stream_chain[idx / per_sector]
					big && [big, (idx % per_sector) * @mini_sector_size]
				end

				def to_s
					lines = ["allocation report: #{ok? ? 'ok' : "#{@issues.length} problem(s)"}"]
					@issues.each { |issue| lines << "  #{issue}" }
					lines.join "\n"
				end
			end

			attr_reader :report

			def initialize io
				@io = io
				@report = Report.new
				# owner description => stream name, for stream owning descriptions
				@owner_streams = {}
			end

			def validate
				pos = begin @io.pos rescue nil end
				begin
					run
				ensure
					begin @io.pos = pos rescue nil end if pos
				end
				@report
			end

			private

			def run
				@io.seek 0
				header_block = @io.read 512
				if header_block.nil? || header_block.length < 512
					issue :header, 'file is too small to contain an OLE2 header'
					return
				end
				(@magic, @clsid, @minor_ver, @major_ver, @byte_order, @b_shift, @s_shift,
					@reserved, @csectdir, @num_bat, @dirent_start, @transacting_signature,
					@threshold, @sbat_start, @num_sbat, @mbat_start, @num_mbat
				) = header_block[0, Header::SIZE].unpack(Header::PACK)
				unless @magic == Header::MAGIC
					issue :header, 'OLE2 signature is invalid'
					return
				end
				unless [9, 12].include? @b_shift
					issue :header, "sector shift #{@b_shift} is invalid, the format only" \
						' allows 512 and 4096 byte sectors'
				end
				if @b_shift < 6 || @b_shift > 20 || @s_shift >= @b_shift
					# cannot make sense of the sector geometry, give up
					issue :header, "unusable sector geometry (sector shift #{@b_shift}," \
						" mini sector shift #{@s_shift})"
					return
				end
				@sector_size = 1 << @b_shift
				@mini_sector_size = 1 << @s_shift
				@report.sector_size = @sector_size
				@report.mini_sector_size = @mini_sector_size

				@io.seek 0, IO::SEEK_END
				file_size = @io.pos
				@num_file_sectors = file_size / @sector_size - 1
				if @num_file_sectors < 0
					@num_file_sectors = 0
					issue :header, "file is too small (#{file_size} bytes) to contain" \
						" any #{@sector_size} byte sectors"
				end

				load_difat header_block
				return unless @fat
				load_directory
				load_minifat
				load_mini_stream
				load_streams
				check_unreachable
			end

			# reads the DIFAT (header entries plus the DIFAT chain if any),
			# claims the DIFAT and FAT sectors, and loads the FAT itself.
			def load_difat header_block
				difat = header_block[Header::SIZE, 109 * 4].unpack 'V*'
				mbat_sectors = []
				if @num_mbat > 0
					idx = @mbat_start
					seen = {}
					# note FREESECT is tolerated as a terminator here, as that is
					# what ruby-ole itself writes in the last DIFAT sector
					until idx == ENDOFCHAIN || idx == FREESECT
						if idx > MAXREGSECT
							issue :difat, "DIFAT chain is terminated by #{marker_name idx}" \
								' instead of ENDOFCHAIN', mbat_sectors
							break
						end
						if idx >= @num_file_sectors
							issue :out_of_range, "DIFAT sector #{idx} lies beyond the end" \
								' of the file', [idx]
							break
						end
						if seen[idx]
							issue :cycle, "DIFAT chain loops back to sector #{idx}", [idx]
							break
						end
						seen[idx] = true
						data = read_sector idx
						unless data
							issue :out_of_range, "unable to read DIFAT sector #{idx}", [idx]
							break
						end
						entries = data.unpack 'V*'
						mbat_sectors << idx
						difat += entries[0..-2]
						idx = entries[-1]
					end
					if mbat_sectors.length != @num_mbat
						issue :difat, "header declares #{@num_mbat} DIFAT sectors but the" \
							" chain provides #{mbat_sectors.length}", mbat_sectors
					end
				end
				mbat_sectors.each { |s| claim s, 'DIFAT' }

				bad = difat.reject { |e| e == FREESECT || e <= MAXREGSECT }
				unless bad.empty?
					issue :difat, 'DIFAT contains invalid entries:' \
						" #{bad.map { |e| marker_name e }.uniq.join(', ')}"
				end
				fat_sectors = difat.select { |e| e <= MAXREGSECT }
				if fat_sectors.length < @num_bat
					issue :difat, "header requires #{@num_bat} FAT sectors but the DIFAT" \
						" only lists #{fat_sectors.length}"
				elsif fat_sectors.length > @num_bat
					issue :difat, "DIFAT lists #{fat_sectors.length} FAT sectors, more than" \
						" the #{@num_bat} declared in the header", fat_sectors[@num_bat..-1]
				end
				fat_sectors = fat_sectors[0, @num_bat]

				@fat = []
				fat_sectors.each do |s|
					if s >= @num_file_sectors
						issue :out_of_range, "FAT sector #{s} lies beyond the end of the file", [s]
						next
					end
					claim s, 'FAT'
					data = read_sector s
					@fat += data ? data.unpack('V*') : [FREESECT] * (@sector_size / 4)
				end
				if fat_sectors.empty? && @num_bat > 0
					issue :header, 'no readable FAT sectors, cannot check allocation'
					@fat = nil
					return
				end

				# the special markers must be consistent with the DIFAT
				fat_sectors.each do |s|
					next if s >= @fat.length
					unless @fat[s] == FATSECT
						issue :invalid_marker, "FAT sector #{s} is marked" \
							" #{marker_name @fat[s]} instead of FATSECT", [s]
					end
				end
				mbat_sectors.each do |s|
					next if s >= @fat.length
					unless @fat[s] == DIFSECT
						issue :invalid_marker, "DIFAT sector #{s} is marked" \
							" #{marker_name @fat[s]} instead of DIFSECT", [s]
					end
				end
				@fat.each_with_index do |v, i|
					if v == FATSECT && !fat_sectors.include?(i)
						issue :invalid_marker, "sector #{i} is marked FATSECT but is not" \
							' listed in the DIFAT', [i]
					elsif v == DIFSECT && !mbat_sectors.include?(i)
						issue :invalid_marker, "sector #{i} is marked DIFSECT but is not" \
							' part of the DIFAT chain', [i]
					end
				end
				if @fat.length < @num_file_sectors
					issue :out_of_range, "the FAT only covers #{@fat.length} sectors but" \
						" the file contains #{@num_file_sectors}"
				end
			end

			def load_directory
				dir_chain = walk_chain @fat, @dirent_start, 'directory chain'
				dir_chain.each { |s| claim s, 'directory' }
				@dirents = []
				data = dir_chain.map { |s| read_sector s }.compact.join
				data.to_enum(:each_chunk, Dirent::SIZE).with_index do |chunk, i|
					next if chunk.length < Dirent::SIZE
					type = chunk[66].ord
					next if type == 0
					name_len = chunk[64, 2].unpack('v').first
					raw = chunk[0, [name_len - 2, 0].max]
					name = begin
						raw.force_encoding('utf-16le').encode 'utf-8', :invalid => :replace, :undef => :replace
					rescue
						chunk[0, 32].inspect
					end
					first_block, size = chunk[116, 8].unpack 'V2'
					# in major version 4 files the stream size is 64 bit, borrowing
					# what is the reserved field in version 3
					size |= chunk[124, 4].unpack('V').first << 32 if @major_ver == 4
					@dirents << SDirent.new(i, name, type, first_block, size)
				end
				unless @dirents.find { |d| d.type == 5 }
					issue :header, 'no root entry found in the directory'
				end
			end

			def load_minifat
				sbat_chain = []
				if @sbat_start == ENDOFCHAIN || @sbat_start == FREESECT
					if @num_sbat > 0
						issue :chain_too_short, "header declares #{@num_sbat} miniFAT sectors" \
						' but the miniFAT chain is empty'
					end
				else
					sbat_chain = walk_chain @fat, @sbat_start, 'miniFAT chain'
					sbat_chain.each { |s| claim s, 'miniFAT' }
					if sbat_chain.length < @num_sbat
						issue :chain_too_short, "miniFAT chain provides #{sbat_chain.length}" \
							" sectors but the header declares #{@num_sbat}", sbat_chain
					end
				end
				@minifat = sbat_chain.map { |s| read_sector s }.compact.join.unpack 'V*'
			end

			def load_mini_stream
				root = @dirents.find { |d| d.type == 5 } or return
				chain = walk_chain @fat, root.first_block, 'mini-stream of the root entry'
				chain.each { |s| claim s, 'mini-stream (Root Entry)' }
				expected = num_blocks root.size, @sector_size
				if chain.length < expected
					issue :chain_too_short, 'mini-stream of the root entry declares' \
						" #{root.size} bytes, requiring #{expected} sectors, but the chain" \
						" only provides #{chain.length}", chain
				end
				@report.mini_stream_chain = chain
			end

			def load_streams
				@dirents.each do |d|
					next unless d.type == 2
					owner = "stream #{d.name.inspect} (dirent ##{d.index})"
					if d.size >= @threshold
						chain = walk_chain @fat, d.first_block, owner, d.name
						chain.each { |s| claim s, owner, d.name }
						expected = num_blocks d.size, @sector_size
						if chain.length < expected
							issue :chain_too_short, "#{owner} declares #{d.size} bytes," \
								" requiring #{expected} sectors, but the chain only provides" \
								" #{chain.length}", chain, d.name
						end
					else
						chain = walk_chain @minifat, d.first_block, owner, d.name, true
						chain.each { |m| claim_mini m, owner, d.name }
						expected = num_blocks d.size, @mini_sector_size
						if chain.length < expected
							issue :chain_too_short, "#{owner} declares #{d.size} bytes," \
								" requiring #{expected} mini sectors, but the chain only" \
								" provides #{chain.length}", mini_to_big(chain), d.name
						end
					end
				end
			end

			# anything marked allocated that nothing claimed is unreachable
			def check_unreachable
				@fat.each_with_index do |v, i|
					next if v == FREESECT || v == FATSECT || v == DIFSECT
					if i >= @num_file_sectors
						issue :out_of_range, "sector #{i} is allocated in the FAT but lies" \
							' beyond the end of the file', [i]
					elsif !@report.owners.key?(i)
						issue :unreachable, "sector #{i} is allocated in the FAT but is not" \
							' reachable from any object', [i]
					end
				end
				@minifat.each_with_index do |v, i|
					next if v == FREESECT
					if v > MAXREGSECT && v != ENDOFCHAIN
						issue :invalid_marker, "miniFAT entry #{i} is #{marker_name v}," \
							' which is not valid in the miniFAT', mini_to_big([i])
						next
					end
					if i >= mini_capacity
						issue :out_of_range, "mini sector #{i} is allocated in the miniFAT" \
							" but lies beyond the end of the mini-stream (#{mini_desc i})",
							mini_to_big([i])
					elsif !@report.mini_owners.key?(i)
						issue :unreachable, "mini sector #{i} is allocated in the miniFAT" \
							" but is not reachable from any stream (#{mini_desc i})",
							mini_to_big([i])
					end
				end
			end

			# follows a chain in +table+ starting at +start+, checking for
			# loops, out of range sectors and misuse of the special sector
			# markers. returns the chain of sector numbers collected before
			# any problem was hit. +context+ describes the owning object for
			# error messages; +stream+ is the stream name, if any.
			def walk_chain table, start, context, stream=nil, mini=false
				chain = []
				seen = {}
				idx = start
				until idx == ENDOFCHAIN
					if idx > MAXREGSECT
						issue :invalid_marker, "#{context}: chain is terminated by" \
							" #{marker_name idx} instead of ENDOFCHAIN",
							chain_sectors(chain, mini), stream
						break
					end
					if idx >= table.length
						issue :out_of_range, "#{context}: #{mini ? 'mini sector' : 'sector'}" \
							" #{idx} is outside the allocation table (#{table.length} entries)",
							chain_sectors(chain, mini), stream
						break
					end
					limit = mini ? mini_capacity : @num_file_sectors
					if idx >= limit
						issue :out_of_range, "#{context}: #{describe_sector idx, mini} lies" \
							" beyond the end of the #{mini ? 'mini-stream' : 'file'}",
							chain_sectors(chain + [idx], mini), stream
						break
					end
					if seen.key? idx
						cycle = chain[seen[idx]..-1]
						issue :cycle, "#{context}: chain loops back to" \
							" #{describe_sector idx, mini}", chain_sectors(cycle, mini), stream
						break
					end
					seen[idx] = chain.length
					chain << idx
					idx = table[idx]
				end
				chain
			end

			# records +sector+ as owned by +owner+, reporting a conflict if it
			# was already claimed by something else.
			def claim sector, owner, stream=nil
				@owner_streams[owner] = stream if stream
				list = (@report.owners[sector] ||= [])
				return if list.include? owner
				unless list.empty?
					issue :cross_ownership, "sector #{sector} is claimed by both" \
						" #{list.first} and #{owner}", [sector],
						(list + [owner]).map { |o| @owner_streams[o] }.compact.uniq
				end
				list << owner
			end

			# same as #claim, but for a mini sector of the mini-stream
			def claim_mini mini, owner, stream=nil
				@owner_streams[owner] = stream if stream
				list = (@report.mini_owners[mini] ||= [])
				return if list.include? owner
				unless list.empty?
					issue :cross_ownership, "#{mini_desc mini} is claimed by both" \
						" #{list.first} and #{owner}", mini_to_big([mini]),
						(list + [owner]).map { |o| @owner_streams[o] }.compact.uniq
				end
				list << owner
			end

			def issue category, message, sectors=[], stream=nil
				@report.issues << Issue.new(category, message, sectors, Array(stream).compact)
			end

			def read_sector idx
				@io.seek((idx + 1) * @sector_size)
				data = @io.read @sector_size
				data && data.length == @sector_size ? data : nil
			end

			def num_blocks size, block_size
				(size / block_size.to_f).ceil
			end

			def mini_capacity
				@report.mini_stream_chain.length * (@sector_size / @mini_sector_size)
			end

			# the big sectors that physically hold the given mini sectors
			def mini_to_big minis
				per_sector = @sector_size / @mini_sector_size
				minis.map { |m| @report.mini_stream_chain[m / per_sector] }.compact.uniq
			end

			def chain_sectors chain, mini
				mini ? mini_to_big(chain) : chain
			end

			def describe_sector idx, mini
				mini ? mini_desc(idx) : "sector #{idx}"
			end

			# describes a mini sector together with the big sector it lives in
			def mini_desc idx
				loc = @report.mini_sector_location idx
				if loc
					"mini sector #{idx} (sector #{loc[0]}, offset #{loc[1]})"
				else
					"mini sector #{idx} (outside the mini-stream)"
				end
			end

			def marker_name value
				MARKER_NAMES[value] || ('0x%08x' % value)
			end
		end
	end
end
