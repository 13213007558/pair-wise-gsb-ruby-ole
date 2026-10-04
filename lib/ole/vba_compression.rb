# encoding: ASCII-8BIT

#
# = Introduction
#
# Decoder and encoder for the "CompressedContainer" format described in
# [MS-OVBA] 2.4.1, used to store VBA source code inside OLE (CFBF) files
# (the "_VBA_PROJECT" / "dir" streams and module streams).
#
# This only rewrites bytes between a compressed container and its plain
# text form. It never parses, compiles or runs any macro code.
#
# Both directions work on IO like objects (+read+ for input, +write+ for
# output), so containers can be processed without loading everything into
# memory at once:
#
#   require 'ole/vba_compression'
#
#   Ole::VBACompression.decode compressed_io, plain_io            # inflate
#   Ole::VBACompression.decode compressed_io, plain_io, 1_000_000 # inflate, capped
#   Ole::VBACompression.encode plain_io, compressed_io            # deflate
#
# = Format notes
#
# A container is a 0x01 signature byte followed by chunks. Each chunk has
# a 16 bit little endian header: bits 0-11 hold the chunk data size minus
# one, bits 12-14 are the 0b011 signature, bit 15 flags a compressed
# chunk. A clear flag means 4096 raw bytes follow.
#
# Inside a compressed chunk, a flag byte introduces 8 tokens. A clear
# flag bit is a literal byte; a set bit is a 2 byte copy token. The split
# of the copy token into offset and length bits depends on the current
# position within the 4096 byte decompressed chunk: the nearer the chunk
# end, the fewer bits the offset gets. Copies may overlap, in which case
# the source bytes are produced one at a time as the copy proceeds.
#
module Ole
	module VBACompression
		# raised for any malformed container, or when a decode limit is hit.
		class Error < StandardError; end

		# size of the sliding window; copy tokens can never reach back
		# across a chunk boundary.
		CHUNK_SIZE = 4096

		SIGNATURE        = 0x01
		HEADER_SIGNATURE = 0x3000
		COMPRESSED_FLAG  = 0x8000
		RAW_CHUNK_HEADER = HEADER_SIGNATURE | (CHUNK_SIZE - 1)

		#
		# Inflate the compressed container read from +input+ and write the
		# decompressed bytes to +output+. When +limit+ is given, an Error is
		# raised as soon as the total decompressed size would exceed it
		# (useful when processing untrusted archives). Returns the number of
		# bytes written.
		#
		def self.decode input, output, limit=nil
			signature = input.read 1
			raise Error, 'missing container signature' unless signature && signature.bytesize == 1
			raise Error, 'invalid container signature' unless signature.getbyte(0) == SIGNATURE
			written = 0
			loop do
				header = input.read 2
				break if header.nil? || header.empty?
				raise Error, 'truncated chunk header' if header.bytesize < 2
				header = header.unpack('v').first
				raise Error, 'invalid chunk header signature' unless (header & 0x7000) == HEADER_SIGNATURE
				if (header & COMPRESSED_FLAG) == 0
					chunk = input.read CHUNK_SIZE
					raise Error, 'truncated raw chunk' unless chunk && chunk.bytesize == CHUNK_SIZE
				else
					data_size = (header & 0x0fff) + 1
					data = input.read data_size
					raise Error, 'truncated compressed chunk' unless data && data.bytesize == data_size
					chunk = decompress_chunk data
				end
				if limit && written + chunk.bytesize > limit
					raise Error, "decompressed size exceeds limit of #{limit} bytes"
				end
				output.write chunk
				written += chunk.bytesize
			end
			written
		end

		#
		# Compress the bytes read from +input+ into a container written to
		# +output+. Chunks that do not compress well are stored as legal
		# uncompressed (raw) chunks; copy tokens never reference bytes from
		# before the current 4096 byte chunk. Returns the number of bytes
		# written.
		#
		def self.encode input, output
			written = SIGNATURE.chr.bytesize
			output.write SIGNATURE.chr
			while (chunk = input.read CHUNK_SIZE) && !chunk.empty?
				written += encode_chunk(chunk, output)
			end
			written
		end

		# number of offset bits a copy token has at +position+ within its
		# decompressed chunk (the rest of the 16 bits encode the length).
		def self.copy_token_offset_bits position
			(CHUNK_SIZE - 1 - position).bit_length
		end

		def self.decompress_chunk data # :nodoc:
			out = ''
			pos = 0
			while pos < data.bytesize
				flags = data.getbyte pos
				pos += 1
				8.times do |bit|
					break if pos >= data.bytesize # padding at the chunk tail
					if (flags & (1 << bit)) == 0
						out << data.getbyte(pos)
						pos += 1
					else
						raise Error, 'truncated copy token' if pos + 2 > data.bytesize
						token = data.getbyte(pos) | (data.getbyte(pos + 1) << 8)
						pos += 2
						bit_count = copy_token_offset_bits out.bytesize
						length = (token & (0xffff >> bit_count)) + 3
						offset = (token >> (16 - bit_count)) + 1
						raise Error, 'copy token offset before chunk start' if offset > out.bytesize
						raise Error, 'decompressed chunk too large' if out.bytesize + length > CHUNK_SIZE
						# copy byte by byte so overlapping copies take effect
						# progressively, replicating their own output.
						length.times { out << out.getbyte(out.bytesize - offset) }
					end
				end
			end
			out
		end

		def self.encode_chunk chunk, output # :nodoc:
			data = compress_chunk chunk
			if data.bytesize >= chunk.bytesize && chunk.bytesize == CHUNK_SIZE
				# no gain on a full chunk: emit a legal uncompressed chunk.
				output.write [RAW_CHUNK_HEADER].pack('v')
				output.write chunk
				2 + CHUNK_SIZE
			elsif data.bytesize <= CHUNK_SIZE
				header = HEADER_SIGNATURE | COMPRESSED_FLAG | (data.bytesize - 1)
				output.write [header].pack('v')
				output.write data
				2 + data.bytesize
			else
				# a partial chunk can expand past the encodable chunk data
				# size; split it and let the pieces use smaller chunks.
				half = chunk.bytesize / 2
				encode_chunk(chunk.byteslice(0, half), output) +
					encode_chunk(chunk.byteslice(half, chunk.bytesize - half), output)
			end
		end

		def self.compress_chunk chunk # :nodoc:
			size = chunk.bytesize
			out = ''
			table = {}
			pos = 0
			while pos < size
				flag_index = out.bytesize
				out << "\x00"
				flags = 0
				8.times do |bit|
					break if pos >= size
					match = find_match chunk, pos, table
					if match
						offset, length = match
						bit_count = copy_token_offset_bits pos
						token = ((offset - 1) << (16 - bit_count)) | (length - 3)
						out << (token & 0xff) << (token >> 8)
						flags |= 1 << bit
						length.times { |i| record_position table, chunk, pos + i }
						pos += length
					else
						out << chunk.getbyte(pos)
						record_position table, chunk, pos
						pos += 1
					end
				end
				out.setbyte flag_index, flags
			end
			out
		end

		# greedy longest match against the most recent occurrence of the
		# same 3 byte prefix, limited to what a copy token at +pos+ can
		# encode. returns [offset, length] or nil.
		def self.find_match chunk, pos, table # :nodoc:
			size = chunk.bytesize
			return nil if pos + 3 > size
			candidate = table[match_key(chunk, pos)]
			return nil unless candidate
			bit_count = copy_token_offset_bits pos
			offset = pos - candidate
			return nil if offset > (1 << bit_count)
			max_length = [(0xffff >> bit_count) + 3, size - pos].min
			length = 0
			while length < max_length && chunk.getbyte(candidate + length) == chunk.getbyte(pos + length)
				length += 1
			end
			length >= 3 ? [offset, length] : nil
		end

		def self.record_position table, chunk, pos # :nodoc:
			table[match_key(chunk, pos)] = pos if pos + 3 <= chunk.bytesize
		end

		def self.match_key chunk, pos # :nodoc:
			(chunk.getbyte(pos) << 16) | (chunk.getbyte(pos + 1) << 8) | chunk.getbyte(pos + 2)
		end

		private_class_method :decompress_chunk, :encode_chunk, :compress_chunk,
			:find_match, :record_position, :match_key
	end
end
