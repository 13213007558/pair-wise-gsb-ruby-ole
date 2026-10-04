# encoding: ASCII-8BIT

require 'stringio'

module Ole
	module VBACompression
		# Compressed container signature byte from [MS-OVBA] 2.4.1.
		SIGNATURE = 0x01
		# Each compressed chunk decompresses to at most this many bytes.
		CHUNK_SIZE = 4096
		# Larger hash chains are unnecessary for the small, per-chunk search window.
		MATCH_CHAIN_DEPTH = 32

		class FormatError < StandardError
		end

		def self.decode(input, output = nil, max_output_length = nil)
			if !max_output_length.nil? && (!max_output_length.integer? || max_output_length < 0)
				raise ArgumentError, 'maximum output length must be a non-negative integer'
			end
			source = to_io(input)
			destination = binary_io(output || StringIO.new)
			signature = source.read(1)
			raise FormatError, 'missing compressed container signature' if signature.nil? || signature.empty?
			raise FormatError, 'invalid compressed container signature' unless signature.ord == SIGNATURE

			remaining_output = max_output_length
			until source.eof?
				header = source.read(2)
				raise FormatError, 'truncated compressed chunk header' unless header && header.length == 2
				raw_header = header.unpack('v').first
				chunk_signature = raw_header & 0xf000
				raise FormatError, 'invalid compressed chunk signature' unless [0x3000, 0xb000].include?(chunk_signature)
				compressed = chunk_signature == 0xb000
				size_field = raw_header & 0x0fff
				chunk_size = size_field + 3
				raise FormatError, 'compressed chunk size is out of range' unless (3..4098).include?(chunk_size)

				data_size = size_field + 1
				data = source.read(data_size)
				raise FormatError, 'truncated compressed chunk data' unless data && data.length == data_size
				final_chunk = source.eof?

				if compressed
					remaining_output = decode_compressed_chunk(data, destination, remaining_output, final_chunk)
				else
					raise FormatError, 'uncompressed chunk must contain 4096 bytes' unless final_chunk || data.length == CHUNK_SIZE
					remaining_output = write_output(destination, data, remaining_output)
				end
			end

			return destination if output
			destination.string.dup.force_encoding(Encoding::ASCII_8BIT)
		end

		def self.encode(input, output = nil)
			source = to_io(input)
			destination = binary_io(output || StringIO.new)
			destination.write(SIGNATURE.chr)

			until source.eof?
				chunk = source.read(CHUNK_SIZE)
				compressed_chunk = encode_chunk(chunk)
				if compressed_chunk.length < chunk.length
					write_chunk destination, true, compressed_chunk
				else
					write_chunk destination, false, chunk
				end
			end

			return destination if output
			destination.string.dup.force_encoding(Encoding::ASCII_8BIT)
		end

		class << self
			private

			def to_io(object)
				case object
				when String
					StringIO.new(object.dup.force_encoding(Encoding::ASCII_8BIT))
				else
					binary_io(object)
				end
			end

			def binary_io(object = nil)
				io = object ? object : StringIO.new
				if io.respond_to?(:string)
					io.string.force_encoding(Encoding::ASCII_8BIT)
					io.set_encoding(Encoding::ASCII_8BIT) if io.respond_to?(:set_encoding)
				end
				io
			end

			def write_output(output, data, remaining_output)
				unless remaining_output.nil?
					raise FormatError, 'maximum output length exceeded' if data.length > remaining_output
				end
				output.write(data)
				remaining_output - data.length unless remaining_output.nil?
			end

			def write_chunk(output, compressed, chunk)
				size_field = chunk.length - 1
				header = (compressed ? 0xb000 : 0x3000) | (size_field & 0x0fff)
				output.write([header].pack('v'))
				output.write(chunk)
			end

			def decode_compressed_chunk(data, output, remaining_output, final_chunk)
				decompressed = ''.dup
				position = 0

				while position < data.length && decompressed.length < CHUNK_SIZE
					flags_byte = data.getbyte(position)
					raise FormatError, 'truncated token flags' if flags_byte.nil?
					position += 1

					8.times do |token_index|
						break if position >= data.length

						if (flags_byte & (1 << token_index)) == 0
							byte = data[position]
							position += 1
							remaining_output = reserve_output(remaining_output, 1)
							append_byte decompressed, byte
						else
							token = data[position, 2]
							raise FormatError, 'truncated copy token' unless token && token.length == 2
							position += 2

							packed = token.unpack('v').first
							offset_bits, length_bits = copy_token_help(decompressed.length)
							distance = packed & ((1 << offset_bits) - 1)
							length_field = packed >> offset_bits
							length_mask = (1 << length_bits) - 1
							distance += 1
							source_position = decompressed.length - distance

							raise FormatError, 'invalid copy token offset' if distance > decompressed.length
							raise FormatError, 'invalid copy token length' if length_field > length_mask
							length = length_field + 3
							remaining_output = reserve_output(remaining_output, length)
							length.times do
								raise FormatError, 'compressed chunk exceeds 4096 bytes' if decompressed.length >= CHUNK_SIZE
								append_byte decompressed, decompressed[source_position]
								source_position += 1
							end
						end

						break if decompressed.length >= CHUNK_SIZE
					end

				end
					raise FormatError, 'compressed chunk exceeds 4096 bytes' if decompressed.length > CHUNK_SIZE
					raise FormatError, 'trailing bytes in compressed chunk' unless position == data.length
					raise FormatError, 'compressed chunk produced no output' if decompressed.empty?
					raise FormatError, 'compressed chunk must contain 4096 bytes' unless final_chunk || decompressed.length == CHUNK_SIZE

				write_output output, decompressed, remaining_output
			end

			def append_byte(output, byte)
				raise FormatError, 'compressed chunk exceeds 4096 bytes' if output.length >= CHUNK_SIZE
				output << byte
			end

			def reserve_output(remaining_output, amount)
				return remaining_output if remaining_output.nil?
				raise FormatError, 'maximum output length exceeded' if amount > remaining_output
				remaining_output - amount
			end

			def copy_token_help(current_length)
				offset_bits = bit_length(current_length - 1)
				offset_bits = 4 if offset_bits < 4
				offset_bits = 12 if offset_bits > 12
				length_bits = 16 - offset_bits
				[offset_bits, length_bits, (1 << length_bits) + 2]
			end

			def encode_chunk(chunk)
				result = ''.dup
				position = 0
				matches = Array.new(1 << 16) { [] }

				while position < chunk.length
					token_start = result.length
					result << 0
					flags = 0

					8.times do |token_index|
						break unless position < chunk.length
						distance, length = find_match(chunk, position, matches)

						if length >= 3
							offset_bits, = copy_token_help(position)
							result << [(distance - 1) | ((length - 3) << offset_bits)].pack('v')
							flags |= 1 << token_index
							remember_matches chunk, position, length, matches
							position += length
						else
							result << chunk[position]
							remember_match matches, chunk, position
							position += 1
						end
					end

					result.setbyte(token_start, flags)
				end

				result
			end

			def find_match(chunk, position, matches)
				return [nil, 0] if position + 3 > chunk.length

				best_distance = nil
				best_length = 0
				key = match_key(chunk, position)
				_, _, max_match_length = copy_token_help(position)
				max_match_length = [max_match_length, chunk.length - position].min
				matches[key].last(MATCH_CHAIN_DEPTH).reverse_each do |match_position|
					distance = position - match_position
					match_length = matching_length(chunk, match_position, position, max_match_length)
					if match_length > best_length
						best_distance = distance
						best_length = match_length
					end
				end
				best_length >= 3 ? [best_distance, best_length] : [nil, 0]
			end

			def matching_length(chunk, match_position, position, max_length)
				length = 0
				while length < max_length && chunk.getbyte(match_position + length) == chunk.getbyte(position + length)
					length += 1
				end
				length
			end

			def remember_matches(chunk, start, length, matches)
				length.times do |offset|
					position = start + offset
					remember_match matches, chunk, position if position + 3 <= chunk.length
				end
			end

			def remember_match(matches, chunk, position)
				return if position + 3 > chunk.length
				key = match_key(chunk, position)
				matches[key] << position
			end

			def bit_length(value)
				bits = 0
				while value > 0
					value >>= 1
					bits += 1
				end
				bits
			end

			def match_key(chunk, position)
				(chunk.getbyte(position) << 8) ^ (chunk.getbyte(position + 1) << 4) ^ chunk.getbyte(position + 2)
			end
		end
	end

	VBA = VBACompression unless const_defined?(:VBA)
end
