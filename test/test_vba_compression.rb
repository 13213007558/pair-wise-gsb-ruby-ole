#! /usr/bin/ruby
# encoding: ASCII-8BIT

$: << File.dirname(__FILE__) + '/../lib'

require 'test/unit'
require 'ole/vba_compression'
require 'stringio'

class TestVBACompression < Test::Unit::TestCase
	def test_round_trip_short_and_repeated_data
		[ '', 'abc', 'abcabcabc', 'a' * 100, 'ab' * 3000 ].each do |data|
			assert_equal data, Ole::VBACompression.decode(Ole::VBACompression.encode(data))
		end
	end

	def test_chunk_boundaries_are_self_contained
		data = 'a' * 8192
		compressed = Ole::VBACompression.encode(data)
		assert_equal 13, compressed.length
		assert_equal data, Ole::VBACompression.decode(compressed)
		assert_equal "\x03\xb0", compressed[1, 2]
		assert_equal "\x03\xb0", compressed[7, 2]
	end

	def test_uncompressed_blocks_are_used_for_incompressible_boundaries
		first = Random.new(7).bytes(4096)
		compressed = Ole::VBACompression.encode(first + 'x')
		assert_equal "\xff\x3f", compressed[1, 2]
		assert_equal "\x00\x30", compressed[4099, 2]
		assert_equal first + 'x', Ole::VBACompression.decode(compressed)
	end

	def test_encoder_uses_uncompressed_block_when_compression_does_not_pay
		data = Random.new(11).bytes(5000)
		compressed = Ole::VBACompression.encode(data)
		assert_equal "\xff\x3f", compressed[1, 2]
		assert_equal data, Ole::VBACompression.decode(compressed)
	end

	def test_overlapping_copy_takes_effect_incrementally
		compressed = [
			0x01,
			0x03, 0xb0,
			0x02, 0x61,
			0x70, 0x00
		].pack('C*')
		assert_equal 'a' * 11, Ole::VBACompression.decode(compressed)
	end

	def test_long_overlapping_copy
		body = "\x02a" + [0xffc0].pack('v')
		compressed = "\x01" + [0xb000 | (body.length - 1)].pack('v') + body
		assert_equal 'a' * 4096, Ole::VBACompression.decode(compressed)
	end

	def test_copy_token_distance_bits_change_with_position
		literals16 = (0...16).map(&:chr).join
		compressed16 = explicit_copy_container(literals16, 0x000f, 16)
		assert_equal "\x0f\x00", compressed16[-2, 2]
		assert_equal literals16 + "\x00\x01\x02", Ole::VBACompression.decode(compressed16)

		literals17 = literals16 + 0x10.chr
		compressed17 = explicit_copy_container(literals17, 0x0010, 17)
		assert_equal "\x10\x00", compressed17[-2, 2]
		assert_equal literals17 + "\x00\x01\x02", Ole::VBACompression.decode(compressed17)
	end

	def test_bad_copy_offset
		compressed = [0x01, 0x03, 0xb0, 0x02, 0x61, 0x01, 0x00].pack('C*')
		assert_raises(Ole::VBACompression::FormatError) do
			Ole::VBACompression.decode(compressed)
		end
	end

	def test_max_output_length
		compressed = Ole::VBACompression.encode('abc')
		assert_equal 'abc', Ole::VBACompression.decode(compressed, nil, 3)
		assert_raises(Ole::VBACompression::FormatError) do
			Ole::VBACompression.decode(compressed, nil, 2)
		end
		assert_raises(ArgumentError) { Ole::VBACompression.decode(compressed, nil, -1) }
	end

	def test_io_inputs_and_outputs
		source = StringIO.new('abcabcabc')
		compressed_io = StringIO.new
		assert_same compressed_io, Ole::VBACompression.encode(source, compressed_io)

		decoded_io = StringIO.new
		assert_same decoded_io, Ole::VBACompression.decode(StringIO.new(compressed_io.string), decoded_io)
		assert_equal Encoding::ASCII_8BIT, decoded_io.string.encoding
		assert_equal 'abcabcabc', decoded_io.string
	end

	def test_string_input_and_io_output_keep_bytes_binary
		io = StringIO.new
		result = Ole::VBACompression.decode(StringIO.new(Ole::VBACompression.encode('abcabcabc')), io)
		assert_same io, result
		assert_equal Encoding::ASCII_8BIT, io.string.encoding
	end

	private

	def explicit_copy_container(literals, packed, position)
		groups = Array.new((position + 1 + 7) / 8) { |group|
			start = group * 8
			tokens = (start...[start + 8, position + 1].min).map { |index|
				index == position ? [1, [packed].pack('v')] : [0, literals[index]]
			}
			flags = tokens.map(&:first).each_with_index.inject(0) { |value, (bit, index)| value | (bit << index) }
			flags.chr + tokens.map(&:last).join
		}.join
		"\x01" + [0xb000 | (groups.length - 1)].pack('v') + groups
	end
end
