#! /usr/bin/ruby

$: << File.dirname(__FILE__) + '/../lib'

require 'test/unit'
require 'stringio'
require 'ole/vba_compression'

class TestVBACompression < Test::Unit::TestCase
	# hand crafted compressed containers (hex), kept short on purpose:
	#
	# 01                   container signature
	# 08 b0                chunk header: compressed, 9 bytes of chunk data
	# 00                   flag byte: 8 literals follow
	# 41..48               "ABCDEFGH"
	LITERALS_VECTOR = ['0108b0004142434445464748'].pack('H*')

	# flag 08: literals "ABC", then a copy token (offset 3, length 6)
	COPY_VECTOR     = ['0105b0084142432' + '300'].pack('H*')

	# flag 02: literal "A", then an overlapping copy token (offset 1,
	# length 10) which must replicate its own output byte by byte
	OVERLAP_VECTOR  = ['0103b002410700'].pack('H*')

	# flag 01: a copy token as the very first token; offset 1 has no
	# history to point at
	BAD_OFFSET_VECTOR = ['0102b0010000'].pack('H*')

	# flag 04: literals "AB", then a copy token with offset 5 while only
	# 2 bytes of history exist
	BAD_OFFSET_VECTOR2 = ['0104b004414240' + '00'].pack('H*')

	def decode str, limit=nil
		out = StringIO.new "".b
		written = Ole::VBACompression.decode StringIO.new(str), out, limit
		assert_equal out.string.bytesize, written
		out.string
	end

	def encode str
		out = StringIO.new "".b
		written = Ole::VBACompression.encode StringIO.new(str), out
		assert_equal out.string.bytesize, written
		out.string
	end

	def test_known_vectors
		assert_equal 'ABCDEFGH', decode(LITERALS_VECTOR)
		assert_equal 'ABCABCABC', decode(COPY_VECTOR)
		assert_equal 'A' * 11, decode(OVERLAP_VECTOR)
	end

	def test_bad_offset_vectors
		assert_raise(Ole::VBACompression::Error) { decode BAD_OFFSET_VECTOR }
		assert_raise(Ole::VBACompression::Error) { decode BAD_OFFSET_VECTOR2 }
	end

	def test_bad_container
		assert_raise(Ole::VBACompression::Error) { decode '' }
		assert_raise(Ole::VBACompression::Error) { decode "\x02" }
		# truncated chunk header
		assert_raise(Ole::VBACompression::Error) { decode "\x01\x08" }
		# chunk data shorter than the header promises
		assert_raise(Ole::VBACompression::Error) { decode "\x01\x08\xb0\x00" }
		# bad chunk header signature bits
		assert_raise(Ole::VBACompression::Error) { decode "\x01\x08\x90\x00" * 10 }
		# truncated raw chunk
		assert_raise(Ole::VBACompression::Error) { decode "\x01\xff\x3f" + 'A' * 100 }
	end

	def test_output_limit
		assert_equal 'ABCDEFGH', decode(LITERALS_VECTOR, 8)
		assert_raise(Ole::VBACompression::Error) { decode LITERALS_VECTOR, 7 }
		packed = encode 'A' * 10_000
		assert_equal 'A' * 10_000, decode(packed, 10_000)
		assert_raise(Ole::VBACompression::Error) { decode packed, 9_999 }
	end

	def test_roundtrip_sizes
		# around and across the 4096 byte chunk boundary
		[0, 1, 2, 100, 4095, 4096, 4097, 8191, 8192, 8193, 20_000].each do |size|
			data = (0...size).map { |i| 'ABCDEFGH'[i % 8] }.join
			assert_equal data, decode(encode(data)), "patterned size #{size}"
			random = Random.new(1234).bytes size
			assert_equal random, decode(encode(random)), "random size #{size}"
		end
	end

	def test_roundtrip_long_repeats
		['A' * 100_000, 'ab' * 50_000, 'The quick brown fox. ' * 5_000].each do |data|
			packed = encode data
			assert packed.bytesize < data.bytesize / 10
			assert_equal data, decode(packed)
		end
	end

	def test_no_reference_across_chunk_boundary
		# the second chunk repeats bytes from the first one; the encoder
		# must not reference back across the 4096 byte boundary (the strict
		# decoder would raise on such an offset).
		block = Random.new(99).bytes 4096
		assert_equal block + block, decode(encode(block + block))
		text = ('Attribute VB_Name = "Module1"' + "\r\n" + 'Sub Main()' + "\r\n") * 200
		assert_equal text + text, decode(encode(text + text))
	end

	def test_uncompressed_chunk_when_no_gain
		random = Random.new(42).bytes 4096
		packed = encode random
		assert_equal 1, packed.getbyte(0)
		# raw chunk header: signature bits 0b011, flag clear, size 4095
		assert_equal 0x3fff, packed[1, 2].unpack('v').first
		assert_equal 1 + 2 + 4096, packed.bytesize
		assert_equal random, decode(packed)
	end

	def test_compressed_chunk_header
		packed = encode 'A' * 4096
		header = packed[1, 2].unpack('v').first
		assert_equal 0x3000, header & 0x7000
		assert_equal 0x8000, header & 0x8000
		assert packed.bytesize < 1000
	end

	def test_io_objects
		# anything IO like will do, not just StringIO
		dst, src = IO.pipe
		src.write encode("hello " * 1000)
		src.close
		out = StringIO.new "".b
		Ole::VBACompression.decode dst, out
		assert_equal 'hello ' * 1000, out.string
	end
end
