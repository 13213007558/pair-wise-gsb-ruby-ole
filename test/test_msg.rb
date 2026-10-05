#! /usr/bin/ruby
# coding: utf-8

$: << File.dirname(__FILE__) + '/../lib'

require 'test/unit'
require 'stringio'
require 'ole/msg'

#
# Tests for the MSG reading layer (Ole::Msg). The fixtures are small MSG
# files constructed in memory: a message with two recipients, a regular
# attachment and an embedded-message attachment, plus a named property
# mapping exercising GUID, string name and LID forms.
#
class TestMsg < Test::Unit::TestCase
	CUSTOM_GUID = '{00062008-0000-0000-c000-000000000046}'

	# utf-16le, as stored for PT_UNICODE values and nameid string names
	def utf16 str
		Ole::Types::Lpwstr.dump(str) + 0.chr * 2
	end

	def fixed_entry id, type, value
		[(id << 16) | type, 0].pack('V2') + value.ljust(8, 0.chr)
	end

	def long_entry id, value
		fixed_entry id, 0x0003, [value].pack('V')
	end

	def var_entry id, type, data
		[(id << 16) | type, 0, data.bytesize].pack('V3') + data + 0.chr * ((8 - data.bytesize % 8) % 8)
	end

	def unicode_entry id, str
		var_entry id, 0x001f, utf16(str)
	end

	def string8_entry id, str
		var_entry id, 0x001e, str + 0.chr
	end

	def binary_entry id, data
		var_entry id, 0x0102, data
	end

	# 32 byte message object property stream header
	def msg_header recip_count, attach_count
		0.chr * 8 + [recip_count, attach_count, recip_count, attach_count].pack('V4') + 0.chr * 8
	end

	# 16 byte recipient/attachment property stream header
	def embedded_header
		0.chr * 16
	end

	def write_stream ole, path, data
		ole.file.open(path, 'w') { |f| f.write data }
	end

	def build_string_stream names
		data, offsets = ''.b, []
		names.each do |name|
			offsets << data.bytesize
			enc = Ole::Types::Lpwstr.dump name
			data << [enc.bytesize].pack('V') << enc
			data << 0.chr * ((4 - data.bytesize % 4) % 4)
		end
		[data, offsets]
	end

	def build_msg
		io = StringIO.new
		Ole::Storage.open io do |ole|
			# named property mapping: guid stream, entry stream, string stream
			string_stream, offsets = build_string_stream %w[MyCustomProp MyMultiProp]
			entries = [
				[offsets[0], 1, (3 << 1) | 1], # 0x8000: "MyCustomProp", guid stream guid
				[0x8501,     2, 1 << 1],       # 0x8001: lid 0x8501, PS_MAPI
				[offsets[1], 3, (2 << 1) | 1], # 0x8002: "MyMultiProp", PS_PUBLIC_STRINGS
				[0x8502,     4, 1 << 1],       # 0x8003: lid 0x8502, PS_MAPI
			]
			ole.dir.mkdir '/__nameid_version1.0'
			write_stream ole, '/__nameid_version1.0/__substg1.0_00020102', Ole::Types::Clsid.parse(CUSTOM_GUID)
			write_stream ole, '/__nameid_version1.0/__substg1.0_00030102', entries.map { |e| e.pack 'Vvv' }.join
			write_stream ole, '/__nameid_version1.0/__substg1.0_00040102', string_stream

			# named property value streams
			write_stream ole, '/__substg1.0_8000001F', utf16('named value')
			write_stream ole, '/__substg1.0_80010003', [42].pack('V')
			write_stream ole, '/__substg1.0_8002101F', ''.b
			write_stream ole, '/__substg1.0_8002101F-00000000', utf16('one')
			write_stream ole, '/__substg1.0_8002101F-00000001', utf16('two')
			write_stream ole, '/__substg1.0_80031003', [1, 2, 3].pack('V3')

			# message properties
			write_stream ole, '/__properties_version1.0',
				msg_header(2, 2) +
				unicode_entry(0x0037, 'Re: 主题 héllo') +
				unicode_entry(0x1000, 'Body text') +
				string8_entry(0x003d, "Re: caf\xe9".b) +
				long_entry(0x3ffd, 1252)

			# two recipients
			ole.dir.mkdir '/__recip_version1.0_#00000000'
			write_stream ole, '/__recip_version1.0_#00000000/__properties_version1.0',
				embedded_header +
				unicode_entry(0x3001, 'Alice') +
				unicode_entry(0x3003, 'alice@example.com') +
				long_entry(0x0c15, 1)
			ole.dir.mkdir '/__recip_version1.0_#00000001'
			write_stream ole, '/__recip_version1.0_#00000001/__properties_version1.0',
				embedded_header +
				unicode_entry(0x3001, 'Bob') +
				string8_entry(0x3003, 'bob@example.com'.b) +
				long_entry(0x0c15, 2)

			# a regular attachment
			ole.dir.mkdir '/__attach_version1.0_#00000000'
			write_stream ole, '/__attach_version1.0_#00000000/__properties_version1.0',
				embedded_header +
				unicode_entry(0x3707, 'hello.txt') +
				long_entry(0x3705, 1) +
				binary_entry(0x3701, 'file contents'.b)

			# an embedded-message attachment
			ole.dir.mkdir '/__attach_version1.0_#00000001'
			write_stream ole, '/__attach_version1.0_#00000001/__properties_version1.0',
				embedded_header +
				unicode_entry(0x3707, 'embedded.msg') +
				long_entry(0x3705, 5)
			ole.dir.mkdir '/__attach_version1.0_#00000001/__substg1.0_3701000D'
			write_stream ole, '/__attach_version1.0_#00000001/__substg1.0_3701000D/__properties_version1.0',
				msg_header(0, 0) +
				unicode_entry(0x0037, 'Embedded note')
		end
		io.rewind
		io
	end

	def setup
		@msg = Ole::Msg.open build_msg
	end

	def test_fixed_properties
		assert_equal 'Re: 主题 héllo', @msg.subject
		assert_equal 'Body text', @msg.body
		# PT_STRING8 decoded using the message codepage (1252)
		assert_equal 'Re: café', @msg.properties[0x003d]
		assert_equal 1252, @msg.properties[0x3ffd]
		assert_equal 2, @msg.properties.recipient_count
		assert_equal 2, @msg.properties.attachment_count
	end

	def test_fixed_and_named_are_separate
		assert !@msg.properties.fixed.empty?
		@msg.properties.fixed.each_key { |id| assert id < 0x8000, "0x#{id.to_s 16}" }
		assert_equal 4, @msg.properties.named.length
		@msg.properties.named.each { |prop| assert prop.number >= 0x8000 }
	end

	def test_named_properties_keep_stable_identity
		named = @msg.properties.named
		custom = named.find { |prop| prop.string_name == 'MyCustomProp' }
		assert_equal Ole::Types::Clsid.parse(CUSTOM_GUID).format, custom.guid.format
		assert_equal :string, custom.kind
		assert_equal 'named value', custom.value

		lid_prop = named.find { |prop| prop.lid == 0x8501 }
		assert_equal :lid, lid_prop.kind
		assert_equal Ole::Msg::NameIDMap::PS_MAPI.format, lid_prop.guid.format
		assert_equal 42, lid_prop.value

		assert_equal 'named value', @msg.properties.named_lookup(CUSTOM_GUID, 'MyCustomProp')
		assert_equal 42, @msg.properties.named_lookup(Ole::Msg::NameIDMap::PS_MAPI, 0x8501)
		assert_equal 'named value',
			@msg.properties.named_map[[CUSTOM_GUID.delete('{}').downcase, 'MyCustomProp']]
	end

	def test_multi_valued_named_properties
		mv_strings = @msg.properties.named.find { |prop| prop.string_name == 'MyMultiProp' }
		assert_equal %w[one two], mv_strings.value
		mv_longs = @msg.properties.named.find { |prop| prop.lid == 0x8502 }
		assert_equal [1, 2, 3], mv_longs.value
	end

	def test_recipients
		recipients = @msg.recipients
		assert_equal 2, recipients.length
		assert_equal 'Alice', recipients[0].name
		assert_equal 'alice@example.com', recipients[0].email
		assert_equal 1, recipients[0].type
		assert_equal 'Bob', recipients[1].name
		assert_equal 'bob@example.com', recipients[1].email
		assert_equal 2, recipients[1].type
	end

	def test_attachments
		attachments = @msg.attachments
		assert_equal 2, attachments.length
		assert_equal 'hello.txt', attachments[0].filename
		assert_equal 'file contents', attachments[0].data
		assert !attachments[0].embedded?
		assert_nil attachments[0].embedded_msg
	end

	def test_embedded_message_attachment
		attachment = @msg.attachments[1]
		assert_equal 'embedded.msg', attachment.filename
		assert attachment.embedded?
		# no raw data for embedded messages; the content is another message
		assert_nil attachment.data
		embedded = attachment.embedded_msg
		assert_kind_of Ole::Msg::Message, embedded
		assert_equal 'Embedded note', embedded.subject
		assert_equal [], embedded.recipients
		assert_equal [], embedded.attachments
	end

	def test_corrupt_property_stream_locates_storage
		io = StringIO.new
		Ole::Storage.open io do |ole|
			ole.dir.mkdir '/__recip_version1.0_#00000000'
			# 20 bytes: a 16 byte header plus half a property entry
			write_stream ole, '/__recip_version1.0_#00000000/__properties_version1.0', 0.chr * 20
			write_stream ole, '/__properties_version1.0', msg_header(1, 0)
		end
		io.rewind
		msg = Ole::Msg.open io
		error = assert_raise Ole::Msg::FormatError do
			msg.recipients
		end
		assert_match %r{/__recip_version1\.0_#00000000}, error.message
	end

	def test_missing_property_stream_locates_storage
		io = StringIO.new
		Ole::Storage.open io do |ole|
			ole.dir.mkdir '/__attach_version1.0_#00000000'
			write_stream ole, '/__properties_version1.0', msg_header(0, 1)
		end
		io.rewind
		msg = Ole::Msg.open io
		error = assert_raise Ole::Msg::FormatError do
			msg.attachments
		end
		assert_match %r{/__attach_version1\.0_#00000000}, error.message
	end
end
