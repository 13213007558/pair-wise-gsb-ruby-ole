# encoding: ASCII-8BIT

require 'ole/storage'

module Ole # :nodoc:
	#
	# = Ole::Msg
	#
	# A read-only layer for Outlook MSG files ([MS-OXMSG]) on top of
	# Ole::Storage.
	#
	# An MSG file is an OLE compound document whose streams and storages encode
	# a MAPI message: fixed (predefined) properties live in the
	# +__properties_version1.0+ stream, while named and multi-valued properties
	# live in +__substg1.0_*+ streams, keyed through the +__nameid_version1.0+
	# mapping storage. Recipients and attachments are child storages, and an
	# attachment may itself embed a further message.
	#
	#   require 'ole/msg'
	#
	#   Ole::Msg.open 'message.msg' do |msg|
	#     puts msg.subject
	#     msg.recipients.each { |r| puts "#{r.name} <#{r.email}>" }
	#     msg.attachments.each { |a| puts a.filename }
	#   end
	#
	# This layer deliberately performs no MIME conversion, and does not parse
	# or execute attachment content; attachment data is returned as raw bytes,
	# and embedded messages are exposed as nested Ole::Msg::Message objects.
	#
	module Msg
		# thrown for any bogus MSG file errors. the message carries the path of
		# the storage that triggered the problem where possible.
		class FormatError < Storage::FormatError; end

		# MAPI property types ([MS-OXCDATA] 2.11.1), the subset we decode.
		module PropertyType
			PT_I2       = 0x0002
			PT_LONG     = 0x0003
			PT_R4       = 0x0004
			PT_DOUBLE   = 0x0005
			PT_CURRENCY = 0x0006
			PT_APPTIME  = 0x0007
			PT_ERROR    = 0x000a
			PT_BOOLEAN  = 0x000b
			PT_OBJECT   = 0x000d
			PT_I8       = 0x0014
			PT_STRING8  = 0x001e
			PT_UNICODE  = 0x001f
			PT_SYSTIME  = 0x0040
			PT_CLSID    = 0x0048
			PT_BINARY   = 0x0102
			MV_FLAG     = 0x1000
		end

		include PropertyType

		# size in bytes of the scalar property types, used both for the value
		# field of fixed length property stream entries, and for splitting
		# multi-valued streams into elements.
		FIXED_LENGTHS = {
			PT_I2 => 2, PT_LONG => 4, PT_R4 => 4, PT_DOUBLE => 8,
			PT_CURRENCY => 8, PT_APPTIME => 8, PT_ERROR => 4, PT_BOOLEAN => 2,
			PT_I8 => 8, PT_SYSTIME => 8
		}

		# scalar types whose data is stored out of line (a variable length entry
		# in the property stream, or a dedicated stream for named properties).
		VARIABLE_LENGTH_TYPES = [PT_OBJECT, PT_STRING8, PT_UNICODE, PT_CLSID, PT_BINARY]

		DEFAULT_CODEPAGE = 1252

		PROPERTIES_STREAM    = '__properties_version1.0'
		NAMEID_STORAGE       = '__nameid_version1.0'
		GUID_STREAM          = '__substg1.0_00020102'
		ENTRY_STREAM         = '__substg1.0_00030102'
		STRING_STREAM        = '__substg1.0_00040102'
		EMBEDDED_MSG_STORAGE = '__substg1.0_3701000D'

		ATTACH_BY_VALUE     = 1
		ATTACH_EMBEDDED_MSG = 5

		# Open an MSG file. +arg+ can be a filename, an IO object, or an already
		# open Ole::Storage. Returns a Msg::Message.
		def self.open arg, &block
			Message.open arg, &block
		end

		# the slash separated path of +dirent+ within its storage, used to
		# locate errors in corrupt files.
		def self.path_of dirent
			parts = []
			while dirent && dirent.parent
				parts.unshift dirent.name
				dirent = dirent.parent
			end
			'/' + parts.join('/')
		end

		def self.variable_length? type
			type & MV_FLAG != 0 || VARIABLE_LENGTH_TYPES.include?(type)
		end

		# decode a single scalar value of the given (base) property type.
		def self.decode_scalar type, data, codepage
			data = data.to_s
			case type
			when PT_I2              then data[0, 2].unpack('v').first
			when PT_LONG            then data[0, 4].unpack('l<').first
			when PT_ERROR           then data[0, 4].unpack('V').first
			when PT_R4              then data[0, 4].unpack('e').first
			when PT_DOUBLE, PT_APPTIME then data[0, 8].unpack('E').first
			when PT_CURRENCY        then data[0, 8].unpack('q<').first / 10000.0
			when PT_BOOLEAN         then data[0, 2].unpack('v').first != 0
			when PT_I8              then data[0, 8].unpack('q<').first
			when PT_SYSTIME         then Types::FileTime.load data[0, 8]
			when PT_CLSID           then Types::Clsid.load data[0, 16]
			when PT_UNICODE         then decode_unicode data
			when PT_STRING8         then decode_string8 data, codepage
			else data
			end
		end

		# decode a property value, expanding multi-valued fixed length types.
		def self.decode_value type, data, codepage
			base = type & ~MV_FLAG
			if type & MV_FLAG != 0
				size = FIXED_LENGTHS[base] or return data
				(0...data.bytesize).step(size).map do |offset|
					decode_scalar base, data[offset, size], codepage
				end
			else
				decode_scalar base, data, codepage
			end
		end

		def self.decode_unicode data
			str = data.to_s.dup.force_encoding Encoding::UTF_16LE
			str.encode(Encoding::UTF_8).sub(/\0+\z/, '')
		rescue EncodingError
			data.to_s.dup.force_encoding Encoding::ASCII_8BIT
		end

		def self.decode_string8 data, codepage
			str = data.to_s.sub(/\0+\z/, '')
			encoding = begin
				Encoding.find "CP#{codepage || DEFAULT_CODEPAGE}"
			rescue ArgumentError
				Encoding::ASCII_8BIT
			end
			str.force_encoding(encoding).encode Encoding::UTF_8
		rescue EncodingError
			str.force_encoding Encoding::ASCII_8BIT
		end
	end
end
