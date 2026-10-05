# encoding: ASCII-8BIT

require 'ole/msg/base'

module Ole # :nodoc:
	module Msg
		#
		# The stable identity of a named property, resolved through the
		# +__nameid_version1.0+ mapping storage. A named property is identified
		# by the GUID of its property set plus either a string name or a numeric
		# LID - never by the transient 0x8000+ property number used within a
		# particular file.
		#
		class PropertyName
			attr_reader :guid, :kind, :name, :lid

			def initialize guid, kind, name_or_lid
				@guid, @kind = guid, kind
				if kind == :string
					@name = name_or_lid
				else
					@lid = name_or_lid
				end
			end

			def key
				[guid && guid.format, kind == :string ? name : lid]
			end

			def inspect
				"#<#{self.class} #{key.inspect}>"
			end
		end

		#
		# A named property and its decoded value. +name+ is the resolved
		# PropertyName (may be nil if the file's nameid mapping didn't cover
		# this property number).
		#
		class NamedProperty
			attr_reader :number, :name, :type, :value

			def initialize number, name, type, value
				@number, @name, @type, @value = number, name, type, value
			end

			def guid
				name && name.guid
			end

			def kind
				name && name.kind
			end

			# the string name, when the property is named by string
			def string_name
				name && name.name
			end

			# the numeric lid, when the property is named by lid
			def lid
				name && name.lid
			end

			def key
				name ? name.key : [nil, number]
			end

			def inspect
				"#<#{self.class} #{key.inspect}=#{value.inspect}>"
			end
		end

		#
		# Parses the +__nameid_version1.0+ storage of a message, mapping the
		# transient 0x8000+ property numbers used in the file's streams to
		# stable PropertyName identities (GUID + string name or LID).
		#
		class NameIDMap
			# well known property sets, referenced by index rather than appearing
			# in the guid stream ([MS-OXMSG] 2.2.3.1).
			PS_MAPI           = Types::Clsid.parse '{00020328-0000-0000-c000-000000000046}'
			PS_PUBLIC_STRINGS = Types::Clsid.parse '{00020329-0000-0000-c000-000000000046}'

			attr_reader :guids, :names

			def initialize guids=[], names=[]
				@guids, @names = guids, names
			end

			def self.load root
				storage = root / NAMEID_STORAGE
				return new unless storage
				path = Msg.path_of storage
				guid_data   = read_stream(storage, GUID_STREAM)   || ''
				entry_data  = read_stream(storage, ENTRY_STREAM)  || ''
				string_data = read_stream(storage, STRING_STREAM) || ''
				guids = guid_data.scan(/.{16}/m).map { |data| Types::Clsid.load data }
				names = []
				entry_data.scan(/.{8}/m) do |rec|
					name_id, prop_index, guid_kind = rec.unpack 'V v v'
					guid_index = guid_kind >> 1
					guid = case guid_index
						when 1 then PS_MAPI
						when 2 then PS_PUBLIC_STRINGS
						else guids[guid_index - 3]
					end
					if guid_kind & 1 == 1
						if name_id + 4 > string_data.bytesize
							raise FormatError, "corrupt nameid mapping in #{path}: string offset out of range"
						end
						length = string_data[name_id, 4].unpack('V').first
						if name_id + 4 + length > string_data.bytesize
							raise FormatError, "corrupt nameid mapping in #{path}: truncated string name"
						end
						name = Msg.decode_unicode string_data[name_id + 4, length]
						names[prop_index - 1] = PropertyName.new guid, :string, name
					else
						names[prop_index - 1] = PropertyName.new guid, :lid, name_id
					end
				end
				new guids, names
			end

			# the PropertyName for a 0x8000+ property number, or nil if unmapped.
			def resolve number
				number >= 0x8000 ? @names[number - 0x8000] : nil
			end

			def self.read_stream storage, name
				dirent = storage / name
				dirent && dirent.file? ? dirent.read : nil
			end
		end
	end
end
