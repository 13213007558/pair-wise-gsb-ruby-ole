# encoding: ASCII-8BIT

module Ole
	class Msg
		class NameIdMapping
			PS_MAPI = Types::Clsid.parse('{00020328-0000-0000-c000-000000000046}')
			PS_PUBLIC_STRINGS = Types::Clsid.parse('{00020329-0000-0000-c000-000000000046}')

			def self.load(root, path, parent_mapping=nil)
				nameid = root['__nameid_version1.0']
				return parent_mapping unless nameid && nameid.dir?
				new(nameid, path)
			end

			def initialize(nameid, path)
				@path = path
				@by_index = {}

				guid_stream = read_required(nameid, '__substg1.0_00020102')
				entry_stream = read_required(nameid, '__substg1.0_00030102')
				names_stream = read_optional(nameid, '__substg1.0_00040102')

				validate!(guid_stream.size % 16 == 0)
				validate!(entry_stream.size % 8 == 0)

				guids = [nil, PS_MAPI, PS_PUBLIC_STRINGS]
				guid_stream.bytes.each_slice(16) { |bytes| guids << Types::Clsid.load(bytes.pack('C*')) }

				entry_stream.bytes.each_slice(8) do |bytes|
					entry = bytes.pack('C*')
					name_id, flags, property_index = entry.unpack('Vvv')
					property_kind = flags & 1
					guid_index = flags >> 1
					guid = guids[guid_index]
					validate!(!guid.nil?)

					if property_kind == 1
						name = read_name(names_stream, name_id)
						key = NamedProperty::Key.new(guid, name, nil)
					else
						key = NamedProperty::Key.new(guid, nil, name_id)
					end

					@by_index[0x8000 + property_index] = key
				end
			end

			attr_reader :by_index

			def [](property_id)
				@by_index[property_id]
			end

			private

			def read_required(nameid, name)
				stream = nameid[name]
				validate!(stream && stream.file?)
				stream.read
			end

			def read_optional(nameid, name)
				stream = nameid[name]
				stream && stream.file? ? stream.read : EMPTY_BYTES
			end

			def read_name(stream, offset)
				validate!(offset + 4 <= stream.size)
				length = stream[offset, 4].unpack1('V')
				start = offset + 4
				validate!(start + length <= stream.size)
				data = stream[start, length].dup.force_encoding(Encoding::ASCII_8BIT)
				data.encode(Encoding::UTF_8, Encoding::UTF_16LE,
					:invalid => :replace, :undef => :replace)
			end

			def validate!(condition)
				return if condition
				location = if @path.empty?
					'__nameid_version1.0'
				else
					"#{@path}/__nameid_version1.0"
				end
				raise FormatError, "corrupt named property storage #{location}"
			end

			EMPTY_BYTES = ''.dup.force_encoding(Encoding::ASCII_8BIT)
		end
	end
end
