# encoding: ASCII-8BIT

module Ole
	module Types
		class PropertySet
			HEADER_SIZE = 28
			HEADER_PACK = "vvVa#{Clsid::SIZE}V"
			DEFAULT_OS = 2
			DEFAULT_CODEPAGE = 1252

			OS_MAP = {0 => :win16, 1 => :mac, 2 => :win32, 0x20001 => :ooffice}

			DATA = {
				Clsid.parse('{f29f85e0-4ff9-1068-ab91-08002b27b3d9}') => ['FMTID_SummaryInformation', {
					2  => 'doc_title', 3 => 'doc_subject', 4 => 'doc_author',
					5  => 'doc_keywords', 6 => 'doc_comments', 7 => 'doc_template',
					8  => 'doc_last_author', 9 => 'doc_rev_number',
					10 => 'doc_edit_time', 11 => 'doc_last_printed',
					12 => 'doc_created_time', 13 => 'doc_last_saved_time',
					14 => 'doc_page_count', 15 => 'doc_word_count',
					16 => 'doc_char_count', 18 => 'doc_app_name', 19 => 'security'
				}],
				Clsid.parse('{d5cdd502-2e9c-101b-9397-08002b2cf9ae}') => ['FMTID_DocSummaryInfo', {
					2  => 'doc_category', 3 => 'doc_presentation_target',
					4  => 'doc_byte_count', 5 => 'doc_line_count',
					6  => 'doc_para_count', 7 => 'doc_slide_count',
					8  => 'doc_note_count', 9 => 'doc_hidden_count',
					10 => 'mmclips', 11 => 'scale_crop',
					12 => 'heading_pairs', 13 => 'doc_part_titles',
					14 => 'doc_manager', 15 => 'doc_company', 16 => 'links_up_to_date'
				}],
				Clsid.parse('{d5cdd505-2e9c-101b-9397-08002b2cf9ae}') => ['FMTID_UserDefinedProperties', {}]
			}

			PROPERTY_MAP = DATA.inject({}) do |h1, (guid, data)|
				data[1].inject(h1) { |h2, (id, name)| h2.update name => [guid, id] }
			end

			module Constants
				DATA.each { |guid, (name, _)| const_set name, guid }
			end

			include Constants
			include Enumerable

			CODEPAGE_ENCODINGS = {
				0 => Encoding::ASCII_8BIT, 1200 => Encoding::UTF_16LE,
				1201 => Encoding::UTF_16BE, 65000 => Encoding::UTF_7,
				65001 => Encoding::UTF_8,
			}

			class Property
				attr_accessor :id, :type, :value, :raw

				def initialize id, type=nil, value=nil, raw=nil
					@id, @type, @value, @raw = id, type, value, raw
				end

				def raw?
					!@raw.nil?
				end
			end

			attr_reader :io, :signature, :unknown, :os, :guid, :sections
			attr_accessor :os_id

			def self.create *guids
				guids = [FMTID_SummaryInformation] if guids.empty?
				property_set = allocate
				property_set.send :initialize_new, guids
				property_set
			end

			def initialize io=nil
				@io = io
				@signature = 0xfffe
				@unknown = 0
				@os_id = DEFAULT_OS
				@guid = Clsid.new(0.chr * Clsid::SIZE)
				@sections = []
				return unless io
				load_header io.read(HEADER_SIZE)
				load_section_list io.read(@num_sections * Section::SIZE)
			end

			def add_section guid
				guid = Clsid.load guid
				section = @sections.find { |s| s.guid == guid }
				return section if section
				@section = Section.create self, guid
				@sections << @section
				@section
			end

			def section guid
				guid = Clsid.load guid
				@sections.find { |s| s.guid == guid }
			end

			def [] key
				pair = PROPERTY_MAP[key.to_s]
				if pair
					section = section(pair.first)
					return section && section[pair.last]
				end
				@sections.each do |s|
					value = s[key]
					return value unless value.nil?
				end
				nil
			end

			def []= key, value, type=nil
				pair = PROPERTY_MAP[key.to_s]
				if pair
					section = section(pair.first)
					raise IndexError, "no section for #{key}" unless section
					return section.set_id(pair.last, value, type)
				end
				raise IndexError, 'user defined properties require a document summary section' unless section(FMTID_DocSummaryInfo)
				(section(FMTID_UserDefinedProperties) || add_section(FMTID_UserDefinedProperties)).set(key, value, type)
			end

			def set key, value, type=nil
				send :[]=, key, value, type
			end

			def delete key
				pair = PROPERTY_MAP[key.to_s]
				if pair
					s = section(pair.first)
					return s && s.delete_id(pair.last)
				end
				@sections.each do |s|
					value = s.delete(key)
					return value unless value.nil?
				end
				nil
			end

			def each
				@sections.each do |section|
					map = DATA[section.guid]
					section.each do |id, value|
						name = map && map[1][id] || section.name_for(id)
						yield name, value if name
					end
				end
			end

			def to_h
				inject({}) { |hash, (name, value)| hash.update name.to_sym => value }
			end

			def to_s
				body = @sections.map { |section| section.dump }
				offsets = []
				offset = HEADER_SIZE + @sections.length * Section::SIZE
				body.each do |data|
					offsets << offset
					offset += data.bytesize
				end
				list = @sections.zip(offsets).map do |section, section_offset|
					section.guid.to_s + [section_offset].pack('V')
				end.join
				data = [@signature, @unknown, @os_id, @guid.to_s, @sections.length].pack(HEADER_PACK) + list + body.join
				data.force_encoding(Encoding::ASCII_8BIT)
			end

			def save target=nil
				target ||= @io
				data = to_s
				target.seek 0
				target.truncate data.bytesize if target.respond_to? :truncate
				target.write data
				target.seek 0
				data.bytesize
			end

			def method_missing name, *args, &block
				if name.to_s =~ /(.*)=$/
					return super unless args.length == 1 && PROPERTY_MAP[$1]
					self[$1] = args.first
				else
					return super unless args.empty? && PROPERTY_MAP[name.to_s]
					self[name]
				end
			end

		def respond_to_missing? name, include_private=false
			PROPERTY_MAP.key?(name.to_s.sub(/=$/, '')) || super
		end

		class Section
			include Variant::Constants
			include Enumerable

			SIZE = Clsid::SIZE + 4
			PACK = "a#{Clsid::SIZE}V"

			LENGTH_TYPES = [VT_LPSTR, VT_LPWSTR, VT_BLOB, VT_STREAM, VT_STORAGE,
				VT_STREAMED_OBJECT, VT_STORED_OBJECT, VT_BLOB_OBJECT].inject({}) { |h, t| h.update t => true }

			FIXED_TYPES = {
				VT_I1 => ['c', 1], VT_UI1 => ['C', 1],
				VT_I2 => ['s', 2], VT_UI2 => ['v', 2],
				VT_I4 => ['l', 4], VT_UI4 => ['V', 4],
				VT_INT => ['l', 4], VT_UINT => ['V', 4],
				VT_ERROR => ['V', 4], VT_HRESULT => ['V', 4],
				VT_BOOL => ['V', 4], VT_R4 => ['e', 4],
				VT_R8 => ['E', 8], VT_DATE => ['E', 8],
				VT_I8 => ['q', 8], VT_UI8 => ['Q', 8],
				VT_FILETIME => ["a#{FileTime::SIZE}", FileTime::SIZE],
				VT_CLSID => ["a#{Clsid::SIZE}", Clsid::SIZE],
				VT_DECIMAL => ['a14', 14],
			}

			attr_accessor :guid, :offset
			attr_reader :properties

			def self.create property_set, guid
				section = allocate
				section.instance_variable_set :@property_set, property_set
				section.instance_variable_set :@properties, {1 => Property.new(1, VT_I2, DEFAULT_CODEPAGE)}
				section.instance_variable_set :@names, {}
				section.instance_variable_set :@codepage, DEFAULT_CODEPAGE
				section.guid = Clsid.load guid
				section.offset = 0
				section
			end

			def initialize str, property_set
				@property_set = property_set
				@properties = {}
				@names = {}
				@codepage = DEFAULT_CODEPAGE
				return unless str
				raw_guid, @offset = str.unpack PACK
				self.guid = Clsid.load raw_guid
				load
			end

			def length
				@properties.length
			end

			def byte_size
				dump.bytesize
			end

			def codepage
				property = @properties[1]
				value = property && property.type == VT_I2 ? property.value : @codepage
				value.is_a?(Integer) && value < 0 ? value + 65536 : value
			end

			def codepage= value
				set 1, value, VT_I2
			end

			def [] key, type=nil
				id = Integer === key ? key : @names.key(key)
				property = id && @properties[id]
				property ? property.value : nil
			end

			def []= key, value, type=nil
				set key, value, type
			end

			def set key, value, type=nil
				set_id id_for_key(key, true), value, type
			end

			def set_id id, value, type=nil
				return delete_id(id) if value.nil?
				old = @properties[id]
				type ||= old && old.type || infer_type(value, id)
				@properties[id] = Property.new(id, type, value)
				value
			end

			def delete key
				id = Integer === key ? key : @names.key(key)
				id ? delete_id(id) : nil
			end

			def delete_id id
				property = @properties.delete(id)
				@names.delete(id)
				@names.delete_if { |_, other_id| other_id == id }
				property && property.value
			end

			def name_for id
				@names[id]
			end

			def each
				@properties.each { |id, property| yield id, property.value }
			end

			def dump
				properties = @properties.dup
				if @properties.key?(0) || !@names.empty?
					properties[0] = Property.new(0, VT_BLOB, dump_dictionary)
				end
				entries = properties.keys.sort
				table = ''.dup.force_encoding(Encoding::ASCII_8BIT)
				body = ''.dup.force_encoding(Encoding::ASCII_8BIT)
				offset = 8 + entries.length * 8
				entries.each do |id|
					record = dump_property(properties[id])
					table << [id, offset].pack('V2')
					body << record.dup.force_encoding(Encoding::ASCII_8BIT)
					offset += record.bytesize
				end
				[8 + table.bytesize + body.bytesize, entries.length].pack('V2') + table + body
			end

		private

			def io
				@property_set.io
			end

			def id_for_key key, create
				return key if Integer === key
				id = @names.key(key)
				return id if id
				raise IndexError, "undefined property #{key.inspect}" unless create
				id = 2
				id += 1 while @properties.key?(id)
				@names[id] = key
				id
			end

			def infer_type value, id=nil
				if guid == PropertySet::FMTID_DocSummaryInfo && Array === value
					return VT_VECTOR | VT_VARIANT if id == 12
					return VT_VECTOR | VT_LPSTR if id == 13
				end
				if guid == PropertySet::FMTID_DocSummaryInfo && [11, 16].include?(id) && [true, false].include?(value)
					return VT_BOOL
				end
				return VT_FILETIME if guid == PropertySet::FMTID_SummaryInformation && [10, 11, 12, 13].include?(id)
				case value
				when FileTime, Time, Date then VT_FILETIME
				when Clsid then VT_CLSID
				when Data then VT_BLOB
				when String then VT_LPSTR
				when true, false then VT_BOOL
				when Float then VT_R8
				when Integer then VT_I4
				when Array then infer_vector_type(value)
				else raise ArgumentError, "unknown property value #{value.inspect}"
				end
			end

			def infer_vector_type values
				elements = values.map { |value| infer_type(value) & VT_TYPEMASK }
				if elements.empty? || elements.uniq.length != 1
					VT_VECTOR | VT_VARIANT
				else
					VT_VECTOR | elements.first
				end
			end

			def load
				io.seek offset
				@byte_size, @length = io.read(8).unpack 'V2'
				entries = @length.times.map { io.read(8).unpack('V2') }
				entries.each do |id, property_offset|
					raw = read_record(property_offset, entries)
					type = id == 0 ? VT_BLOB : raw[0, 4].unpack('V').first
					value = id == 0 ? raw : decode_value(type, raw)
					property = Property.new(id, type, value)
					property.raw = raw unless id == 0 || known_type?(type, raw)
					@properties[id] = property
					if id == 1 && type == VT_I2 && Integer === value && value < 0
						property.value = value + 65536
					end
				end
				@codepage = @properties[1] && @properties[1].value || DEFAULT_CODEPAGE
				load_dictionary if @properties[0]
			end

			def read_record property_offset, entries
				next_offset = entries.map { |_, offset| offset }.select { |offset| offset > property_offset }.min
				length = next_offset || @byte_size
				io.seek offset + property_offset
				io.read(length - property_offset)
			end

			def known_type? type, raw=nil
				element = type & VT_TYPEMASK
				if type & VT_VECTOR == 0
					return !!(FIXED_TYPES[type] || LENGTH_TYPES[type] || type == VT_CF)
				end
				if element != VT_VARIANT
					return !!(FIXED_TYPES[element] || LENGTH_TYPES[element])
				end
				return false unless raw
				count = raw[4, 4].unpack('V').first
				variant_elements_supported? count, raw[8, raw.bytesize - 8] || ''.dup
			end

			def variant_elements_supported? count, data
				pos = 0
				count.times do
					return false if data.bytesize < pos + 4
					type = data[pos, 2].unpack('v').first
					if FIXED_TYPES[type]
						_, size = FIXED_TYPES[type]
						width = [4, size].max
						return false if data.bytesize < pos + 4 + width
						pos += align4(4 + width)
					elsif LENGTH_TYPES[type]
						return false if data.bytesize < pos + 8
						length = data[pos + 4, 4].unpack('V').first
						return false if data.bytesize < pos + 8 + length
						pos += align4(8 + length)
					else
						return false
					end
			end
				data.bytesize == pos
			end

			def decode_value type, raw
				return raw unless raw
				if type & VT_VECTOR != 0
					if known_type?(type, raw)
						count = raw[4, 4].unpack('V').first
						return decode_vector(type & VT_TYPEMASK, count, raw[8, raw.bytesize - 8] || ''.dup)
					end
					return raw
				end
				return decode_scalar(type, raw[4, raw.bytesize - 4] || ''.dup) if FIXED_TYPES[type]
				return decode_clipboard(raw[4, raw.bytesize - 4] || ''.dup) if type == VT_CF
				if LENGTH_TYPES[type]
					length = raw[4, 4].unpack('V').first
					return decode_length_value(type, raw[8, length] || ''.dup)
				end
				raw
			end

			def decode_scalar type, data
				template, size = FIXED_TYPES[type]
				value = data[0, size].unpack(template).first
				case type
				when VT_BOOL then value != 0
				when VT_FILETIME then FileTime.load(value)
				when VT_CLSID then Clsid.load(value)
				else value
				end
			end

			def decode_length_value type, data
				case type
				when VT_LPSTR then decode_codepage_string(data)
				when VT_LPWSTR then Lpwstr.load(data)
				else Data.load(data)
				end
			end

			def decode_clipboard data
				Data.load data
			end

			def decode_vector element, count, data
				if element == VT_VARIANT
					values = []
					pos = 0
					count.times do
						type = data[pos, 2].unpack('v').first
						value, size = decode_variant_element(type, data[pos, data.bytesize - pos])
						values << value
						pos += size
					end
					values
				elsif FIXED_TYPES[element]
					decode_fixed_vector(element, count, data)
				else
					values = []
					pos = 0
					count.times do
						length = data[pos, 4].unpack('V').first
						values << decode_length_value(element, data[pos + 4, length])
						pos += align4(length + 4)
					end
					values
				end
			end

			def decode_fixed_vector type, count, data
				template, size = FIXED_TYPES[type]
				values = data[0, size * count].unpack(template + count.to_s)
				if type == VT_BOOL
					values.map! { |value| value != 0 }
				elsif type == VT_FILETIME
					values.map! { |value| FileTime.load(value) }
				elsif type == VT_CLSID
					values.map! { |value| Clsid.load(value) }
				end
				values
			end

			def decode_variant_element type, data
				if FIXED_TYPES[type]
					template, size = FIXED_TYPES[type]
					width = [4, size].max
					value = data[4, size].unpack(template).first
					value = value != 0 if type == VT_BOOL
					[value, align4(4 + width)]
				else
					length = data[4, 4].unpack('V').first
					[decode_length_value(type, data[8, length]), align4(8 + length)]
				end
			end

			def dump_property property
				return pad4(property.value.to_s) if property.id == 0
				return property.raw if property.raw?
				type = property.type
				if type & VT_VECTOR != 0
					body = [property.value.length].pack('V') + dump_vector(type & VT_TYPEMASK, property.value)
				elsif FIXED_TYPES[type]
					body = dump_scalar(type, property.value)
				elsif LENGTH_TYPES[type]
					payload = dump_length_value(type, property.value)
					body = pad4([payload.bytesize].pack('V') + payload)
				elsif type == VT_CF
					body = property.value.to_s
				else
					raise ArgumentError, 'unknown ole type - 0x%04x' % type
				end
				[type].pack('V') + pad4(body)
			end

			def dump_scalar type, value
				case type
				when VT_BOOL then [value ? 1 : 0].pack('V')
				when VT_FILETIME then FileTime.dump(value)
				when VT_CLSID then Clsid.dump(value)
				else
					template, _ = FIXED_TYPES[type]
					[value].pack(template)
				end
			end

			def dump_length_value type, value
				case type
				when VT_LPSTR then encode_codepage_string(value)
				when VT_LPWSTR then Lpwstr.dump(value) + 0.chr * 2
				else Variant.dump(type, value).to_s
				end
			end

			def dump_vector element, values
				if element == VT_VARIANT
					values.map { |value| dump_variant_element(infer_type(value), value) }.join
				elsif FIXED_TYPES[element]
					values.map { |value| dump_scalar(element, value) }.join
				else
					values.map do |value|
						payload = dump_length_value(element, value)
						pad4([payload.bytesize].pack('V') + payload)
					end.join
				end
			end

			def dump_variant_element type, value
				if FIXED_TYPES[type]
					_, size = FIXED_TYPES[type]
					width = [4, size].max
					scalar = dump_scalar(type, value)
					scalar = 0.chr * (4 - width) + scalar
					scalar << 0.chr * (width - size)
					pad4([type].pack('v') + 0.chr * 2 + scalar)
				else
					payload = dump_length_value(type, value)
					pad4([type].pack('v') + 0.chr * 2 + [payload.bytesize].pack('V') + payload)
				end
			end

			def dump_dictionary
				payload = [@names.length].pack('V')
				@names.keys.sort.each do |id|
					name = encode_codepage_string(@names[id])
					payload << [id, name.bytesize].pack('V2') + name
				end
				pad4 payload
			end

			def load_dictionary
				payload = @properties[0].value.to_s
				count = payload[0, 4].unpack('V').first
				pos = 4
				count.times do
					id, length = payload[pos, 8].unpack('V2')
					@names[id] = decode_dictionary_name(payload[pos + 8, length].to_s)
					pos += 8 + length
				end
			end

			def decode_codepage_string data
				value = data.chomp(0.chr)
				value.force_encoding(codepage_encoding).encode(Encoding::UTF_8)
			rescue EncodingError
				value
			end

			def encode_codepage_string value
				data = value.to_s.encode(codepage_encoding)
				data.force_encoding(Encoding::ASCII_8BIT) + 0.chr
			end

			def decode_dictionary_name data
				value = data.chomp(0.chr)
				value.force_encoding(codepage_encoding).encode(Encoding::UTF_8)
			rescue EncodingError
				value
			end

			def codepage_encoding
				CODEPAGE_ENCODINGS[codepage] || Encoding.find("CP#{codepage}")
			end

			def align4 length
				(length + 3) & ~3
			end

			def pad4 data
				data + 0.chr * (align4(data.bytesize) - data.bytesize)
			end
		end

		def initialize_new guids
			@io = nil
			@signature = 0xfffe
			@unknown = 0
			@os_id = DEFAULT_OS
			@guid = Clsid.new(0.chr * Clsid::SIZE)
			@sections = guids.map { |guid| Section.create self, guid }
		end

		def load_header str
			@signature, @unknown, @os_id, @guid, @num_sections = str.unpack HEADER_PACK
			@guid = Clsid.load @guid
			@os = OS_MAP[@os_id] || Log.warn("unknown operating system id #{@os_id}")
		end

		def load_section_list str
			@sections = str.to_enum(:each_chunk, Section::SIZE).map { |s| Section.new s, self }
		end
		end
	end
end
