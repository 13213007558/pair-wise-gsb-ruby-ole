# encoding: ASCII-8BIT

require 'date'

module Ole
	class Msg
		class Reader
			SUBSTG_RX = /\A__substg1\.0_([0-9a-fA-F]{8})(?:[_-]([0-9a-fA-F]{8}))?\z/

			def self.read(dir, header_size, path, mapping)
				new(dir, header_size, path, mapping).properties
			end

			def initialize(dir, header_size, path, mapping)
				@dir = dir
				@header_size = header_size
				@path = path
				@mapping = mapping
				index_children
				read_stream
				parse_entries
			end

			attr_reader :properties

			private

			def index_children
				@streams = Hash.new { |hash, tag| hash[tag] = [] }
				@storages = Hash.new { |hash, tag| hash[tag] = [] }
				@dir.children.each do |child|
					match = SUBSTG_RX.match(child.name)
					next unless match
					tag = match[1].to_i(16)
					index = match[2] ? match[2].to_i(16) : nil
					if child.file?
						@streams[tag] << [index, child]
					else
						@storages[tag] << [index, child]
					end
				end
				@streams.each_value { |children| children.sort_by! { |index, _| index || -1 } }
				@storages.each_value { |children| children.sort_by! { |index, _| index || -1 } }
			end

			def read_stream
				stream = @dir['__properties_version1.0']
				corrupt! unless stream && stream.file?
				@data = stream.read
				valid_size = @data.size >= @header_size &&
					(@data.size - @header_size) % 16 == 0
				corrupt! unless valid_size
			end

			def parse_entries
				@properties = Msg::Properties.new({})
				((@data.size - @header_size) / 16).times do |index|
					offset = @header_size + index * 16
					tag, flags = @data[offset, 8].unpack('V2')
					fixed = @data[offset + 8, 8]
					next if @properties.all.key?(tag)
					property = build_property(tag, flags, fixed)
					@properties.all[tag] = property
				end
			end

			def build_property(tag, flags, fixed)
				id = tag >> 16
				type = tag & 0xffff
				name = id >= 0x8000 && @mapping ? @mapping[id] : nil
				Property.new(tag, id, type, flags, name, read_value(tag, type, fixed))
			end

			def read_value(tag, type, fixed)
				if type == 0x000d
					storage = @storages[tag].first
					return storage && storage[1]
				end

				if (type & 0x1000) != 0
					return read_multi_value(tag, type & 0x0fff)
				end

				data = scalar_stream(tag)
				case type
				when 0x0000, 0x0001 then nil
				when 0x0002 then fixed.unpack1('s<')
				when 0x0003 then fixed.unpack1('l<')
				when 0x0004 then fixed.unpack1('e')
				when 0x0005 then fixed.unpack1('E')
				when 0x0006 then fixed.unpack1('q<')
				when 0x0007 then Types::FileTime::EPOCH - 1 + fixed.unpack1('E')
				when 0x000a then fixed.unpack1('V')
				when 0x000b then fixed.unpack1('v') != 0
				when 0x0010 then fixed.unpack1('c')
				when 0x0011 then fixed.unpack1('C')
				when 0x0012 then fixed.unpack1('v')
				when 0x0013 then fixed.unpack1('V')
				when 0x0014 then fixed.unpack1('q<')
				when 0x0015 then fixed.unpack1('Q<')
				when 0x0016 then fixed.unpack1('l<')
				when 0x0017 then fixed.unpack1('V')
				when 0x0040 then Types::Variant.load(Types::VT_FILETIME, fixed)
				when 0x001e then decode_ansi(data)
				when 0x001f then decode_unicode(data)
				when 0x0048 then data && Types::Clsid.load(data)
				when 0x0102, 0x0041, 0x0046 then binary(data)
				else data ? binary(data) : fixed
				end
			rescue FormatError
				raise
			rescue StandardError
				corrupt! "corrupt property stream #{stream_path}"
			end

			def scalar_stream(tag)
				entry = @streams[tag].find { |index, _| index.nil? }
				entry && entry[1].read
			end

			def read_multi_value(tag, type)
				entries = @streams[tag]
				return nil if entries.empty?
				base = entries.find { |index, _| index.nil? }
				parts = entries.select { |index, _| !index.nil? }.sort_by(&:first).map { |_, stream| stream.read }

				if parts.empty?
					read_compact_multi_value(base[1].read, type)
				else
					lengths = base ? base[1].read : ''.b
					read_indexed_multi_value(lengths, parts, type)
				end
			end

			def read_compact_multi_value(data, type)
				corrupt! if data.size < 4
				count = data.unpack1('V')
				if variable_type?(type)
					offset = 4
					Array.new(count) do
						size = data[offset, 4].unpack1('V')
						offset += 4
						value = decode_variable(type, data[offset, size])
						offset += size
						offset = (offset + 3) & ~3
						value
					end
				else
					size = fixed_size(type)
					Array.new(count) { |index| decode_fixed(type, data[4 + index * size, size]) }
				end
			end

			def read_indexed_multi_value(lengths, parts, type)
				if type == 0x0102
					Array.new(parts.length) do |index|
						expected = index * 8 < lengths.size ? lengths[index * 8, 4].unpack1('V') : nil
						_ = expected
						decode_variable(type, parts[index])
					end
				else
					Array.new(parts.length) { |index| decode_variable(type, parts[index]) }
				end
			end

			def variable_type?(type)
				[0x001e, 0x001f, 0x0048, 0x0102, 0x0041, 0x0046].include?(type)
			end

			def decode_variable(type, data)
				case type
				when 0x001e then decode_ansi(data)
				when 0x001f then decode_unicode(data)
				when 0x0048 then Types::Clsid.load(data)
				else binary(data)
				end
			end

			def fixed_size(type)
				case type
				when 0x0002 then 2
				when 0x0004 then 4
				when 0x0003, 0x000a, 0x0013, 0x0016, 0x0017 then 4
				when 0x0005, 0x0006, 0x0007, 0x0014, 0x0015, 0x0040 then 8
				when 0x000b, 0x0010, 0x0011, 0x0012 then 2
				when 0x0048 then 16
				else 8
				end
			end

			def decode_fixed(type, data)
				dummy = StringIO.new
				dummy.close
				read_value(type, type, data)
			end

			def binary(data)
				data && data.dup.force_encoding(Encoding::ASCII_8BIT)
			end

			def decode_ansi(data)
				return nil if data.nil?
				bytes = data.dup.force_encoding(Encoding::ASCII_8BIT).sub(/\x00+\z/, '')
				bytes.force_encoding('Windows-1252').encode(Encoding::UTF_8,
					:invalid => :replace, :undef => :replace)
			end

			def decode_unicode(data)
				return nil if data.nil?
				bytes = data.dup.force_encoding(Encoding::ASCII_8BIT)
				bytes = bytes.byteslice(0, bytes.size - 1) if bytes.size.odd?
				bytes = bytes.sub(/(?:\x00\x00)+\z/, '')
				bytes.encode(Encoding::UTF_8, Encoding::UTF_16LE,
					:invalid => :replace, :undef => :replace)
			end

			def stream_path
				@path.empty? ? '__properties_version1.0' : "#{@path}/__properties_version1.0"
			end

			def corrupt!(message="corrupt property stream #{stream_path}")
				raise FormatError, message
			end
		end
	end
end
