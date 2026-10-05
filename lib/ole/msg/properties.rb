# encoding: ASCII-8BIT

require 'ole/msg/base'

module Ole # :nodoc:
	module Msg
		#
		# The set of MAPI properties attached to a message, recipient or
		# attachment storage.
		#
		# Fixed (predefined) properties and named properties are kept separate:
		#
		# * +fixed+ is a hash of 16 bit property id => decoded value.
		# * +named+ is a list of NamedProperty objects, each retaining the
		#   resolved GUID and string name or LID from the nameid mapping, rather
		#   than the transient 0x8000+ property number used within the file.
		#
		class Properties
			include Msg::PropertyType

			# [MS-OXMSG] 2.4.1: message object property stream header carries the
			# recipient/attachment bookkeeping; 2.4.2: recipient and attachment
			# property streams have a smaller reserved header.
			ROOT_HEADER_SIZE     = 32
			EMBEDDED_HEADER_SIZE = 16

			attr_reader :fixed, :named, :codepage
			attr_reader :next_recipient_id, :next_attachment_id
			attr_reader :recipient_count, :attachment_count

			def self.load message, dirent, root=false
				new.send :load, message, dirent, root
			end

			# fixed property lookup by 16 bit property id, eg properties[0x0037]
			def [] id
				@fixed[id]
			end

			# named property values keyed by [guid_string, name_or_lid]
			def named_map
				@named.inject({}) { |hash, prop| hash[prop.key] = prop.value; hash }
			end

			# look up a named property value by property set GUID (string or
			# Ole::Types::Clsid) and string name or numeric LID.
			def named_lookup guid, name_or_lid
				fmt = guid.respond_to?(:format) ? guid.format : guid.to_s.downcase.gsub(/[{}]/, '')
				found = @named.find do |prop|
					prop.guid && prop.guid.format == fmt &&
						(prop.kind == :string ? prop.string_name : prop.lid) == name_or_lid
				end
				found && found.value
			end

			private

			def load message, dirent, root
				@message, @dirent = message, dirent
				path = Msg.path_of dirent
				stream = dirent / PROPERTIES_STREAM or
					raise FormatError, "missing #{PROPERTIES_STREAM} stream in #{path}"
				data = stream.read
				header_size = root ? ROOT_HEADER_SIZE : EMBEDDED_HEADER_SIZE
				if data.bytesize < header_size
					raise FormatError, "corrupt property stream in #{path}: truncated header"
				end
				if root
					@next_recipient_id, @next_attachment_id,
						@recipient_count, @attachment_count = data.unpack '@8V4'
				end
				@fixed, @named = {}, []
				entries = parse_entries data, header_size, path
				@codepage = find_codepage entries, root
				entries.each do |id, type, raw|
					@fixed[id] = Msg.decode_value type, raw, @codepage
				end
				load_substg_streams
				self
			end

			def parse_entries data, offset, path
				entries = []
				while offset < data.bytesize
					if offset + 8 > data.bytesize
						raise FormatError, "corrupt property stream in #{path}: truncated property entry at offset #{offset}"
					end
					tag, _flags = data.unpack "@#{offset}V2"
					offset += 8
					id, type = tag >> 16, tag & 0xffff
					if Msg.variable_length? type
						if offset + 4 > data.bytesize
							raise FormatError, "corrupt property stream in #{path}: truncated property entry at offset #{offset}"
						end
						size = data.unpack("@#{offset}V").first
						offset += 4
						if offset + size > data.bytesize
							raise FormatError, "corrupt property stream in #{path}: truncated data for property 0x#{'%04x' % id}"
						end
						raw = data[offset, size]
						offset += (size + 7) & ~7
					else
						if offset + 8 > data.bytesize
							raise FormatError, "corrupt property stream in #{path}: truncated property entry at offset #{offset}"
						end
						raw = data[offset, 8]
						offset += 8
					end
					# named and multi-valued properties are stored in dedicated
					# __substg1.0_* streams, not in the property stream.
					entries << [id, type, raw] if id < 0x8000 && type & MV_FLAG == 0
				end
				entries
			end

			def find_codepage entries, root
				if root
					entry = entries.find { |id, type, _| id == 0x3ffd && type == PT_LONG }
					entry ? Msg.decode_scalar(PT_LONG, entry[2], nil) : DEFAULT_CODEPAGE
				else
					@message.codepage
				end
			end

			# named and multi-valued properties live in __substg1.0_NNNNTTTT
			# streams; multi-valued variable length types additionally split
			# their elements into -NNNNNNNN sub streams.
			def load_substg_streams
				groups = {}
				@dirent.children.each do |child|
					next unless child.file?
					next unless child.name =~ /\A__substg1\.0_([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})(?:-([0-9A-Fa-f]{8}))?\z/
					(groups[[$1.hex, $2.hex]] ||= {})[$3 && $3.hex] = child
				end
				groups.each do |(number, type), variants|
					base = type & ~MV_FLAG
					subs = variants.reject { |index, _| index.nil? }
					value = if type & MV_FLAG != 0 && !subs.empty?
						subs.keys.sort.map { |index| Msg.decode_scalar base, subs[index].read, @codepage }
					elsif type & MV_FLAG != 0
						Msg.decode_value type, variants[nil].read, @codepage
					else
						Msg.decode_scalar base, variants[nil].read, @codepage
					end
					if number >= 0x8000
						@named << NamedProperty.new(number, @message.nameid_map.resolve(number), type, value)
					else
						@fixed[number] = value
					end
				end
			end
		end
	end
end
