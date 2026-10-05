# encoding: ASCII-8BIT

require 'date'
require 'ole/storage'

module Ole
	class Msg
		class FormatError < Storage::FormatError; end

		Property = Struct.new(:tag, :id, :type, :flags, :name, :value)

		class NamedProperty
			Key = Struct.new(:guid, :name, :lid) do
				def to_s
					name || "0x%04x" % lid
				end
			end

			attr_reader :mapping

			def self.load(storage, root)
				new(root, storage, '', true)
			end

			private_class_method :new

			def self.read(storage, root=nil, path='', embedded=false, parent_mapping=nil)
				new(root || storage.root, storage, path, embedded, parent_mapping)
			end

			private_class_method :read

			def self.open(arg, mode=nil)
				Storage.open(arg, mode) do |storage|
					msg = load(storage, storage.root)
					if block_given?
						yield msg
					else
						msg
					end
				end
			rescue FormatError
				raise
			end

			private

			def initialize(root, storage, path, embedded, parent_mapping=nil)
				@root = root
				@storage = storage
				@path = path
				@embedded = embedded
				@mapping = NameIdMapping.load(root, path, parent_mapping)
				@properties = read_properties(root, embedded ? 24 : 32, @mapping)
				@recipients = collect('__recip_version1.0_#') do |dir, name|
					Recipient.new(self, dir, join_path(name))
				end
				@attachments = collect('__attach_version1.0_#') do |dir, name|
					Attachment.new(self, dir, join_path(name))
				end
			end

			public

			attr_reader :properties, :recipients, :attachments
			alias props :properties

			def [](tag)
				properties[tag]
			end

			def value(tag)
				properties.value(tag)
			end

			def subject
				value_by_id(0x0037)
			end

			def body
				value_by_id(0x1000)
			end

			def message_class
				value_by_id(0x001a)
			end

			private

			def value_by_id(id)
				property = properties.all.values.find { |entry| entry.id == id }
				property && property.value
			end

			def collect(prefix)
				@root.children.select { |child| child.dir? && child.name.start_with?(prefix) }.
					sort_by { |child| suffix_number(child.name) }.
					map { |child| yield(child, child.name) }
			end

			def suffix_number(name)
				name[/([0-9a-fA-F]{8})\z/, 1]&.to_i(16) || 0
			end

			def read_properties(dir, header_size, mapping)
				Reader.read(dir, header_size, @path, mapping)
			end

				def join_path(name)
					@path.empty? ? name : "#{@path}/#{name}"
			end

			end

			class Properties
				include Enumerable

				def initialize(properties)
					@by_tag = properties
				end

				attr_reader :all

				def each(&block)
					@by_tag.each_value(&block)
				end

				def [](tag)
					@by_tag[normalize_tag(tag)]
				end

				def value(tag)
					property = self[tag]
					property && property.value
				end

				def fixed
					@by_tag.reject { |tag, _| (tag >> 16) >= 0x8000 }
				end

				def named
					@by_tag.select { |tag, _| (tag >> 16) >= 0x8000 }
				end

				def to_h
					@by_tag
				end

				private

				def normalize_tag(tag)
					return tag if Integer === tag
					tag.to_s.sub(/\A0x/i, '').to_i(16)
				end

				def initialize_copy(other)
					super
					@by_tag = @by_tag.dup
				end
			end

		class Recipient
			def initialize(message, dir, path)
				@message = message
				@dir = dir
				@path = path
				@properties = message.send(:read_properties, dir, 8, message.mapping)
			end

			attr_reader :properties, :path
			alias props :properties

			def type
				properties.value(0x0c150003)
			end

			def display_name
				string_value(0x3001)
			end

			def address_type
				string_value(0x3002)
			end

			def email_address
				string_value(0x39fe) || string_value(0x3003)
			end

			private

			def string_value(id)
				[0x001f, 0x001e].each do |type|
					value = @properties.value((id << 16) | type)
					return value unless value.nil?
				end
				nil
			end
		end

		class Attachment
			OBJECT_TAG = 0x3701000d
			DATA_TAG = 0x37010102

			def initialize(message, dir, path)
				@message = message
				@dir = dir
				@path = path
				@properties = message.send(:read_properties, dir, 8, message.mapping)
			end

			attr_reader :properties, :path
			alias props :properties

			def filename
				string_value(0x3707) || string_value(0x3704) || string_value(0x370d)
			end

			def long_filename
				string_value(0x3707)
			end

			def short_filename
				string_value(0x3704)
			end

			def extension
				string_value(0x3703)
			end

			def method_type
				properties.value(0x37050003)
			end

			def embedded_message?
				!!embedded_dir
			end

			def data
				if (dir = embedded_dir)
					Msg.send(:read, @message.instance_variable_get(:@storage), dir, "#{@path}/__substg1.0_3701000D", true, @message.mapping)
				else
					stream = @dir['__substg1.0_37010102']
					stream && stream.read
				end
			end

			private

			def embedded_dir
				dir = @dir['__substg1.0_3701000D']
				dir if dir && dir.dir? && dir['__properties_version1.0']
			end

			def string_value(id)
				[0x001f, 0x001e].each do |type|
					value = @properties.value((id << 16) | type)
					return value unless value.nil?
				end
				nil
			end
		end
	end
		end


require_relative 'msg/name_id_mapping'
require_relative 'msg/reader'
