# encoding: ASCII-8BIT

require 'ole/msg/base'

module Ole # :nodoc:
	module Msg
		#
		# An MSG message. This is the entry point of the MSG reading layer,
		# and is also used to represent embedded-message attachments.
		#
		class Message
			attr_reader :ole, :root, :properties, :nameid_map

			def self.open arg
				own, ole = Ole::Storage === arg ? [false, arg] : [true, Ole::Storage.open(arg)]
				msg = new ole
				if block_given?
					begin
						yield msg
					ensure
						msg.close if own
					end
				else
					msg
				end
			end

			# +ole+ is an open Ole::Storage; +root+ is the Dirent of the message
			# storage (the storage root for a top level message, or the embedded
			# message substorage of an attachment).
			def initialize ole, root=nil
				@ole = ole
				@root = root || ole.root
				@nameid_map = NameIDMap.load @root
				@properties = Properties.load self, @root, true
			end

			def codepage
				@properties ? @properties.codepage : DEFAULT_CODEPAGE
			end

			def recipients
				@recipients ||= child_storages(/\A__recip_version1\.0_#[0-9a-f]{8}\z/i).map do |dirent|
					Recipient.new self, dirent
				end
			end

			def attachments
				@attachments ||= child_storages(/\A__attach_version1\.0_#[0-9a-f]{8}\z/i).map do |dirent|
					Attachment.new self, dirent
				end
			end

			def subject
				properties[0x0037]
			end

			def body
				properties[0x1000]
			end

			def close
				@ole.close
			end

			private

			def child_storages pattern
				@root.children.select { |child| child.dir? && child.name =~ pattern }.
					sort_by { |child| child.name[/[0-9a-f]{8}/i].hex }
			end
		end

		#
		# A message recipient (a +__recip_version1.0_#NNNNNNNN+ storage).
		#
		class Recipient
			attr_reader :message, :dirent, :properties

			def initialize message, dirent
				@message, @dirent = message, dirent
				@properties = Properties.load message, dirent
			end

			def name
				properties[0x3001]
			end

			def email
				properties[0x39fe] || properties[0x3003]
			end

			def address_type
				properties[0x3002]
			end

			# PidTagRecipientType: 1 => to, 2 => cc, 3 => bcc
			def type
				properties[0x0c15]
			end
		end

		#
		# A message attachment (an +__attach_version1.0_#NNNNNNNN+ storage).
		#
		class Attachment
			attr_reader :message, :dirent, :properties

			def initialize message, dirent
				@message, @dirent = message, dirent
				@properties = Properties.load message, dirent
			end

			def filename
				properties[0x3707] || properties[0x3704]
			end

			def mime_type
				properties[0x370e]
			end

			def attach_method
				properties[0x3705]
			end

			def size
				properties[0x0e20]
			end

			# the raw attachment bytes for regular (ATTACH_BY_VALUE) attachments.
			# the content is returned unparsed, as a binary string.
			def data
				properties[0x3701] unless embedded?
			end

			# is this an embedded-message attachment?
			def embedded?
				attach_method == ATTACH_EMBEDDED_MSG && !!(@dirent / EMBEDDED_MSG_STORAGE)
			end

			# for embedded-message attachments, the nested message
			def embedded_msg
				return @embedded_msg if defined? @embedded_msg
				@embedded_msg = embedded? ? Message.new(@message.ole, @dirent / EMBEDDED_MSG_STORAGE) : nil
			end
		end
	end
end
