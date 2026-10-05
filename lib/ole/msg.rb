# encoding: ASCII-8BIT

#
# = Ole::Msg
#
# Read-only support for Outlook MSG files ([MS-OXMSG]); see Ole::Msg::Message
# for the entry point. This file simply pulls in the whole MSG layer:
#
#   require 'ole/msg'
#
#   Ole::Msg.open 'message.msg' do |msg|
#     puts msg.subject
#     msg.recipients.each { |r| puts "#{r.name} <#{r.email}>" }
#     msg.attachments.each { |a| puts a.filename }
#   end
#

require 'ole/msg/base'
require 'ole/msg/nameid_map'
require 'ole/msg/properties'
require 'ole/msg/message'
