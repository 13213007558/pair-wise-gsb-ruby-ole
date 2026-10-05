#! /usr/bin/ruby

$: << File.dirname(__FILE__) + '/../lib'

require 'stringio'
require 'test/unit'
require 'ole/types'

class TestPropertySet < Test::Unit::TestCase
	include Ole::Types

	def setup
		@io = open File.dirname(__FILE__) + '/test_SummaryInformation', 'rb'
	end

	def teardown
		@io.close
	end

	def test_property_set
		propset = PropertySet.new @io
		assert_equal :mac, propset.os
		assert_equal 1, propset.sections.length
		section = propset.sections.first
		assert_equal 14, section.length
		assert_equal 'f29f85e0-4ff9-1068-ab91-08002b27b3d9', section.guid.format
		assert_equal PropertySet::FMTID_SummaryInformation, section.guid
		assert_equal 'Charles Lowe', section.to_a.assoc(4).last
		assert_equal 'Charles Lowe', propset.doc_author
		assert_equal 'Charles Lowe', propset.to_h[:doc_author]
		assert_equal 65001, section.codepage
		assert_kind_of FileTime, section[12]

		assert_raise(NoMethodError) { propset.non_existent_key }
		assert_raise(NoMethodError) { propset.non_existent_key = 'Value' }
		assert_equal nil, propset.security
	end

	def test_add_replace_delete_and_save
		io = StringIO.new File.binread(File.dirname(__FILE__) + '/test_SummaryInformation')
		propset = PropertySet.new io
		propset.doc_author = 'New Author'
		propset.doc_title = 'Title'
		propset.doc_page_count = 7
		size = propset.save
		assert_equal size, io.size

		reloaded = PropertySet.new(StringIO.new(io.string))
		assert_equal 'New Author', reloaded.doc_author
		assert_equal 'Title', reloaded.doc_title
		assert_equal 7, reloaded.doc_page_count

		reloaded.doc_author = nil
		reloaded.save
		assert_nil PropertySet.new(StringIO.new(io.string)).doc_author
	end

	def test_two_sections_custom_names_types_and_relayout
		propset = PropertySet.create(
			PropertySet::FMTID_DocSummaryInfo,
			PropertySet::FMTID_UserDefinedProperties
		)
		doc, user = propset.sections
		propset.doc_company = 'Acme'
		doc.set 12, [1, 'Heading', 2, 'Subheading'], VT_VECTOR | VT_VARIANT
		doc.set 13, ['First Part', 'Second Part']
		user.codepage = 65001
		user['Project Name'] = 'Initial'
		user['Count'] = 42
		user['When'] = FileTime.new(2020, 1, 2, 3, 4, 5)
		user['Flags'] = [1, 2, 3]
		user.delete 'Count'
		short = propset.to_s

		user['Project Name'] = 'A much longer project name'
		long = propset.to_s
		assert long.bytesize > short.bytesize

		reloaded = PropertySet.new(StringIO.new(long))
		doc2, user2 = reloaded.sections
		assert_equal 'Acme', reloaded.doc_company
		assert_equal [1, 'Heading', 2, 'Subheading'], doc2[12]
		assert_equal ['First Part', 'Second Part'], doc2[13]
		assert_equal 'A much longer project name', user2['Project Name']
		assert_nil user2['Count']
		assert_equal [1, 2, 3], user2['Flags']
		assert_equal '2020-01-02T03:04:05+00:00', user2['When'].to_s
		project_id, _ = user2.properties.detect { |_, property| property.value == 'A much longer project name' }
		assert project_id
		assert_equal 'A much longer project name', user2[project_id]
		assert_equal 'Project Name', user2.name_for(project_id)
		assert_equal 2, reloaded.sections.length
	end

	def test_unknown_type_payload_is_preserved
		io = StringIO.new File.binread(File.dirname(__FILE__) + '/test_SummaryInformation')
		propset = PropertySet.new(io)
		thumbnail = propset.sections.first.properties[17]
		assert_equal VT_CF, thumbnail.type
		assert_kind_of Data, thumbnail.value
		original = thumbnail.raw
		reloaded = PropertySet.new(StringIO.new(propset.to_s))
		assert_equal original, reloaded.sections.first.properties[17].raw

		bytes = File.binread(File.dirname(__FILE__) + '/test_SummaryInformation')
		entry_offset = propset.sections.first.offset + 8 + 3 * 8
		property_offset = propset.sections.first.offset + bytes[entry_offset + 4, 4].unpack('V').first
		bytes[property_offset, 4] = [0x1234].pack('V')
		preserved = PropertySet.new(StringIO.new(bytes))
		unknown = preserved.sections.first.properties[10]
		assert_equal 0x1234, unknown.type
		assert_equal unknown.raw, unknown.value
		roundtrip = PropertySet.new(StringIO.new(preserved.to_s))
		assert_equal unknown.raw, roundtrip.sections.first.properties[10].raw
	end
end
