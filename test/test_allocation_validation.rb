#! /usr/bin/ruby
# coding: utf-8

$: << File.dirname(__FILE__) + '/../lib'

require 'test/unit'
require 'ole/storage'
require 'stringio'

class TestAllocationValidation < Test::Unit::TestCase
	EOC = Ole::Storage::AllocationTable::EOC
	FREE = Ole::Storage::AllocationTable::AVAIL
	FAT_SECTOR = Ole::Storage::AllocationTable::BAT
	DIFAT_SECTOR = Ole::Storage::AllocationTable::META_BAT
	EOT = Ole::Storage::Dirent::EOT

	def test_existing_512_byte_files
		%w[test_word_6.doc oleWithDirs.ole test.doc].each do |name|
			report = Ole::Storage.validate_allocation("#{File.dirname(__FILE__)}/#{name}")
			assert report.valid?, report.issues.map(&:message).join('; ')
			assert_equal 512, report.sector_size
			assert_equal 64, report.mini_sector_size
		end
	end

	def test_4096_byte_sectors_and_mini_mapping
		report = validate_without_loading(build_4096)
		assert report.valid?, report.issues.map(&:message).join('; ')
		assert_equal 4096, report.sector_size
		assert_equal 10, report.owners.length
		mini = report.mini_owners[0]
		assert_equal 'mini_stream', mini[:kind]
		assert_equal 'small', mini[:name]
		assert_equal 3, mini[:big_sector]
		assert_equal 0, mini[:offset]
	end

	def test_big_stream_cycle
		data = build_4096
		patch_u32 data, fat_offset(5, 4096), 4
		report = validate_without_loading(data)
		assert_issue report, :chain_cycle, :sectors => [4, 5, 4]
		assert_stream report, 'big'
	end

	def test_cross_linked_big_streams
		data = build_512_with_two_chains
		patch_u32 data, sector_offset(21) + 9 * 4, 11
		report = validate_without_loading(data)
		assert_issue report, :cross_linked_sector, :sectors => [11]
		assert report.issues.any? { |i| i.objects.any? { |o| o[:name] == 'a' } }
		assert report.issues.any? { |i| i.objects.any? { |o| o[:name] == 'b' } }
	end

	def test_declared_length_too_short_for_big_stream
		data = build_4096
		patch_u32 data, fat_offset(8, 4096), EOC
		report = validate_without_loading(data)
		assert_issue report, :declared_length_too_short
		assert_stream report, 'big'
	end

	def test_root_mini_stream_declared_length_too_short
		data = build_4096
		patch_u32 data, sector_offset(1, 4096) + 116, 99
		report = validate_without_loading(data)
		assert_issue report, :declared_length_too_short, :sectors => []
		assert report.issues.any? { |i| i.objects.any? { |o| o[:kind] == 'root_mini_stream' } }
	end

	def test_minifat_cycle
		data = build_4096
		offset = sector_offset(2, 4096) + 3 * 4
		patch_u32 data, offset, 2
		report = validate_without_loading(data)
		assert_issue report, :chain_cycle, :mini_sectors => [2, 3, 2]
		assert report.issues.any? { |i| i.mini_sectors.include?(2) && i.objects.any? { |o| o[:name] == 'small2' } }
	end

	def test_minifat_cross_link_and_mini_position
		data = build_4096
		offset = sector_offset(2, 4096) + 2 * 4
		patch_u32 data, offset, 1
		report = validate_without_loading(data)
		assert_issue report, :cross_linked_mini_sector, :mini_sectors => [1]
		assert report.issues.any? { |i| i.mini_sectors.include?(1) && i.objects.any? { |o| o[:name] == 'small' } }
		assert report.issues.any? { |i| i.mini_sectors.include?(1) && i.objects.any? { |o| o[:name] == 'small2' } }
	end

	def test_special_fat_marker_is_wrong_for_stream
		data = build_4096
		patch_u32 data, fat_offset(5, 4096), FAT_SECTOR
		report = validate_without_loading(data)
		assert report.issues.any? { |i| i.code == :invalid_special_marker && i.sectors.include?(5) }
	end

	def test_unreachable_allocated_sector
		data = build_4096
		patch_u32 data, fat_offset(10, 4096), 10
		report = validate_without_loading(data)
		assert_issue report, :unreachable_sector, :sectors => [10]
	end

	def test_out_of_bounds_pointer
		data = build_4096
		patch_u32 data, fat_offset(4, 4096), 99
		report = validate_without_loading(data)
		assert_issue report, :sector_out_of_bounds, :sectors => [4]
	end

	def test_difat_chain_cycle
		data = build_minimal_difat
		patch_u32 data, sector_offset(237) + 127 * 4, 237
		report = validate_without_loading(data)
		assert_issue report, :chain_cycle, :sectors => [237]
		assert report.issues.any? { |i| i.objects.any? { |o| o[:kind] == 'difat' } }
	end

	def test_minimal_difat_is_valid
		report = validate_without_loading(build_minimal_difat)
		assert report.valid?, report.issues.map(&:message).join('; ')
		assert_equal 2, report.chains.find { |chain| chain[:owner][:kind] == 'difat' }[:sectors].length
		assert_equal 237, report.chains.find { |chain| chain[:owner][:kind] == 'fat' }[:sectors].length
	end

	def test_difat_pointer_points_to_fat_sector
		data = build_minimal_difat
		patch_u32 data, sector_offset(237) + 127 * 4, 0
		report = validate_without_loading(data)
		assert_issue report, :cross_linked_sector, :sectors => [0]
	end

	def test_difat_fat_pointer_is_special
		data = build_minimal_difat
		# Global DIFAT slot 109 is the first FAT pointer stored in the first DIFAT sector.
		patch_u32 data, sector_offset(237), DIFAT_SECTOR
		report = validate_without_loading(data)
		assert_issue report, :invalid_fat_pointer
	end

	def test_read_only_io_position_is_restored
		io = StringIO.new(build_4096)
		io.pos = 123
		Ole::Storage.validate_allocation(io)
		assert_equal 123, io.pos
	end

	private

	def validate_without_loading data
		Ole::Storage.validate_allocation(StringIO.new(data))
	end

	def assert_issue report, code, options={}
		issue = report.issues.find { |item| item.code == code }
		assert issue, "expected #{code.inspect}, got #{report.issues.map(&:code).inspect}"
		options.each do |key, value|
			assert_equal value, issue.send(key), "issue #{code} #{key}"
		end
	end

	def assert_stream report, name
		assert report.chains.any? { |chain| chain[:owner][:name] == name }
	end

	def sector_offset sector, sector_size=512
		(sector + 1) * sector_size
	end

	def fat_offset sector, sector_size=512
		sector_offset(0, sector_size) + sector * 4
	end

	def patch_u32 data, offset, value
		data[offset, 4] = [value].pack('V')
	end

	def pack_header options
		values = [
			Ole::Storage::Header::MAGIC, 0.chr * 16, 59, options.fetch(:major_version, 3), "\xfe\xff",
			options.fetch(:sector_shift, 9), 6, 0.chr * 6, 0,
			options.fetch(:fat_count, 1), options.fetch(:directory_start, EOC), 0.chr * 4,
			4096, options.fetch(:minifat_start, EOC), options.fetch(:minifat_count, 0),
			options.fetch(:difat_start, EOC), options.fetch(:difat_count, 0)
		]
		header = values.pack(Ole::Storage::Header::PACK)
		header << 0.chr * (512 - header.length)
	end

	def pack_directory type, name, first_block, size, links=[EOT, EOT, EOT]
		utf16 = (name + "\0").encode('UTF-16LE')
		name_field = utf16.dup.force_encoding(Encoding::ASCII_8BIT)
		name_field << 0.chr * (64 - name_field.length)
		[ name_field, utf16.bytesize, type, 1, links[0], links[1], links[2],
		  0.chr * 16, 0, 0.chr * 8, 0.chr * 8, first_block, size & 0xffffffff,
		  [size >> 32].pack('V') ].pack(Ole::Storage::Dirent::PACK)
	end

	def build_4096
		sector_size = 4096
		sector_count = 12
		data = pack_header(
			:sector_shift => 12, :major_version => 4, :fat_count => 1,
			:directory_start => 1, :minifat_start => 2, :minifat_count => 1,
			:difat_start => EOC, :difat_count => 0
		)
		data << 0.chr * (sector_size * sector_count - 512)

		fat = [FAT_SECTOR, EOC, EOC, EOC, 5, 6, 7, 8, 9, EOC, FREE, EOC]
		data[sector_offset(0, sector_size), fat.length * 4] = fat.pack('V*')

		directory = ''.dup.force_encoding(Encoding::ASCII_8BIT)
		directory << pack_directory(5, 'Root Entry', 3, 4096, [EOT, EOT, 1])
		directory << pack_directory(2, 'small', 0, 100)
		directory << pack_directory(2, 'small2', 2, 100)
		directory << pack_directory(2, 'big', 4, 4096 * 6)
		data[sector_offset(1, sector_size), directory.length] = directory

		minifat = [1, EOC, 3, EOC, FREE] + [FREE] * (sector_size / 4 - 5)
		data[sector_offset(2, sector_size), minifat.length * 4] = minifat.pack('V*')

		data
	end

	def build_512_with_two_chains
		io = StringIO.new(''.dup)
		Ole::Storage.open(io, :update_timestamps => false) do |ole|
			ole.file.open('a', 'w') { |f| f.write 'A' * 5000 }
			ole.file.open('b', 'w') { |f| f.write 'B' * 5000 }
		end
		io.string
	end

	def build_minimal_difat
		sector_size = 512
		sector_count = 240
		fat_sector_count = 237
		difat_sector = 237
		difat_sector_2 = 238
		directory_sector = 239
		data = pack_header(
			:fat_count => fat_sector_count, :directory_start => directory_sector,
			:minifat_start => EOC, :minifat_count => 0,
			:difat_start => difat_sector, :difat_count => 2
		)
		data << 0.chr * (sector_size * sector_count)

		(0...109).each { |sector| patch_u32(data, Ole::Storage::Header::SIZE + sector * 4, sector) }
		difat_1 = (109...236).to_a + [difat_sector_2]
		difat_2 = [236] + [FREE] * 126 + [EOC]
		data[sector_offset(difat_sector), sector_size] = difat_1.pack('V*')
		data[sector_offset(difat_sector_2), sector_size] = difat_2.pack('V*')
		(0...fat_sector_count).each do |fat_sector|
			values = [FREE] * (sector_size / 4)
			values.each_index do |index|
				sector = fat_sector * (sector_size / 4) + index
				values[index] = FAT_SECTOR if sector < fat_sector_count
			values[index] = DIFAT_SECTOR if sector == difat_sector || sector == difat_sector_2
			values[index] = EOC if sector == directory_sector
			end
		data[sector_offset(fat_sector), sector_size] = values.pack('V*')
		end
		directory = pack_directory(5, 'Root Entry', EOC, 0, [EOT, EOT, EOT])
		data[sector_offset(directory_sector), directory.length] = directory
		data
	end
end
