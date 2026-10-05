#! /usr/bin/ruby

$: << File.dirname(__FILE__) + '/../lib'

require 'test/unit'
require 'ole/storage'
require 'stringio'
require 'tempfile'

#
# Tests for Ole::Storage.validate_allocation. Each corruption test builds a
# small controlled compound file, then breaks exactly one pointer in it and
# checks that the report names the streams and sectors involved. The files
# are never repaired.
#
class TestValidateAllocation < Test::Unit::TestCase
	AT = Ole::Storage::AllocationTable
	HEADER_PACK = Ole::Storage::Header::PACK
	HEADER_SIZE = Ole::Storage::Header::SIZE
	HEADER_KEYS = %w[
		magic clsid minor_ver major_ver byte_order b_shift s_shift
		reserved csectdir num_bat dirent_start transacting_signature threshold
		sbat_start num_sbat mbat_start num_mbat
	]

	def setup
		@tmp = Tempfile.new 'ole-validate'
		@path = @tmp.path
		@tmp.close
		make_test_file @path
	end

	def teardown
		@tmp.close!
	end

	# builds a small controlled compound file with two miniFAT streams and
	# two FAT streams
	def make_test_file path, sector_shift=9
		Ole::Storage.open path, 'w+' do |ole|
			if sector_shift != 9
				ole.header.b_shift = sector_shift
				ole.bbat.instance_variable_set :@block_size, 1 << sector_shift
			end
			ole.file.open('small1', 'w') { |f| f.write 'A' * 100 }
			ole.file.open('small2', 'w') { |f| f.write 'B' * 300 }
			ole.file.open('big1', 'w') { |f| f.write 'C' * 10_000 }
			ole.file.open('big2', 'w') { |f| f.write 'D' * 6_000 }
		end
	end

	# reads the raw header of the file at +path+
	def read_header path
		data = File.open(path, 'rb') { |f| f.read 512 }
		header = Hash[HEADER_KEYS.zip data[0, HEADER_SIZE].unpack(HEADER_PACK)]
		header['difat'] = data[HEADER_SIZE, 109 * 4].unpack 'V*'
		header
	end

	def sector_size path
		1 << read_header(path)['b_shift']
	end

	# file offset of FAT entry +index+
	def fat_entry_offset path, index
		header = read_header path
		ss = 1 << header['b_shift']
		fat_sectors = header['difat'].select { |e| e <= 0xfffffffa }[0, header['num_bat']]
		per_sector = ss / 4
		(fat_sectors[index / per_sector] + 1) * ss + (index % per_sector) * 4
	end

	# file offset of miniFAT entry +index+
	def minifat_entry_offset path, index
		Ole::Storage.open path, 'rb' do |ole|
			chain = ole.bbat.chain ole.header.sbat_start
			ss = ole.bbat.block_size
			per_sector = ss / 4
			return (chain[index / per_sector] + 1) * ss + (index % per_sector) * 4
		end
	end

	# file offset of the 128 byte directory entry named +name+
	def dirent_offset path, name
		Ole::Storage.open path, 'rb' do |ole|
			chain = ole.bbat.chain ole.header.dirent_start
			data = ole.bbat.read chain
			ss = ole.bbat.block_size
			data.to_enum(:each_chunk, 128).with_index do |chunk, i|
				name_len = chunk[64, 2].unpack('v').first
				entry_name = chunk[0, [name_len - 2, 0].max].
					force_encoding('utf-16le').encode('utf-8') rescue nil
				if entry_name == name
					pos = i * 128
					return (chain[pos / ss] + 1) * ss + (pos % ss)
				end
			end
			raise "dirent #{name.inspect} not found"
		end
	end

	def write_u32 path, offset, value
		File.open(path, 'r+b') { |f| f.seek offset; f.write [value].pack('V') }
	end

	def write_fat_entry path, index, value
		write_u32 path, fat_entry_offset(path, index), value
	end

	def write_minifat_entry path, index, value
		write_u32 path, minifat_entry_offset(path, index), value
	end

	# sector layout of the valid test file, using the library itself
	def layout path
		Ole::Storage.open path, 'rb' do |ole|
			l = {:chains => {}}
			%w[small1 small2 big1 big2].each do |name|
				dirent = ole.root / name
				bat = dirent.size >= ole.header.threshold ? ole.bbat : ole.sbat
				l[:chains][name] = bat.chain dirent.first_block
			end
			l[:mini_stream] = ole.bbat.chain ole.root.first_block
			l[:dir] = ole.bbat.chain ole.header.dirent_start
			l[:sbat] = ole.bbat.chain ole.header.sbat_start
			l[:fat] = (0...ole.bbat.length).select { |i| ole.bbat[i] == AT::BAT }
			l
		end
	end

	def test_valid_file
		report = Ole::Storage.validate_allocation @path
		assert report.ok?, report.to_s
		assert_equal 512, report.sector_size
		assert_equal 64, report.mini_sector_size

		# everything lives in the one ownership report
		l = layout @path
		l[:fat].each { |s| assert_equal ['FAT'], report.owners[s] }
		l[:dir].each { |s| assert_equal ['directory'], report.owners[s] }
		l[:sbat].each { |s| assert_equal ['miniFAT'], report.owners[s] }
		l[:mini_stream].each { |s| assert_equal ['mini-stream (Root Entry)'], report.owners[s] }
		%w[big1 big2].each do |name|
			l[:chains][name].each do |s|
				assert report.owners[s] && report.owners[s].first.include?(name),
					"sector #{s} should belong to #{name}"
			end
		end
		%w[small1 small2].each do |name|
			l[:chains][name].each do |m|
				assert report.mini_owners[m] && report.mini_owners[m].first.include?(name),
					"mini sector #{m} should belong to #{name}"
			end
		end

		# mini sectors can be traced back to the big sectors of the mini-stream
		assert_equal [l[:mini_stream][0], 0], report.mini_sector_location(0)
		assert_equal [l[:mini_stream][0], 64], report.mini_sector_location(1)
		assert_equal (l[:fat][0] + 1) * 512, report.sector_file_offset(l[:fat][0])
	end

	def test_instance_method
		Ole::Storage.open @path, 'rb' do |ole|
			assert ole.validate_allocation.ok?
		end
	end

	def test_valid_file_4096
		make_test_file @path, 12
		report = Ole::Storage.validate_allocation @path
		assert report.ok?, report.to_s
		assert_equal 4096, report.sector_size
	end

	def test_read_only
		before = File.binread @path
		Ole::Storage.validate_allocation @path
		assert_equal before, File.binread(@path), 'file must not be modified'
	end

	def test_invalid_file
		report = Ole::Storage.validate_allocation StringIO.new('not an ole file')
		assert !report.ok?
		assert_equal 1, report.issues_for(:header).length
	end

	def test_cycle
		chain = layout(@path)[:chains]['big1']
		# point the third sector of big1 back at its first sector
		write_fat_entry @path, chain[2], chain[0]
		report = Ole::Storage.validate_allocation @path
		cycles = report.issues_for :cycle
		assert_equal 1, cycles.length, report.to_s
		assert_include cycles[0].streams, 'big1'
		assert_include cycles[0].sectors, chain[0]
		assert_include cycles[0].message, "sector #{chain[0]}"
	end

	def test_cross_ownership
		l = layout @path
		big1, big2 = l[:chains]['big1'], l[:chains]['big2']
		# merge big2's chain into the middle of big1's chain
		write_fat_entry @path, big2[0], big1[1]
		report = Ole::Storage.validate_allocation @path
		cross = report.issues_for :cross_ownership
		assert cross.length >= 1, report.to_s
		issue = cross.find { |i| i.sectors == [big1[1]] }
		assert issue, report.to_s
		assert_include issue.streams, 'big1'
		assert_include issue.streams, 'big2'
		assert_include issue.message, 'big1'
		assert_include issue.message, 'big2'
	end

	def test_chain_too_short
		chain = layout(@path)[:chains]['big1']
		# terminate big1's chain after 6 of its 20 sectors
		write_fat_entry @path, chain[5], AT::EOC
		report = Ole::Storage.validate_allocation @path
		short = report.issues_for :chain_too_short
		assert_equal 1, short.length, report.to_s
		assert_include short[0].streams, 'big1'
		assert_match(/declares 10000 bytes/, short[0].message)
		assert_equal chain[0, 6], short[0].sectors
	end

	def test_fat_sector_marker
		fat_sector = layout(@path)[:fat].first
		# the FAT sector itself is no longer marked FATSECT
		write_fat_entry @path, fat_sector, AT::EOC
		report = Ole::Storage.validate_allocation @path
		markers = report.issues_for :invalid_marker
		assert_equal 1, markers.length, report.to_s
		assert_equal [fat_sector], markers[0].sectors
		assert_match(/FAT sector #{fat_sector} is marked ENDOFCHAIN instead of FATSECT/,
			markers[0].message)
	end

	def test_marker_inside_chain
		chain = layout(@path)[:chains]['big1']
		# a special marker shows up in the middle of big1's chain
		write_fat_entry @path, chain[1], AT::BAT
		report = Ole::Storage.validate_allocation @path
		markers = report.issues_for :invalid_marker
		# the sector is both mis-marked in the FAT and hit by big1's chain
		assert_equal 2, markers.length, report.to_s
		issue = markers.find { |i| i.streams.include? 'big1' }
		assert issue, report.to_s
		assert_match(/terminated by FATSECT/, issue.message)
		assert_include markers.map { |i| i.sectors }.flatten, chain[1]
	end

	def test_unreachable_sectors
		l = layout @path
		chain = l[:chains]['big2']
		# sever big2 from its chain; the sectors stay allocated in the FAT
		write_u32 @path, dirent_offset(@path, 'big2') + 116, AT::EOC
		report = Ole::Storage.validate_allocation @path
		unreachable = report.issues_for :unreachable
		sectors = unreachable.map { |i| i.sectors }.flatten
		chain.each { |s| assert_include sectors, s }
		# and the declared size of big2 can no longer be satisfied
		short = report.issues_for :chain_too_short
		assert_equal 1, short.length, report.to_s
		assert_include short[0].streams, 'big2'
	end

	def test_mini_cycle
		l = layout @path
		chain = l[:chains]['small1']
		assert chain.length >= 2
		# loop small1's mini chain back onto itself
		write_minifat_entry @path, chain[1], chain[0]
		report = Ole::Storage.validate_allocation @path
		cycles = report.issues_for :cycle
		assert_equal 1, cycles.length, report.to_s
		assert_include cycles[0].streams, 'small1'
		# the mini sector is reported together with its actual big sector
		big = l[:mini_stream][chain[0] / 8]
		assert_equal [big], cycles[0].sectors
		assert_match(/mini sector #{chain[0]} \(sector #{big},/, cycles[0].message)
	end

	def test_mini_cross_ownership
		l = layout @path
		small1, small2 = l[:chains]['small1'], l[:chains]['small2']
		# merge small2's mini chain into small1's
		write_minifat_entry @path, small2[0], small1[1]
		report = Ole::Storage.validate_allocation @path
		cross = report.issues_for :cross_ownership
		assert_equal 1, cross.length, report.to_s
		assert_include cross[0].streams, 'small1'
		assert_include cross[0].streams, 'small2'
		big = l[:mini_stream][small1[1] / 8]
		assert_equal [big], cross[0].sectors
		assert_match(/mini sector #{small1[1]} \(sector #{big},/, cross[0].message)
	end

	def test_mini_chain_too_short
		chain = layout(@path)[:chains]['small2']
		# truncate small2's mini chain after its first mini sector
		write_minifat_entry @path, chain[0], AT::EOC
		report = Ole::Storage.validate_allocation @path
		short = report.issues_for :chain_too_short
		assert_equal 1, short.length, report.to_s
		assert_include short[0].streams, 'small2'
		assert_match(/requiring #{chain.length} mini sectors/, short[0].message)
	end

	def test_4096_cycle
		make_test_file @path, 12
		chain = layout(@path)[:chains]['big1']
		write_fat_entry @path, chain[1], chain[0]
		report = Ole::Storage.validate_allocation @path
		assert_equal 4096, report.sector_size
		cycles = report.issues_for :cycle
		assert_equal 1, cycles.length, report.to_s
		assert_include cycles[0].streams, 'big1'
		assert_include cycles[0].sectors, chain[0]
	end

	def test_directory_cycle
		dir_chain = layout(@path)[:dir]
		# loop the directory chain back onto itself
		write_fat_entry @path, dir_chain[0], dir_chain[0]
		report = Ole::Storage.validate_allocation @path
		cycles = report.issues_for :cycle
		assert_equal 1, cycles.length, report.to_s
		assert_include cycles[0].message, 'directory chain'
		assert_include cycles[0].sectors, dir_chain[0]
	end

	def test_difat_chain
		# a file big enough to require a DIFAT chain (more than the 109 FAT
		# sector slots in the header)
		Ole::Storage.open @path, 'w+' do |ole|
			ole.file.open('myfile', 'w') do |f|
				s = 0.chr * 1_000_000
				10.times { f.write s }
			end
		end
		report = Ole::Storage.validate_allocation @path
		assert report.ok?, report.to_s
		header = read_header @path
		assert header['num_mbat'] > 0, 'test file should have a DIFAT chain'
		assert_equal ['DIFAT'], report.owners[header['mbat_start']]

		# break the DIFAT chain: point its next-sector pointer back at itself
		mbat = header['mbat_start']
		write_u32 @path, (mbat + 1) * 512 + 508, mbat
		report = Ole::Storage.validate_allocation @path
		cycles = report.issues_for :cycle
		assert_equal 1, cycles.length, report.to_s
		assert_include cycles[0].message, 'DIFAT'
		assert_include cycles[0].sectors, mbat
	end
end
