#! /usr/bin/ruby

$: << File.dirname(__FILE__) + '/../lib'

require 'test/unit'
require 'ole/storage'
require 'digest/sha1'
require 'stringio'
require 'tempfile'

#
# Tests for Ole::Storage::Layout - the archival layout rewriter that
# places a nominated set of hot streams contiguously in a new file.
#
class TestLayout < Test::Unit::TestCase
	Layout = Ole::Storage::Layout
	AT = Ole::Storage::AllocationTable

	# build a source document with a mixture of stream sizes, nested
	# directories, non default meta data, an empty stream, and a big
	# stream whose chain is fragmented across the file.
	def make_source
		temp = Tempfile.new 'test-layout'
		temp.binmode
		Ole::Storage.open(temp, nil, :update_timestamps => false) do |ole|
			ole.dir.mkdir 'dir1'
			ole.dir.mkdir 'dir1/dir2'
			ole.file.open('hot_big_1', 'w') { |f| f.write 'H' * 5000 }
			ole.file.open('cold_big', 'w') { |f| f.write 'C' * 9000 }
			# growing hot_big_1 after cold_big was allocated fragments its chain
			ole.file.open('hot_big_1', 'a') { |f| f.write 'h' * 5000 }
			ole.file.open('hot_big_2', 'w') { |f| f.write 'B' * 6000 }
			ole.file.open('hot_small', 'w') { |f| f.write 's' * 100 }
			ole.file.open('cold_small', 'w') { |f| f.write 't' * 300 }
			ole.file.open('empty', 'w') { |f| }
			ole.file.open('dir1/nested', 'w') { |f| f.write 'n' * 50 }
			dir1 = ole.root / 'dir1'
			dir1.clsid = (1..16).to_a.pack 'C*'
			dir1.flags = 0x0b
			hot = ole.root / 'hot_big_1'
			hot.create_time_str = "\x01\x02\x03\x04\x05\x06\x07\x08"
			hot.modify_time_str = "\x11\x12\x13\x14\x15\x16\x17\x18"
		end
		temp
	end

	def all_paths ole
		paths = []
		walk = lambda do |dirent, prefix|
			dirent.children.each do |child|
				path = prefix.empty? ? child.name : "#{prefix}/#{child.name}"
				paths << path
				walk.call child, path if child.dir?
			end
		end
		walk.call ole.root, ''
		paths
	end

	def test_rewrite_layout
		temp = make_source
		src = Ole::Storage.open temp.path, 'rb'
		out = Tempfile.new 'test-layout-out'
		out.close
		report = src.rewrite_layout out.path,
			:order => %w[hot_big_2 hot_big_1 hot_small],
			:align => { 'hot_big_2' => 4, 'hot_small' => 2 }

		# every stream's hash checks out, and nothing is more fragmented
		# than it was.
		assert report.ok?
		assert report.fragments_after <= report.fragments_before
		assert_equal 1, report['hot_big_2'].fragments_after
		assert_equal 1, report['hot_big_1'].fragments_after
		assert_equal 1, report['hot_small'].fragments_after

		# the fragmented hot stream is defragmented
		assert report['hot_big_1'].fragments_before >= 2
		assert_equal 1, report['hot_big_1'].fragments_after

		# hot streams are laid out in the requested order, and adjacently
		# (hot_big_2 occupies 12 sectors, hot_big_1 follows immediately)
		assert report['hot_big_2'].first_block_after < report['hot_big_1'].first_block_after
		assert_equal report['hot_big_2'].first_block_after + 12,
			report['hot_big_1'].first_block_after
		r2 = report['hot_big_2'].ranges_after
		r1 = report['hot_big_1'].ranges_after
		assert_equal 1, r2.length
		assert_equal 1, r1.length

		# alignment constraints are honoured
		assert_equal 0, report['hot_big_2'].first_block_after % 4
		assert_equal 0, report['hot_small'].first_block_after % 2

		# the empty stream is still empty, and correctly represented
		assert_equal 0, report['empty'].size
		assert_equal :empty, report['empty'].space
		assert_equal AT::EOC, report['empty'].first_block_after

		new_ole = Ole::Storage.open out.path, 'rb'
		# storage hierarchy is preserved
		assert_equal all_paths(src), all_paths(new_ole)
		# clsid, state bits and time fields are preserved
		dir1 = new_ole.root / 'dir1'
		assert_equal (1..16).to_a.pack('C*'), dir1.clsid
		assert_equal 0x0b, dir1.flags
		hot = new_ole.root / 'hot_big_1'
		assert_equal "\x01\x02\x03\x04\x05\x06\x07\x08", hot.create_time_str
		assert_equal "\x11\x12\x13\x14\x15\x16\x17\x18", hot.modify_time_str
		# logical content of every stream is unchanged
		assert_equal 'H' * 5000 + 'h' * 5000, new_ole.file.read('hot_big_1')
		assert_equal 'B' * 6000, new_ole.file.read('hot_big_2')
		assert_equal 'C' * 9000, new_ole.file.read('cold_big')
		assert_equal 's' * 100, new_ole.file.read('hot_small')
		assert_equal 't' * 300, new_ole.file.read('cold_small')
		assert_equal 'n' * 50, new_ole.file.read('dir1/nested')
		assert_equal '', new_ole.file.read('empty')
		assert_equal AT::EOC, (new_ole.root / 'empty').first_block
	ensure
		src.close if src
	end

	def test_mini_stream_cutoff
		temp = Tempfile.new 'test-layout-cutoff'
		temp.binmode
		sizes = { 's4095' => 4095, 's4096' => 4096, 's4097' => 4097, 's0' => 0 }
		Ole::Storage.open temp do |ole|
			sizes.each do |name, size|
				ole.file.open(name, 'w') { |f| f.write name[0] * size }
			end
		end
		src = Ole::Storage.open temp.path, 'rb'
		out = Tempfile.new 'test-layout-cutoff-out'
		out.close
		report = src.rewrite_layout out.path
		assert report.ok?

		# each stream lands on the correct side of the mini stream cutoff
		assert_equal :mini, report['s4095'].space
		assert_equal :big, report['s4096'].space
		assert_equal :big, report['s4097'].space
		assert_equal :empty, report['s0'].space

		new_ole = Ole::Storage.open out.path, 'rb'
		# 4095 lives in the mini stream, addressed through the sbat
		assert_equal 64, new_ole.sbat.chain((new_ole.root / 's4095').first_block).length
		# 4096 and 4097 use regular sectors
		assert_equal 8, new_ole.bbat.chain((new_ole.root / 's4096').first_block).length
		assert_equal 9, new_ole.bbat.chain((new_ole.root / 's4097').first_block).length
		assert_equal AT::EOC, (new_ole.root / 's0').first_block
		sizes.each do |name, size|
			assert_equal name[0] * size, new_ole.file.read(name)
		end
	ensure
		src.close if src
	end

	def test_difat_boundary
		# a document big enough to need more than the 109 difat entries
		# that fit in the header, forcing mbat (difat) sectors.
		temp = Tempfile.new 'test-layout-difat'
		temp.binmode
		Ole::Storage.open temp do |ole|
			ole.file.open 'big', 'w' do |f|
				chunk = 'd' * 1_000_000
				8.times { f.write chunk }
			end
		end
		src = Ole::Storage.open temp.path, 'rb'
		assert src.header.num_bat > Layout::HEADER_DIFAT
		assert src.header.num_mbat > 0

		out = Tempfile.new 'test-layout-difat-out'
		out.close
		report = src.rewrite_layout out.path, :order => %w[big]
		assert report.ok?
		assert_equal 1, report['big'].fragments_after

		new_ole = Ole::Storage.open out.path, 'rb'
		assert new_ole.header.num_bat > Layout::HEADER_DIFAT
		assert new_ole.header.num_mbat > 0
		assert_not_equal AT::EOC, new_ole.header.mbat_start
		assert_equal 'd' * 8_000_000, new_ole.file.read('big')
	ensure
		src.close if src
	end

	def test_below_difat_boundary
		# a medium document stays within the header difat capacity
		temp = Tempfile.new 'test-layout-nodifat'
		temp.binmode
		Ole::Storage.open temp do |ole|
			ole.file.open('mid', 'w') { |f| f.write 'm' * 7_000_000 }
		end
		src = Ole::Storage.open temp.path, 'rb'
		out = Tempfile.new 'test-layout-nodifat-out'
		out.close
		report = src.rewrite_layout out.path
		assert report.ok?
		new_ole = Ole::Storage.open out.path, 'rb'
		assert new_ole.header.num_bat <= Layout::HEADER_DIFAT
		assert_equal 0, new_ole.header.num_mbat
		assert_equal AT::EOC, new_ole.header.mbat_start
		assert_equal 'm' * 7_000_000, new_ole.file.read('mid')
	ensure
		src.close if src
	end

	def test_conflicts
		temp = make_source
		src = Ole::Storage.open temp.path, 'rb'
		out = Tempfile.new 'test-layout-conflict'
		out.write 'sentinel'
		out.close

		# duplicate hot stream
		assert_raise Layout::ConflictError do
			src.rewrite_layout out.path, :order => %w[hot_big_1 hot_big_1]
		end
		# unknown stream
		assert_raise Layout::ConflictError do
			src.rewrite_layout out.path, :order => %w[nosuch]
		end
		# a directory is not a stream
		assert_raise Layout::ConflictError do
			src.rewrite_layout out.path, :order => %w[dir1]
		end
		# unknown alignment target
		assert_raise Layout::ConflictError do
			src.rewrite_layout out.path, :align => { 'nosuch' => 2 }
		end
		# alignment of a directory
		assert_raise Layout::ConflictError do
			src.rewrite_layout out.path, :align => { 'dir1' => 2 }
		end
		# an empty stream has no physical location to align
		assert_raise Layout::ConflictError do
			src.rewrite_layout out.path, :align => { 'empty' => 2 }
		end
		# bogus alignment values
		[0, -2, 1.5, 'x'].each do |n|
			assert_raise Layout::ConflictError do
				src.rewrite_layout out.path, :align => { 'hot_big_1' => n }
			end
		end
		# conflicts are detected before anything is written
		assert_equal 'sentinel', File.read(out.path)
	ensure
		src.close if src
	end

	def test_rewrite_to_io
		temp = make_source
		src = Ole::Storage.open temp.path, 'rb'
		io = StringIO.new ''.dup
		report = src.rewrite_layout io, :order => %w[hot_big_1]
		assert report.ok?
		assert_equal 1, report['hot_big_1'].fragments_after
		new_ole = Ole::Storage.new StringIO.new(io.string)
		assert_equal 'H' * 5000 + 'h' * 5000, new_ole.file.read('hot_big_1')
	ensure
		src.close if src
	end

	def test_output_must_differ_from_source
		temp = make_source
		src = Ole::Storage.open temp.path, 'rb'
		assert_raise(ArgumentError) { src.rewrite_layout temp.path }
		assert_raise(ArgumentError) { src.rewrite_layout src.io }
	ensure
		src.close if src
	end
end
