#! /usr/bin/ruby
# coding: utf-8

$: << File.dirname(__FILE__) + '/../lib'

require 'test/unit'
require 'ole/storage'
require 'stringio'
require 'digest/sha1'

class TestLayoutRewriter < Test::Unit::TestCase
	def build_ole
		io = StringIO.new(''.dup)
		Ole::Storage.open(io) do |ole|
			ole.root.clsid = (32..47).map(&:chr).join
			ole.root.flags = 0x4321
			create_stream(ole, 'empty', '')
			create_stream(ole, 'small_one', 'a' * 100)
			create_stream(ole, 'small_two', 'b' * 4000)
			create_stream(ole, 'big_one', 'c' * 5000)
			ole.dir.mkdir('storage')
			create_stream(ole, 'storage/nested_small', 'd' * 50)
			storage = ole.dirent_from_path('/storage')
			storage.clsid = (1..16).map(&:chr).join
			storage.flags = 0x1234
			file = ole.dirent_from_path('/small_one')
			file.create_time_str = Ole::Types::Variant.dump(Ole::Types::VT_FILETIME, Ole::Types::FileTime.new(2001, 2, 3, 4, 5, 6))
			file.modify_time_str = Ole::Types::Variant.dump(Ole::Types::VT_FILETIME, Ole::Types::FileTime.new(2002, 3, 4, 5, 6, 7))
		end
		io.rewind
		io
	end

	def create_stream(ole, path, data)
		ole.file.open(path, 'w') { |io| io.write(data) }
	end

	def metadata(storage)
		result = {}
		walk = lambda do |dirent, path|
			result[path] = {
				:type => dirent.type, :name => dirent.name, :clsid => dirent.clsid.dup,
				:flags => dirent.flags, :colour => dirent.colour,
				:create => dirent.create_time_str.to_s.dup,
				:modify => dirent.modify_time_str.to_s.dup, :size => dirent.size
			}
			dirent.children.each { |child| walk.call(child, path + '/' + child.name) } unless dirent.file?
		end
		walk.call(storage.root, '')
		result
	end

	def test_reorders_across_mini_and_big_thresholds_with_empty_stream
		source = build_ole
		Ole::Storage.open(source, :update_timestamps => false) do |ole|
			before = metadata(ole)
			result = ole.rewrite_layout(:string, [
				{:path => '/storage/nested_small', :alignment => 1024},
				'/small_one', '/big_one', '/empty'
			])
			after_io = StringIO.new(result[:output])
			assert_equal 0, result[:after][:streams].find { |s| s[:path] == '/empty' }[:intervals]
			nested = result[:after][:streams].find { |s| s[:path] == '/storage/nested_small' }
			big = result[:after][:streams].find { |s| s[:path] == '/big_one' }
			small = result[:after][:streams].find { |s| s[:path] == '/small_one' }
			assert_equal 1, nested[:intervals]
			assert_equal 0, nested[:ranges].first[0] % 1024
			assert_equal 1, small[:intervals]
			assert_equal 1, big[:intervals]
			assert nested[:ranges].last[0] + nested[:ranges].last[1] <= big[:ranges].first[0]
			assert small[:ranges].last[0] + small[:ranges].last[1] <= big[:ranges].first[0]
			assert result[:before][:total_intervals] >= result[:after][:total_intervals]
			assert result[:after][:streams].all? { |stream| stream[:intervals] == (stream[:size].zero? ? 0 : 1) }
			Ole::Storage.open(after_io, :update_timestamps => false) do |new_ole|
				after = metadata(new_ole)
				except_root = ->(hash) { hash.reject { |path, _| path.empty? } }
				assert_equal except_root.call(before), except_root.call(after)
				assert_equal 'd' * 50, new_ole.file.read('/storage/nested_small')
				assert_equal 'c' * 5000, new_ole.file.read('/big_one')
				assert_equal '', new_ole.file.read('/empty')
			end
		end
	end

	def test_crosses_header_difat_capacity_without_a_large_real_document
		source = StringIO.new(''.dup)
		Ole::Storage.open(source) do |ole|
			create_stream(ole, 'warm_small', 'x' * 100)
			create_stream(ole, 'large', 'y' * (8 * 1024 * 1024))
			create_stream(ole, 'cold_small', 'z' * 100)
		end
		source.rewind
		Ole::Storage.open(source, :update_timestamps => false) do |ole|
			result = ole.rewrite_layout(:string, ['/warm_small', '/large'])
			assert result[:plan][:fat_sectors] > 109
			assert_equal 1, result[:plan][:difat_sectors]
			large = result[:after][:streams].find { |s| s[:path] == '/large' }
			warm = result[:after][:streams].find { |s| s[:path] == '/warm_small' }
			assert_equal 1, large[:intervals]
			assert_equal 1, warm[:intervals]
			assert_equal Digest::SHA1.hexdigest('y' * (8 * 1024 * 1024)), large[:sha1]
			Ole::Storage.open(StringIO.new(result[:output])) do |new_ole|
				assert new_ole.header.num_bat > 109
				assert_equal 1, new_ole.header.num_mbat
				assert_equal 8 * 1024 * 1024, new_ole.file.size('/large')
			end
		end
	end

	def test_preserves_global_priority_across_big_and_mini_streams
		source = StringIO.new(''.dup)
		Ole::Storage.open(source) do |ole|
			create_stream(ole, 'first_small', 'a' * 100)
			create_stream(ole, 'middle_big', 'b' * 5000)
			create_stream(ole, 'last_small', 'c' * 100)
		end
		source.rewind
		Ole::Storage.open(source, :update_timestamps => false) do |ole|
			result = ole.rewrite_layout(:string, ['/first_small', '/middle_big', '/last_small'])
			positions = %w[/first_small /middle_big /last_small].map do |path|
				stream = result[:after][:streams].find { |item| item[:path] == path }
				assert_equal 1, stream[:intervals]
				stream[:ranges].first[0]
			end
			assert_equal positions, positions.sort
			assert_equal Digest::SHA1.hexdigest('b' * 5000), result[:after][:streams].find { |s| s[:path] == '/middle_big' }[:sha1]
		end
	end

	def test_reports_conflicts_and_does_not_claim_arbitrary_layout
		source = build_ole
		Ole::Storage.open(source, :update_timestamps => false) do |ole|
			error = assert_raises(Ole::Storage::LayoutConflict) do
				ole.rewrite_layout(:string, ['/missing', '/small_one'], :alignment => {'/big_one' => 4097, '/small_one' => 8})
			end
			messages = error.conflicts.map { |conflict| conflict[:message] }
			assert messages.any? { |message| message.include?('stream not found') }
			assert messages.any? { |message| message.include?('positive multiple') }
		end
	end
end
