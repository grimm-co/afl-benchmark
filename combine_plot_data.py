#!/usr/bin/env python3
from argparse import ArgumentParser
"""
How to use this script for some cool benchmarking:
# Start AFL
~/fuzzing/afl-launch/afl-launch -no-master -n 16 -i ~/fuzzing/afl/testcases/archives/common/tar/ -o ~/fuzzing/outputs/tar -- ~/fuzzing/targets/tar-1.29/src/tar -x

# Give it some time to generate some data
sleep 60

# Combine the plot_data from all the different instances
./fuzzing/combine_plot_data.py -o tmp/plot_data ./fuzzing/outputs/tar/ufngj-*/plot_data

# Plot it out and look at it
~/fuzzing/afl/afl-plot tmp ./fuzzing/test_plot
firefox ./fuzzing/test_plot/index.html

"""

class Record:
	def __init__(self, line=None):
		self.unix_time = -1
		self.cycles_done = 0
		self.cur_path = 0
		self.paths_total = 0
		self.pending_total = 0
		self.pending_favs = 0
		self.map_size = 0
		self.unique_crashes = 0
		self.unique_hangs = 0
		self.max_depth = 0
		self.execs_per_sec = 0
		if line is not None:
			self.parse_line(line)

	def parse_line(self, line):
		"""
		Parse a line of text from the plot_data file.

		:param line: line of text from the plot_data file
		:type line: string
		:returns: False for comments, True if record was parsed
		:rtype: boolean
		"""
		if line[0] == "#":
			return False
		parts = [x.strip() for x in line.strip().split(",")]
		self.unix_time = int(parts[0])
		self.cycles_done = int(parts[1])
		self.cur_path = int(parts[2])
		self.paths_total = int(parts[3])
		self.pending_total = int(parts[4])
		self.pending_favs = int(parts[5])
		self.map_size = float(parts[6].replace("%",""))
		self.unique_crashes = int(parts[7])
		self.unique_hangs = int(parts[8])
		self.max_depth = int(parts[9])
		self.execs_per_sec = float(parts[10])
		return True

	def merge_with(self, other):
		self.cycles_done = max(self.cycles_done, other.cycles_done)
		self.cur_path += other.cur_path
		self.paths_total += other.paths_total
		self.pending_total += other.pending_total
		self.pending_favs += other.pending_favs
		self.map_size = max(self.map_size, other.map_size)
		self.unique_crashes += other.unique_crashes
		self.unique_hangs += other.unique_hangs
		self.max_depth = max(self.max_depth, other.max_depth)
		self.execs_per_sec += other.execs_per_sec

	def __str__(self):
		return "%s, %s, %s, %s, %s, %s, %.2f%%, %s, %s, %s, %.2f" % (
			self.unix_time, self.cycles_done, self.cur_path,
			self.paths_total, self.pending_total, self.pending_favs,
			self.map_size, self.unique_crashes, self.unique_hangs,
			self.max_depth, self.execs_per_sec)

	def __repr__(self):
		return ("{unix_time: %d," % self.unix_time +
			" cycles_done: %d" % self.cycles_done +
			" cur_path: %d" % self.cur_path +
			" paths_total: %d" % self.paths_total +
			" pending_total: %d" % self.pending_total +
			" pending_favs: %d" % self.pending_favs +
			" map_size: %f" % self.map_size +
			" unique_crashes: %d" % self.unique_crashes +
			" unique_hangs: %d" % self.unique_hangs +
			" max_depth: %d" % self.max_depth +
			" execs_per_sec: %f" % self.execs_per_sec +
			"}")

class RecordSet:
	def __init__(self, filename=None):
		self.records = []
		if filename is not None:
			self.read_from_file(filename)

	def read_from_file(self, filename):
		with open(filename, "r") as f:
			for line in f:
				r = Record(line)
				if r.unix_time != -1:
					self.records.append(r)
		print("Read in %d records from %s" % (len(self.records), filename))

	def get_record(self, unix_time, within):
		"""
		Obtains the record in the set with the time closest to the given
		$unix_time.  If this record with not $within the correct number
		of seconds, an exception is raised.

		:param unix_time: The desired unix time
		:type unix_time: integer
		:param within: maximum distance allowed between requested and
				actual times
		:type within: integer
		"""
		if len(self.records) <= 0:
			raise Exception("No records in this set")
		r = self.records[0]
		closest_record = r
		closest_delta = abs(r.unix_time - unix_time)

		for r in self.records[1:]:
			delta = abs(r.unix_time - unix_time)
			if delta < closest_delta:
				closest_record = r
				closest_delta = delta
		if closest_delta > within:
			raise Exception("Closest record to %d was %d (delta=%d) which exceeds limit of %d" %
				(unix_time, closest_record.unix_time, closest_delta, within))

		return closest_record

	def merge_with(self, other, period=60):
		"""
		Pulls in the records from other into self with the other, but
		since the timestamps won't match up perfectly, the output will
		only have a record per $period number of seconds.

		:param other: The other set of records
		:type other: `py:RecordSet`
		:param period: The number of seconds between records
		:type period: integer
		"""
		new_list = []
		last_timestamp = 0
		for r in self.records:
			if abs(r.unix_time - last_timestamp) > period:
				# Accept this record
				last_timestamp = r.unix_time
				other_r = other.get_record(r.unix_time, period/2)
				r.merge_with(other_r)
				new_list.append(r)
		self.records = new_list

	def write_file(self, filename):
		with open(filename, "w") as f:
			for r in self.records:
				f.write("%s\n" % str(r))

def test():
	r = Record("1501957036, 0, 0, 13, 13, 1, 1.38%, 0, 0, 2, 180.22\n")
	assert(repr(r) == "{unix_time: 1501957036, cycles_done: 0 cur_path: 0 paths_total: 13 pending_total: 13 pending_favs: 1 map_size: 1.380000 unique_crashes: 0 unique_hangs: 0 max_depth: 2 execs_per_sec: 180.220000}")
	assert(str(r) == "1501957036, 0, 0, 13, 13, 1, 1.38%, 0, 0, 2, 180.22")

if __name__ == "__main__":
	parser = ArgumentParser("Combines plot_data files from multiple AFL instances")
	parser.add_argument("-o", default="plot_data", help="The filename to write the output")
	parser.add_argument("--delta", "-d", default=60, type=int, help="Amount of time between records")
	parser.add_argument("files", nargs="+")
	args = parser.parse_args()

	# No harm in running a unit test real quick
	test()

	# OK, now lets do the real work...
	full_recordset = RecordSet(args.files[0])
	for filename in args.files[1:]:
		tmp = RecordSet(filename)
		full_recordset.merge_with(tmp, args.delta)
	full_recordset.write_file(args.o)
