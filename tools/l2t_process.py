#!/usr/bin/python
"""
#################################################################################################
                                     l2t_process
#################################################################################################
This is an implementation of l2t_process in Python that sort the l2t_csv file that is the default
output mechanism of log2timeline.

The tool uses external sorting (sort/merge) algorithm to sort the l2t_csv file. This is needed
since the process is often run in SIFT with limited memory. Additionally kitchen-sink approaches
to collecting the supertimeline often results in timeline files in the size range of 4-8 Gb in
size, which makes loading everything in memory and then sort to be both ineffecient and memory
consumption blackhole.

Copyright 2009-2012 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)

This file is part of log2timeline.

    log2timeline is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    log2timeline is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with log2timeline.  If not, see <http://www.gnu.org/licenses/>.
"""
import logging
import os
import re
import sys
import csv
import datetime
import optparse
import random

__author__ = 'Kristinn Gudjonsson (kristinn@log2timeline.net)'
__version__ = '0.1'

# The buffer we use for sorting (increasing it will require more memory usage,
# yet faster processing). This is the default value, but it can be changed
# via parameter to the tool.
# Size is set to 256 Mb by default.
BUFFER_SIZE = 1024 * 1024 * 256

L2T_RE = re.compile(('^date,time,timezone,MACB,source,sourcetype,type,user,host,'
                     'short,desc,version,filename,inode,notes,format,extra$'))

L2T_TIME = re.compile("""^(?P<date>\d{2}\/\d{2}\/\d{2}),(?P<time>\d{2}:\d{2}\d{2}),""", re.X)


def ExternalSplit(sortfile, temp_name, buffer_size=0):
  """External sorting algorithm.

  This is an implementation of an external sorting algorithm that splits up
  the bodyfile into several smaller files, with the size determined by the
  buffer_size, and then sorts each smaller file.

  Args:
    sortfile: The filehandle to the original bodyfile that needs to be sorted.
    temp_name: Name of the temporary output file used to store sorted portions.
    buffer_size: The size of the buffer used for sorting (if zero all file is
    loaded in memory).
  """
  counter = 1
  check_size = 0

  logging.debug('Buffer size: %d', buffer_size)
  temp_buffer = []
  for line in sortfile.readlines():
    date_and_time_str = '%s%s%s%s%s%s' % (line[6:10], line[0:2], line[3:5],
                                          line[11:13], line[14:16], line[17:19])
    date_and_time = int(date_and_time_str)
    a_list = (date_and_time, line)
    if not FilterOut(a_list):
      temp_buffer.append(a_list)

    check_size += len(line)
    if buffer_size and (check_size >= buffer_size):
      logging.debug('[ExternalSplit] Flushing, bufsize: %d, and check_size: %d', buffer_size, check_size)
      FlushBuffer(temp_buffer, counter, temp_name)
      temp_buffer = []
      check_size = 0
      counter += 1
  logging.debug('[ExternalSplit] Flushing last buffer.')
  FlushBuffer(temp_buffer, counter, temp_name)

def FlushBuffer(buf, count, temp):
  """Write a buffer to file.
  
  Args:
    buf: A list containing a tuble with two entries, a date and time merged together and
    the original line.
    count: The number of the "flush" file, or the number of times this method is called.
    temp: The name of the temporary
  """
  fh = open('%s.%05d' % (temp, count), 'wb')

  for line in sorted(buf, key=lambda x: x[0]):
    fh.write('%s,%s' % (line[0], line[1]))

  fh.close()

def FilterOut(test):
  return False

def ExternalMergeSort(in_file_str, out_file):
  """External merge algorithm.

  This is an implementation of a sort-merge algorithm. It takes multiple
  files that are each sorted and merges them together in a one large file,
  that is sorted.

  Args:
    in_file_str: The input file structure.
    out_file: Filehandle to the output file.
  """
  # build a list of all files, 
  # get the first values from each file
  # write the lowest value to a file (or stdout)
  # read new value from that file and continue
  files = []
  lines = []

  for fn in GetListOfFiles(in_file_str):
    files.append(open(fn, 'rb'))
    line = files[-1].readline()
    if not line:
      _ = files.pop()
    else:
      lines.append((int(line[0:14]), line[15:]))
      logging.debug('Appended: %d', int(line[0:14]))
    
  logging.debug('[MERGE] FILES <%d> LINES <%d>', len(files), len(lines))
  while len(files) > 0:
    lowest = sorted(lines, key=lambda x: x[0])[0]
    logging.debug('low: %d', lowest[0])
    i = lines.index(lowest)
    logging.debug('Found lowest [%d]: <%d> %s = %d', i, lowest[0], lowest[1], lines[i][0])
    out_file.write('%s' % lowest[1])
    line = files[i].readline()
    if line:
      lines[i] = (int(line[0:14]), lines[15:])
    else:
      lines.pop(i)
      files.pop(i)

  out_file.close()

def GetListOfFiles(in_file_str):
  path = os.path.dirname(in_file_str) or '.'
  for fn in os.listdir(path):
    if in_file_str in fn:
      yield fn

def IsL2tCsv(filehandle, out):
  """Read the first line and parse the header."""
  line = f.readline()
  
  if L2T_RE.match(line):
    out.write(line)
    return True

  return False

if __name__ == '__main__':
  option_parser = optparse.OptionParser()

  option_parser.add_option('-b', '--file', '--bodyfile', dest='filename',
                           help='The input CSV file.', metavar='FILE')

  option_parser.add_option('--buffer-size', '--bs', dest='buffer_size',
                           help='The size of the buffer used for external sorting.',
                           action='store')

  option_parser.add_option('-d', '--debug', dest='debug',
                           action='store_true', default=False,
                           help='Turn on debug information.')
  option_parser.add_option('-t', '--tab', dest='tab', action='store_true',
                           default=False, help='The input file is TAB delimited.')

  option_parser.add_option('--chunk_size', dest='csize', action='store',
                           default=200, help='The default chunk size for external sorting.')

  option_parser.add_option('--output', '-o', dest='output', action='store',
                           metavar='FILE', help='The output file', default='STDOUT')

  options, args = option_parser.parse_args()

  if options.debug:
    logging.basicConfig(level=logging.DEBUG)
    logging.debug('[l2t_process] Turning debug on.')

  if not options.filename:
    logging.error('[l2t_process] Must provide a filename.')
    sys.exit(1)

  if not os.path.isfile(options.filename):
    logging.error('Wrong usage: bodyfile must exist.')
    sys.exit(1)

  # check if bodyfile is smaller than buf_size
  # then set it to zero.
  if options.output== 'STDOUT':
    output_file = sys.stdout
  else:
    output_file = open(options.output, 'wb')

  # check date filter
  date_filter_low = None
  date_filter_high = None
  if len(args) == 1:
    date_regex = re.compile('^(\d{1,2})-(\d{1,2})-(\d{4})$')
    daterange_regex = re.compile('^(\d{1,2})\-(\d{1,2})\-(\d{4})\.\.(\d{1,2})\-(\d{1,2})\-(\d{4})$')

    m_date = date_regex.match(args[0])

    if m_date:
      date_filter_low = int(''.join(args[0].split('-')))
    else:
      m_range = daterange_regex.match(args[0])
      if m_range:
        filters = args[0].split('..')
        date_filter_low = int(''.join(filters[0].split('-')))
        date_filter_low = int('%04d%02d%02d' % (int(m_range.group(3)), int(m_range.group(1)), int(m_range.group(2))))
        date_filter_high = int('%04d%02d%02d' % (int(m_range.group(6)), int(m_range.group(4)), int(m_range.group(5))))

  if date_filter_low:
    print 'FILTER: %d' % date_filter_low
  if date_filter_high:
    print 'FILTER: %d' % date_filter_high

  with open(options.filename, 'rb') as f:
    if not IsL2tCsv(f, output_file):
      logging.error('This is not a L2t CSV file.')
      sys.exit(2)
    # do some other stuff.
    if 'm' in options.buffer_size:
      bs, _, _ = options.buffer_size.partition('m')
      buffer_use_size = int(bs) * 1024 * 1024
    else:
      buffer_use_size = int(options.buffer_size) or BUFFER_SIZE

    logging.debug('[L2t_process] Using buffer size: %d bytes', buffer_use_size)
    temp_output_name = 'l2t_sort_temp_%05d' % random.randint(1,10000)
    logging.debug('[l2t_process] Using <%s> as base name for temporary output files.', temp_output_name)

    ExternalSplit(f, temp_output_name, buffer_use_size)
    ExternalMergeSort(temp_output_name, output_file)

    # delete temp files
    for name in GetListOfFiles(temp_output_name):
      os.remove(name)

#GetOptions(
#           "y!"          => \$reverse,
#           "keyword=s"   => \$keyword_file,
#           "whitelist=s" => \$whitelist_file,
#           "include!"    => \$include_timestomp,
#           "exclude!"    => \$exclude_timestomp,
#           "scatter|s=s" => \$draw_scatter_plot,
#           "multi"       => \$multi_slice,
