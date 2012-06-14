#!/usr/bin/python
"""
This is a collection of methods to sort files, as used by l2t_process.

Copyright 2012 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)

This file is part of l2t-tools.

    l2t-tools is a collection of free software: you can redistribute it and/or
    modify it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    l2t-tools is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with log2timeline.  If not, see <http://www.gnu.org/licenses/>.
"""
import logging
import os

__author__ = 'Kristinn Gudjonsson (kristinn@log2timeline.net)'
__version__ = '0.1'


def ExternalSplit(sortfile, temp_name, dfilters, buffer_size=0):
  """External sorting algorithm.

  This is an implementation of an external sorting algorithm that splits up
  the bodyfile into several smaller files, with the size determined by the
  buffer_size, and then sorts each smaller file.

  Args:
    sortfile: The filehandle to the original bodyfile that needs to be sorted.
    temp_name: Name of the temporary output file used to store sorted portions.
    dfilters: A list (2 entries) with datefilters, integers.
    buffer_size: The size of the buffer used for sorting (if zero all file is
    loaded in memory).
  """
  counter = 1
  check_size = 0

  logging.debug('Buffer size: %d', buffer_size)
  temp_buffer = []
  for line in sortfile.readlines():
    # should be YYYYMMDDHHMMSS
    date_and_time_str = '%s%s%s%s%s%s' % (line[6:10], line[0:2], line[3:5],
                                          line[11:13], line[14:16], line[17:19])
    try:
      date_and_time = int(date_and_time_str)
    except ValueError as e:
      logging.warning('[Split] Unable to parse line (%s): %s', e, line)
      continue
    a_list = (date_and_time, line)
    if not FilterOut(a_list, dfilters):
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

def FilterOut(test, filters):
  """A simple method to filter out lines based on their date/content.

  Args:
    test: A list containing two entries; the date as an int and the whole line.
    filters: A list containing the date filter (low and high).

  Returns:
    True if the entry should be filtered out, False otherwise."""
  if not len(filters) == 2:
    return False

  if not filters[0]:
    return False

  if filters[1]:
    if test[0] > filters[1]:
      return True

  if test[0] < filters[0]:
    return True

  return False

def ExternalMergeSort(in_file_str, out_file):
  """External merge algorithm.

  This is an implementation of a sort-merge algorithm. It takes multiple
  files that are each sorted and merges them together in a one large file,
  that is sorted.

  The algorithm works in the following manner:
    + Build a list of all the files that contain sorted data.
    + Read a single line from each of them.
    + Sort the results.
    + Output the lowest value.
    + Read another line from the file that had the lowest value.
    + Sort the results and continue until no more lines in any file.

  Args:
    in_file_str: The input file structure.
    out_file: Filehandle to the output file.
  """
  files = []
  lines = []
  last_line = []

  for fn in GetListOfFiles(in_file_str):
    files.append(open(fn, 'rb'))
    line = files[-1].readline()
    if not line:
      _ = files.pop()
    else:
      lines.append((int(line[0:14]), line[15:]))
      logging.debug('Appended: %d', int(line[0:14]))
    
  logging.debug('[MERGE] FILES <%d> LINES <%d>', len(files), len(lines))

  if len(files) == 1:
    line = lines.pop()
    out_file.write(line[1])
    last_line = line
    for line in files[0]:
      line_time = line[0:14]
      line_msg = line[15:]
      if not IsADuplicate((line_time, line_msg), last_line):
        out_file.write(line_msg)
      last_line = line_time, line_msg
    files.pop()

  while len(files) > 0:
    lowest = sorted(lines, key=lambda x: x[0])[0]
    logging.debug('low: %d', lowest[0])
    i = lines.index(lowest)
    logging.debug('Found lowest [%d]: <%d> %s = %d', i, lowest[0], lowest[1], lines[i][0])
    if not IsADuplicate(lowest, last_line):
      out_file.write('%s' % lowest[1])
    last_line = lowest
    line = files[i].readline()
    if line:
      lines[i] = (int(line[0:14]), lines[15:])
    else:
      lines.pop(i)
      files.pop(i)

  out_file.close()

def IsADuplicate(line_a, line_b):
  """Indicate whether or not two lines are duplicates of one another."""
  try:
    if line_a[0] == line_b[0]:
      if line_a[1] == line_b[1]:
        logging.debug('Skipped a line due to a duplicate.')
        return True
  except IndexError:
    logging.debug('Unable to compare lines for duplicates.')

  return False 

def GetListOfFiles(in_file_str):
  """Return all filenames that match the pattern given."""
  path = os.path.dirname(in_file_str) or '.'
  for fn in os.listdir(path):
    if in_file_str in fn:
      yield fn

