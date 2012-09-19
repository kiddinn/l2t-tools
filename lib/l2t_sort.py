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
import pdb
import logging
import os
import re
import heapq

from l2t_tools.lib import lines

__author__ = 'Kristinn Gudjonsson (kristinn@log2timeline.net)'
__version__ = '0.1'


def ExternalSplit(sortfile, temp_name, dfilters, cfilters, pfilters, buffer_size=0):
  """External sorting algorithm.

  This is an implementation of an external sorting algorithm that splits up
  the bodyfile into several smaller files, with the size determined by the
  buffer_size, and then sorts each smaller file.

  Args:
    sortfile: The filehandle to the original bodyfile that needs to be sorted.
    temp_name: Name of the temporary output file used to store sorted portions.
    dfilters: A list (2 entries) with datefilters, integers.
    cfilters: A dict object with other content based filters.
    pfilters: A plugin based filter approach, a list of filter objects.
    buffer_size: The size of the buffer used for sorting (if zero all file is
    loaded in memory).
  """
  counter = 1
  check_size = 0

  logging.debug('Buffer size: %d', buffer_size)
  temp_buffer = []
  temp_append = temp_buffer.append
  for line in sortfile:
    # Should be YYYYMMDDHHMMSS
    # That is we are creating an int that can be used for quick sorting based
    # on the above values.
    date_and_time_str = '%s%s%s%s%s%s' % (line[6:10], line[0:2], line[3:5],
                                          line[11:13], line[14:16], line[17:19])
    try:
      date_and_time = int(date_and_time_str)
    except ValueError as e:
      logging.warning('Unable to parse line (%s): Error msg: %s', line, e)
      continue
    a_list = (date_and_time, line)
    if not FilterOut(a_list, dfilters, cfilters, pfilters):
      temp_append(a_list)
      check_size += len(line)

    if buffer_size and (check_size >= buffer_size):
      logging.debug('Flushing, bufsize: %d, and check_size: %d', buffer_size, check_size)
      FlushBuffer(temp_buffer, counter, temp_name)
      temp_buffer = []
      check_size = 0
      counter += 1
  logging.debug('Flushing last buffer.')
  FlushBuffer(temp_buffer, counter, temp_name)


def GetUnicodeString(string):
  if type(string) == unicode:
    return string

  return str(string).encode('utf-8', 'ignore')


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
    fh.write(','.join(map(GetUnicodeString,line)).decode('utf-8'))

  fh.close()


def FilterOut(test, date_filters, content_filters={}, plugin_filters=[]):
  """A simple method to filter out lines based on their date/content.

  Args:
    test: A list containing two entries; the date as an int and the whole line.
    date_filters: A list containing the date filter (low and high).
    content_filters: A dict containing more detailed content filters.
    plugin_filters: A list of filter objects.

  Returns:
    True if the entry should be filtered out, False otherwise.
  """
  if not len(date_filters) == 2:
    return False

  low, high = date_filters
  date, line = test

  if low and date < low:
    return True

  if high and date > high:
    return True

  # Remove entries if there is a hit.
  if 'blacklist' in content_filters:
    blacklists = content_filters['blacklist']
    for blacklist in blacklists:
      if blacklist.search(line.strip(' ')):
        return True

  # Only include entries if there is a hit.
  if 'whitelist' in content_filters:
    whitelists = content_filters['whitelist']
    for whitelist in whitelists:
      if whitelist.search(line.strip(' ')):
        #TODO check to see if I can change the note
        # field so it includes the match string.
        return False
    return True

  # TODO when threading has been done, just
  # add the event to the queue and don't think
  # about it.
  # Go over all the plugin filters:
  if plugin_filters:
    for pfilter in plugin_filters:
      if not pfilter.FilterLine(test):
        return False
    return True

  return False


def ExternalMergeSort(in_file_str, out_file, plugins, simple=False):
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
    plugins: A list of plugins to run against the input.
    simple: Boolean value determining if we want a simple quick test against
    duplicate lines or a more comprehensive test using a container.
  """
  lowest = []
  if simple:
    container = ()
  else:
    container = lines.L2tContainer()

  count_duplicates = 0

  for fn in GetListOfFiles(in_file_str):
    try:
      handle = open(fn, 'rb')
    except IOError as e:
      logging.error('Unable to append files, perhaps to increase the buffer size? <%s>', e)
      logging.error('All processing has been aborted and temporary files will be removed.')
      out_file.close()
      for _ in range(len(lowest)):
        fh = heapq.heappop(lowest)[2]
        fh.close()
      return
    line = handle.readline()
    if not line:
      continue
    else:
      try:
        heapq.heappush(lowest, (int(line[0:14]), line[15:], handle))
        logging.debug('Appended: %d', int(line[0:14]))
      except ValueError:
        logging.warning('Unable to parse the timestamp: %s' % line[0:14])

  if len(lowest) == 1:
    entry = heapq.heappop(lowest)
    count_duplicates, container = ProcessLine((entry[0], entry[1]), container, out_file,
                                              count_duplicates, plugins)
    for line in entry[2]:
      count_duplicates, container = ProcessLine((line[0:14], line[15:]), container, out_file, count_duplicates, plugins)

  while len(lowest) > 0:
    entry = heapq.heappop(lowest)
    count_duplicates, container = ProcessLine((entry[0], entry[1]), container, out_file, count_duplicates, plugins)
    line = entry[2].readline()
    if line:
      try:
        heapq.heappush(lowest, (int(line[0:14]), line[15:], entry[2]))
      except ValueError:
        logging.warning('Error reading from file: %s (no more processing)', entry[2].name)

  logging.info('Duplicates removed: %d', count_duplicates)
  out_file.close()


def ProcessLine(new_line, container, output, duplicates, plugins):
  """Check if line is a duplicate, run through plugins and return duplicate count and last_line."""
  if type(container) == tuple:
    # Simple check.
    if IsADuplicate(new_line, container):
      duplicates += 1
      return duplicates, new_line

    output.write('%s' % new_line[1])
    for plugin in plugins:
      plugin.AppendLine(new_line)
    return duplicates, new_line

  # We have a container.
  try:
    container.AddLine(new_line[0], new_line[1])
  except lines.WrongTimestamp:
    logging.debug('WrongTimestamp: flushing buffer of size: %d [%d]', len(container), container.timestamp)
    for line in container.FlushContainer():
      output.write('%s' % line)
      for plugin in plugins:
        plugin.AppendLine(str(line))
  except lines.DuplicateLine:
    logging.debug('Duplicate line found, current count: %d', duplicates)
    if 'TEM,1671,-,Log2t:' in new_line[1]:
      pdb.set_trace()
    duplicates += 1
  finally:
    return duplicates, container


def IsADuplicate(line_cur, line_last):
  """Indicate whether or not two lines are duplicates of one another.

  Args:
    line_cur: A list with two entries, timestamp and the original entry.
    line_last: A list with two entries representing the last line that was
    written out. The list contains a timestamp and the original entry.

  Returns:
    A boolean indicating whether or not an entry is a duplicate.
  """
  if not line_last:
    return False

  try:
    if line_cur[0] == line_last[0]:
      if line_cur[1] == line_last[1]:
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


def BuildKeywordList(in_file_str, flags):
  """Return a list of compiled re objects that can be used for keyword matching."""
  if not os.path.isfile(in_file_str):
    return None

  the_list = []
  with open(in_file_str, 'rb') as fh:
    for word in fh:
      if not word:
        continue
      if word[0] == '#':
        continue
      
      # TODO: complete this
      #   + swap commas for dashes s/,/-/g
      #   + swap \ for / (s/\\/\//g)
      word = word.strip('\n\r ')
      logging.debug('Keyword list, adding the word: <%s>', word)
      the_list.append(re.compile(word, flags))
  return the_list
