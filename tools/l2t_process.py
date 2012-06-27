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
import re
import sys
import argparse
import random
import yara

from l2t_tools.lib import l2t_sort
from l2t_tools.filters import yara_filter
from l2t_tools.plugins import count_system32
from l2t_tools.plugins import temp_exe
from l2t_tools.plugins import yara_match

__author__ = 'Kristinn Gudjonsson (kristinn@log2timeline.net)'
__version__ = '0.1'

# The buffer we use for sorting (increasing it will require more memory usage,
# yet faster processing). This is the default value, but it can be changed
# via parameter to the tool.
# Size is set to 256 Mb by default.
BUFFER_SIZE = 1024 * 1024 * 256

L2T_RE = re.compile(('^date,time,timezone,MACB,source,sourcetype,type,user,host,'
                     'short,desc,version,filename,inode,notes,format,extra$'))

LOG_FORMAT = '[%(levelname)s - %(module)s] %(message)s'


def IsL2tCsv(filehandle, out):
  """Read the first line and parse the header to determine if this is a L2T_CSV file."""
  line = filehandle.readline()
  
  if L2T_RE.match(line):
    out.write(line)
    return True

  return False

if __name__ == '__main__':
  usage = """
l2t_process.py [OPTIONS] -b CSV_FILE [DATE_RANGE]

Where DATE_RANGE is MM-DD-YYYY or MM-DD-YYYY..MM-DD-YYYY"""

  arg_parser = argparse.ArgumentParser(description=usage)

  arg_parser.add_argument('-b', '--file', '--bodyfile', dest='filename',
                          help='The input CSV file.', metavar='BODYFILE')

  arg_parser.add_argument('--bs', '--buffer-size', dest='buffer_size',
                          help='The size of the buffer used for external sorting.',
                          action='store')

  arg_parser.add_argument('-d', '--debug', dest='debug',
                          action='store_true', default=False,
                          help='Turn on debug information.')

  arg_parser.add_argument('-t', '--tab', dest='tab', action='store_true',
                          default=False, help='The input file is TAB delimited.')

  arg_parser.add_argument('-o', '--output', dest='output', action='store',
                          metavar='FILE', help='The output file', default='STDOUT')

  arg_parser.add_argument('-w', '--whitelist', dest='whitelist', action='store',
                          metavar='WHITELIST_FILE', default=None,
                          help=('A file with keywords used to filter out content of'
                                ' the timeline. If this option is used then no entry'
                                ' will be included in the timeline except it matches'
                                ' any of the keywords provided.'
                                ' N.b. the keywords are compiled as regular expressions.'))

  arg_parser.add_argument('-k', '--blacklist', dest='blacklist', action='store',
                          metavar='BLACKLIST_FILE', default=None,
                          help=('A file with keywords used to filter out content of'
                                ' the timeline. If this option is used then all entries'
                                ' in the timeline will be filtered out if a match is found'
                                ' here, that is if a match is found that entry will be '
                                'left out of the final timeline, can be used in conjunction'
                                ' with the whitelist to produce an even greater filter.'
                                ' N.b. the keywords are compiled as regular expressions.'))

  arg_parser.add_argument('-y', '--yara-filter', dest='yara_filters', action='store',
                          default=None, metavar='YARA_RULE_FILE',
                          help=('Filter events out of the timeline based on whether or not'
                                ' a set of YARA rules triggers on the input module and description'
                                ' field of the CSV file. This is very similar functionality to the '
                                ' one provided by l2t_find_evil.py, however no information about '
                                ' which rule fired or why is provided, it is a simple filter.'
                                ' For more details use the --yara-rules to run the same rules '
                                'as a plugin against the timeline to get that information.'))

  arg_parser.add_argument('--countsystem32', dest='countsystem32', action='store_true',
                          default=False, help='Test plugin that does nothing of value.')

  arg_parser.add_argument('--exe-in-temp', dest='exe_in_temp', action='store_true',
                          default=False, help=('Plugin that prints out lines that contains '
                                               'executables from a temp directory.'))

  arg_parser.add_argument('--yara-rules', dest='yara_rules', action='store',
                          default=None, metavar='RULE_FILE',
                          help=('Plugin that compares each line in the timeline against a set'
                                ' of YARA rules. This is the same functionality as is provided'
                                ' by l2t_find_evil.py.'))

  arg_parser.add_argument('-i', '--case-insensitive', dest='flag_case', action='store_true',
                          default=False, help=('Make keyword searches case insensitive (by default'
                                               ' it is case sensitive).'))

  arg_parser.add_argument('--force', dest='force', action='store_true',
                          default=False, help='Force the use of buffer sizes less than 60Mb.')

  arg_parser.add_argument('date_range', nargs='?', action='store', metavar='DATE_RANGE',
                          default=None, help='Date filter, either MM-DD-YYYY or MM-DD-YYYY..MM-DD-YYYY')


  options = arg_parser.parse_args()

  if options.debug:
    logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
    logging.debug('[l2t_process] Turning debug on.')
  else:
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

  if not options.filename:
    logging.error('[l2t_process] Must provide a filename.')
    sys.exit(1)

  if not os.path.isfile(options.filename):
    logging.error('Wrong usage: bodyfile must exist.')
    sys.exit(1)

  if options.tab:
    separator = '\t'
  else:
    separator = ','

  if options.output== 'STDOUT':
    output_file = sys.stdout
  else:
    output_file = open(options.output, 'wb')

  plugins = []
  if options.countsystem32:
    plugins.append(count_system32.System32Count(separator))
  if options.exe_in_temp:
    plugins.append(temp_exe.WinExeInTemp(separator))
  if options.yara_rules:
    try:
      plugins.append(yara_match.YaraMatch(separator, options.yara_rules))
    except yara.SyntaxError as e:
      logging.error('[ERROR] Faulty YARA rule file: %s'. e)
    except IOError as e:
      logging.error('[ERROR] YARA Rule file not found (%s)', e)

  csv_filters = []
  if options.yara_filters:
    try:
      csv_filters.append(yara_filter.YaraFilter(separator, options.yara_filters))
    except yara.SyntaxError as e:
      logging.error('[ERROR] Faulty YARA rule file: %s'. e)
    except IOError as e:
      logging.error('[ERROR] YARA Rule file not found (%s)', e)

  # check date filter
  date_filter_low = None
  date_filter_high = None

  if options.date_range:
    date_regex = re.compile('^(\d{1,2})\-(\d{1,2})\-(\d{4})$')
    daterange_regex = re.compile('^(\d{1,2})\-(\d{1,2})\-(\d{4})\.\.(\d{1,2})\-(\d{1,2})\-(\d{4})$')

    m_date = date_regex.match(options.date_range)

    if m_date:
      date_filter_low = int('%04d%02d%02d000000' % (int(m_date.group(3)), int(m_date.group(1)), int(m_date.group(2))))
    else:
      m_range = daterange_regex.match(options.date_range)
      if m_range:
        filters = options.date_range.split('..')
        date_filter_low = int(''.join(filters[0].split('-')))
        date_filter_low = int('%04d%02d%02d000000' % (int(m_range.group(3)), int(m_range.group(1)), int(m_range.group(2))))
        date_filter_high = int('%04d%02d%02d235959' % (int(m_range.group(6)), int(m_range.group(4)), int(m_range.group(5))))

  if date_filter_low:
    logging.debug('[FILTER] Lower date filter: %d', date_filter_low)
  if date_filter_high:
    logging.debug('[FILTER] Higher date filter: %d', date_filter_high)

  with open(options.filename, 'rb') as f:
    if not IsL2tCsv(f, output_file):
      logging.error('This is not a L2t CSV file.')
      sys.exit(2)

    if options.buffer_size:
      if 'm' in options.buffer_size:
        bs, _, _ = options.buffer_size.partition('m')
        buffer_use_size = int(bs) * 1024 * 1024
      else:
        buffer_use_size = int(options.buffer_size) or BUFFER_SIZE
    else:
      buffer_use_size = BUFFER_SIZE

    if options.flag_case:
      flags = re.I
    else:
      flags = re.DOTALL

    if not options.force and buffer_use_size < 60 * 1024 * 1024:
      logging.warning('Buffer size is smaller than 60Mb, are you sure?')
      logging.warning('Perhaps you wanted to use the keyword "m" after the number to denote Mb?')
      logging.warning('Processing cancelled, if you really want the buffer to be this small use --force option.')
      sys.exit(1)

    # If the size of the original file is smaller then the buf size, adjust it to zero (all file).
    if os.stat(options.filename).st_size < buffer_use_size:
      buffer_use_size = 0

    logging.debug('[L2t_process] Using buffer size: %d bytes', buffer_use_size)
    temp_output_name = 'l2t_sort_temp_%05d' % random.randint(1,10000)
    logging.debug('[l2t_process] Using <%s> as base name for temporary output files.', temp_output_name)

    content_filters = {}
    if options.blacklist:
      logging.warning('Building a blacklist.')
      content_filters['blacklist'] = l2t_sort.BuildKeywordList(options.blacklist, flags)

    if options.whitelist:
      logging.warning('Building a whitelist.')
      content_filters['whitelist'] = l2t_sort.BuildKeywordList(options.whitelist, flags)

    try:
      l2t_sort.ExternalSplit(f, temp_output_name, (date_filter_low, date_filter_high),
                             content_filters, csv_filters, buffer_use_size)
      l2t_sort.ExternalMergeSort(temp_output_name, output_file, plugins)
    except KeyboardInterrupt:
      logging.warning('Process killed, cleaning up.')

    # Run through the results from the plugins:
    for plugin in plugins:
      logging.info('%s', plugin.Report())
    # Delete temp files
    for name in l2t_sort.GetListOfFiles(temp_output_name):
      os.remove(name)

