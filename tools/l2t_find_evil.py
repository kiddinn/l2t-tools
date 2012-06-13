#!/usr/bin/python
# -*- coding: utf-8 -*-$
"""A simple script to compare YARA rules against l2t_csv file.

A simple script that can read in a YARA rule file and a l2t_csv file
which is the output from log2timeline and alert on any potential hits.

Usage:
  l2t_find_evil.py.py -r set_of_yara.rules -f supertimeline.csv

The tool will run each and every line of timeline against every
rule there is defined in the YARA rule file.

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
__author__ = 'kristinn@log2timeline.net (Kristinn Gudjonsson)'

import csv
import optparse
import os
import sys
import yara

DEFAULT_RULE_DIR = '/usr/local/yara/rules'
DEFAULT_RULE = 'simple.rules'


def ParseTimeLine(filehandle, yara_rules):
  """Run YARA rules against a l2t_csv timeline.

  This function will read the l2t_csv file using the CSV
  module and split each line up and only compare the YARA
  rules against the description field and the format one.

  Args:
    filehandle: A filehandle to the l2t_csv file.
    yara_rules: A full path to the YARA rule file.
  """
  try:
    rules = yara.compile(yara_rules)
  except yara.SyntaxError as e:
    print '[ERROR] Faulty YARA rule file: %s' % e
    sys.exit(2)

  print '[L2T_EVIL_FIND] Loading YARA rules: %s' % yara_rules

  reader = csv.DictReader(filehandle, delimiter=',')

  for row in reader:
    hits = rules.match(data='[%s] %s' % (row['format'], row['desc']))
    if hits:
      for hit in hits:
        meta_desc = ''

        if 'description' in hit.meta:
          meta_desc = hit.meta['description']

        if 'case_nr' in hit.meta:
          print '[%s - %s (known from case: %s)] %s %s [%s] = %s' % (
              hit.rule,
              meta_desc,
              hit.meta['case_nr'],
              row['date'],
              row['time'],
              row['timezone'],
              row['desc'])
        else:
          print '[%s - %s] %s %s [%s] = %s' % (
              hit.rule,
              meta_desc,
              row['date'],
              row['time'],
              row['timezone'],
              row['desc'])

if __name__ == '__main__':
  option_parser = optparse.OptionParser()
  option_parser.add_option('-f', '--file', '-t', '--timeline', dest='filename',
                           action='store', metavar='FILE',
                           help=('The path to the timeline that is to be'
                                 ' parsed.'))
  option_parser.add_option('-r', '--rule', dest='rulefile', action='store',
                           default='%s/%s' % (DEFAULT_RULE_DIR, DEFAULT_RULE),
                           metavar='FILE', help=('The path to the YARA'
                                                 ' extended rule file'
                                                 ' to compare against'))
  options, argv = option_parser.parse_args()

  if not options.filename:
    option_parser.error('Missing a filename')

  if not os.path.isfile(options.filename):
    option_parser.error('[%s] does not exist.' % options.filename)

  if not os.path.isfile(options.rulefile):
    option_parser.error('Rule file: [%s] does NOT exist.' % options.rulefile)

  with open(options.filename, 'rb') as f:
    ParseTimeLine(f, options.rulefile)

