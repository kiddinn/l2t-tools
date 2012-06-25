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

import argparse 
import csv
import os
import sys
import yara

DEFAULT_RULE_DIR = '/usr/local/yara/rules'
DEFAULT_RULE = 'all.rules'


def ParseTimeLine(filehandle, yara_rules, delim=','):
  """Run YARA rules against a l2t_csv timeline.

  This function will read the l2t_csv file and compare
  YARA rules against the name of the input module and
  description field of the CSV file.

  Args:
    filehandle: A filehandle to the l2t_csv file.
    yara_rules: A full path to the YARA rule file.
    delim: A string containing the delimitor for the l2t_csv
    file (can be a comma or a tab for instance).
  """
  try:
    rules = yara.compile(yara_rules)
  except yara.SyntaxError as e:
    print '[ERROR] Faulty YARA rule file: %s' % e
    sys.exit(2)

  print '[L2T_EVIL_FIND] Loading YARA rules: %s' % yara_rules

  reader = csv.DictReader(filehandle, delimiter=delim)

  for row in reader:
    hits = rules.match(data='[%s] %s' % (row['format'], row['desc']))
    if hits:
      for hit in hits:
        meta_desc = hit.meta.get('description', '')

        meta_case = ''
        if 'case_nr' in hit.meta:
          meta_case = ' (known from case: %s)' % hit.meta['case_nr']

        print '[%s - %s%s] %s %s [%s] = %s' % (
            hit.rule,
            meta_desc,
            meta_case,
            row['date'],
            row['time'],
            row['timezone'],
            row['desc'])

if __name__ == '__main__':
  base = os.path.basename(sys.argv[0])
  usage = ('Automate your timeline analysis using YARA signature matching. '
           '%s assists you with quickly going over your timeline and automatically'
           ' scan for known interesting or "evil" entries within it.' % base)

  option_parser = argparse.ArgumentParser(description=usage)

  option_parser.add_argument('-f', '--file', '-t', '--timeline', dest='filename',
                             action='store', metavar='FILE',
                             help=('The path to the timeline that is to be'
                                 ' parsed.'))
  option_parser.add_argument('--tab', dest='tabfile', action='store_true',
                             default=False,
                             help='This is a tab delimited file, not a CSV one.')
  option_parser.add_argument('-r', '--rule', dest='rulefile', action='store',
                             default='%s/%s' % (DEFAULT_RULE_DIR, DEFAULT_RULE),
                             metavar='RULE', help=('The path to the YARA'
                                                   ' extended rule file'
                                                   ' to compare against'))
  options = option_parser.parse_args()

  limiter = ','
  if options.tabfile:
    limiter = '\t'

  if not options.filename:
    option_parser.error('Missing a filename')

  if not os.path.isfile(options.filename):
    option_parser.error('[%s] does not exist.' % options.filename)

  if not os.path.isfile(options.rulefile):
    option_parser.error('Rule file: [%s] does NOT exist.' % options.rulefile)

  with open(options.filename, 'rb') as f:
    ParseTimeLine(f, options.rulefile, limiter)

