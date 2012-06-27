#!/usr/bin/python
"""
This is a simple plugin that does the same deal as the l2t_find_evil.py script does.
It loads up a YARA rule file and runs it against each line in the CSV file and if there
is a match it will fire up an alert.

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
import re
import os
import yara

from l2t_tools.lib import plugin

__author__ = 'Kristinn Gudjonsson (kristinn@log2timeline.net)'
__version__ = '0.1'


class YaraMatch(plugin.L2tPlugin):
  """Count the number of lines that contain a file inside System32."""

  def __init__(self, separator, rule_file):
    """Constructor.

    Args:
      separator: The CSV file separator, usually a comma or a tab.
      rule_file: The path to a YARA rule file.

    Raises:
      IOError: If the YARA rule file does not exist.
    """
    if not os.path.isfile(rule_file):
      raise IOError('The YARA rule file does not exist.')

    super(YaraMatch, self).__init__(separator)
    self.rules = yara.compile(rule_file)
    logging.info('Plugin: YaraMatch Turned ON.')
    self.alerts = []

  def AppendLine(self, entries):
    """Appends a line to this plugin.

    This function should begin with evaluating the line to see
    if it fits into the plugins spear of interest. If it does
    some processing takes place here.

    Args:
      entries: A list of two entries, timestamp and the full line.
    """
    _, line = entries
    columns = line.split(self.separator)

    hits = self.rules.match(data='[%s] %s' % (columns[15], columns[10]))
    if hits:
      for hit in hits:
        meta_desc = hit.meta.get('description', '')

        meta_case = ''
        if 'case_nr' in hit.meta:
          meta_case = ' (known from case: %s)' % hit.meta['case_nr']

        self.alerts.append('[%s - %s%s] %s %s [%s] = %s' % (
            hit.rule,
            meta_desc,
            meta_case,
            columns[0],
            columns[1],
            columns[2],
            columns[10]))

  def Report(self):
    """Return a report of findings.

    Returns:
      A string containing the results of the plugin.
    """
    append_string = ''
    for alert in self.alerts:
      append_string += '\n\t%s' % alert

    if append_string:
      return 'YARA rule matches: %d.%s' % (len(self.alerts), append_string)
    else:
      return 'YARA rule matches: None found, have a nice day.'
