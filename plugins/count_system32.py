#!/usr/bin/python
"""
An example test class for simple tests against the plugin infrastructure, not
meant to provide any meaningful results nor any other value to the analysis.

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

from l2t_tools.lib import plugin

__author__ = 'Kristinn Gudjonsson (kristinn@log2timeline.net)'
__version__ = '0.1'


class System32Count(plugin.L2tPlugin):
  """Count the number of lines that contain a file inside System32."""

  def __init__(self, separator):
    super(System32Count, self).__init__(separator)

    logging.info('Plugin: CountSystem32 Turned ON.')
    self.system32 = re.compile('.*/(Windows|WINNT)\/system32\/.*', re.I)
    self.counter = 0

  def AppendLine(self, line):
    """Appends a line to this plugin.

    This function should begin with evaluating the line to see
    if it fits into the plugins spear of interest. If it does
    some processing takes place here.

    Args:
      line: A list of two entries, timestamp and the full line.

    Raises:
      NotImplementedError: When not implemented.
    """

    columns = self.IsInputModule(line[1], 'Log2t::input::mft')

    if columns:
      if self.system32.match(columns[10]):
        self.counter += 1

  def Report(self):
    """Return a report of findings.

    Returns:
      A string containing the results of the plugin.

    Raises:
      NotImplementedError: When not implemented.
    """
    return 'Total number of entries stored inside the System32: %d' % self.counter
