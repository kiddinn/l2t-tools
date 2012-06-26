#!/usr/bin/python
"""
A simple plugin that checks for the existence of an executable in a Temp directory.
A temp directory is a directory that has the name of "/tmp/" or "/temp/".

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


class WinExeInTemp(plugin.L2tPlugin):
  """Count the number of lines that contain a file inside System32."""

  EXE_TEMP = re.compile('/temp/.*.exe', re.I)
  MODULES = ('Log2t::input::evt',
             'Log2t::input::evtx',
             'Log2t::input::prefetch',
             'Log2t::input::mft',
             'Log2t::input::exif',
             'Log2t::input::symantec',
             'Log2t::input::win_link',
             'Log2t::input::ftk_dirlisting',
             'Log2t::input::mactime',
             'Log2t::input::mcafee')

  def __init__(self, separator):
    super(WinExeInTemp, self).__init__(separator)

    logging.info('Plugin: ExeInTemp Turned ON.')
    self.exes = []

  def AppendLine(self, entries):
    """Appends a line to this plugin.

    This function should begin with evaluating the line to see
    if it fits into the plugins spear of interest. If it does
    some processing takes place here.

    Args:
      entries: A list of two entries, timestamp and the full line.
    """

    _, line = entries
    columns = self.IsInputModules(line, self.MODULES)

    if self.EXE_TEMP.search(line):
      logging.info('Found a hit: %s', line)
    if columns:
      logging.info('Into columns you say....:%s - %s', columns[15], columns[10])
      if self.EXE_TEMP.search(columns[10]):
        self.exes.append(columns[10])

  def Report(self):
    """Return a report of findings.

    Returns:
      A string containing the results of the plugin.
    """
    append_string = ''
    for exe in self.exes:
      append_string += '\n\t%s' % exe

    if append_string:
      return 'WinExe in Temp Directory Results:\n\tTotal entries found: %d\n%s' % (len(self.exes), append_string)
    else:
      return 'WinExe in Temp: None found, have a nice day.'
