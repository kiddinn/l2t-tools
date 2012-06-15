#!/usr/bin/python
"""
This is the base class for the plugin based approach to more 'advanced' processing
of l2t_csv files.

Each plugin needs to implement this class.

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

__author__ = 'Kristinn Gudjonsson (kristinn@log2timeline.net)'
__version__ = '0.1'

class L2tPlugin(object):
  """This is the base class for the plugin infrastructure."""

  def __init__(self, separator):
    self.separator = separator

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
    raise NotImplementedError

  def Report(self):
    """Return a report of findings.

    Returns:
      A string containing the results of the plugin.

    Raises:
      NotImplementedError: When not implemented.
    """
    raise NotImplementedError

  def IsInputModule(self, line, module):
    """Returns an array of each element if this belongs to the right module.

    Args:
      line: A string containing the entire line.
      module: The name of the module to check against.

    Returns:
      None or a list of entries inside the line.
    """
    columns = line.split(self.separator)
    if module in columns[15]:
      return columns
    
    return None
