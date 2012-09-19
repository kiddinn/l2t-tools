#!/usr/bin/python
"""
This is a file that holds two classes, one to represent a single line (CSV line)
and another one as a collection of lines, or a container.

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


class Error(Exception):
  """Base error handling class."""


class DuplicateLine(Error):
  """Raised when a duplicate line has been detected within a container."""


class WrongTimestamp(Error):
  """Raised when a line with the wrong timestamp is added to a container."""


class L2TLine(object):
  """An object that represents a L2T CSV line."""

  def __init__(self, timestamp, line):
    """L2TLine is an object that represents a single L2T CSV line.

    Args:
      timestamp: The constructed timestamp of the entry.
      line: The entire CSV line as a string.
    """
    self.timestamp = timestamp
    split_entries = line.split(',')
    self.macb = split_entries[3]
    self.source = split_entries[4]
    self.timestamp_desc = split_entries[6]
    self.source_long = split_entries[5]
    self.description = split_entries[10]

    # Line split up into sections
    self.line_first = ','.join(split_entries[0:12])
    self.line_last = ','.join(split_entries[15:])

    # Features that may be joined..
    self.filenames = [split_entries[12]]
    self.inodes = [split_entries[13]]
    self.notes = split_entries[14]

  def AddFile(self, filename, inode):
    """Add a file and inode to the filename list."""
    if type(filename) == str:
      if filename not in self.filenames:
        self.filenames.append(filename)
    else:
      self.filenames.extend(filename)
      for f in filename:
        if f not in self.filenames:
          self.filenames.append(f)

    if type(inode) == list:
      for i in inode:
        i = str(i)
        if i not in self.inodes:
          self.inodes.append(i)
    else:
      i = str(inode)
      if i not in self.inodes:
        self.inodes.append(i)

  def __str__(self):
    """Return the line in a string format."""
    filename = ' '.join(self.filenames)
    inode = ' '.join(self.inodes)
    return '{0},{1},{2},{3},{4}'.format(
        self.line_first, filename, inode, self.notes, self.line_last)

  def __eq__(self, other):
    if self.timestamp != other.timestamp:
      return False

    # EXIF information is limited, so this groups too many entries together.
    if self.source_long == 'EXIF metadata':
      return False

    if self.macb != other.macb:
      return False

    if self.timestamp_desc != other.timestamp_desc:
      return False

    if self.source_long != other.source_long:
      return False

    if self.description != other.description:
      return False

    return True


class L2tContainer(object):
  """A container that stores line objects."""

  def __init__(self):
    self.lines = []
    self.timestamp = 0
    self._first_new_line = None

  def AddLine(self, timestamp, new_line):
    """Check timestamps values."""
    if not self.timestamp:
      self.timestamp = timestamp

    if timestamp != self.timestamp:
      self._first_new_line = L2TLine(timestamp, new_line)
      raise WrongTimestamp('Timestamps changed.')

    # Need to check duplication.
    line_in = L2TLine(timestamp, new_line)
    for line in self.lines:
      if line == line_in:
        logging.debug('=+' * 45)
        line.AddFile(line_in.filenames, line_in.inodes)
        logging.debug('Duplicate line detected:\n%s\nvs.\n%s\n--- --- --- --- ---', line, line_in)
        raise DuplicateLine('Found a duplicate.')

    self.lines.append(line_in)

  def __iter__(self):
    for line in self.lines:
      yield line

  def __exit__(self, unused_type, unused_value, unused_traceback):
    """Make usable with "with" statement."""
    self.CloseContainer()

  def __enter__(self):
    """Make usable with "with" statement."""
    return self

  def FlushContainer(self):
    """Generator."""
    for line in self.lines:
      yield line

    self.CloseContainer()
    if self._first_new_line:
      self.lines.append(self._first_new_line)
      self._first_new_line = None

  def __len__(self):
    return len(self.lines)

  def CloseContainer(self):
    self.timestamp = 0
    self.lines = []
