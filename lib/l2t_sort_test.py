#!/usr/bin/python
# -*- coding: utf-8 -*-
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
import unittest
import tempfile

from l2t_tools.lib import l2t_sort

__author__ = 'Kristinn Gudjonsson (kristinn@log2timeline.net)'
__version__ = '0.1'


class L2tLibTest(unittest.TestCase):
  """A unit test for the l2t_sort library."""


  def setUp(self):
    """Small initial settings."""
    self._base = os.path.join('l2t_tools', 'test_data')
    self._tempfile = os.path.join('test_data', 'testfile.txt')
    self._fh = open(self._tempfile, 'rb')
    self._random = tempfile.mktemp()

  def testExternalSplit(self):
    l2t_sort.ExternalSplit(self._fh, self._random, (None, None), [], [], 0)
    self.assertTrue(os.path.isfile('%s.%05d' % (self._random, 1)))
    self.assertFalse(os.path.isfile('%s.%05d' % (self._random, 2)))

  def testFlushBuffer(self):
    test_buffer = []
    test_buffer.append((123, 'Some text\n'))
    test_buffer.append((124, 'What text?\n'))
    test_buffer.append((125, 'Another text\n'))
    test_buffer.append((125, u'Texti á öðru tungumáli.\n'))

    #terminal 1 - gate 32 
    #terminal 3 - gate 83
    my_temp = tempfile.mktemp()
    l2t_sort.FlushBuffer(test_buffer, 1, my_temp)

    self.assertTrue(os.path.isfile('%s.%05d' % (my_temp, 1)))
    with open('%s.%05d' % (my_temp, 1)) as fh:
      # do stuff
      self.assertEquals(fh.readline(), '123,Some text\n')
      self.assertEquals(fh.readline(), '124,What text?\n')
      self.assertEquals(fh.readline(), '125,Another text\n')
      self.assertEquals(fh.readline(), u'Texti á öðru tungumáli.\n')

  def testFilterOut(self):
    #test, date_filters, content_filters={}, plugin_filters=[]):
    self.assertEquals(1, 1)

  def testExternalMergeSort(self):
    #in_file_str, out_file, plugins):
    self.assertEquals(1, 1)

  def testProcessLine(self):
    #new_line, last_line, output, duplicates, plugins):
    self.assertEquals(1, 1)

  def testIsADuplicate(self):
    #line_a, line_b):
    self.assertEquals(1, 1)

  def testGetListOfFiles(self):
    #in_file_str):
    self.assertEquals(1, 1)

  def testBuildKeywordList(self):
    #in_file_str, flags):
    self.assertEquals(1, 1)

  def testDuplicateLines(self):
    """Test the duplicate line detection using both simple and complex mechanism."""
    file_path = os.path.join(self._base, 'duplicate_entries.csv')
    # File contains 6 lines in total.
    #   2 of which are exact copies.
    #   2 of which are near copies.
    # Simple collection should return 5 lines.
    # Standard collection should return 4 lines.
    fh = open(file_path, 'rb')
    l2t_sort.ExternalSplit(fh, self._random, (None, None), [], [], 0)
    # Use with to create temporary folder, finish the split
    # Call the merge, and store results in a buffer.
    # Check the length of the buffer.


  def tearDown(self):
    self._fh.close()
    for f in l2t_sort.GetListOfFiles(self._random):
      os.remove(f)

if __name__ == '__main__':
  unittest.main()
