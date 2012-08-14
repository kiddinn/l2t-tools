#!/usr/bin/python
"""
This is a unit test for the lines classes (container and a line).

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

import unittest

from l2t_tools.lib import lines


class LinesTest(unittest.TestCase):
  """A simple unit test for the line container and object."""

  def setUp(self):
    """Set up the needed object.

    We have four lines in total:
      line1: Original line.
      line2: Different time and content than line1.
      line3: Same content as line 1, just different file/inode
      (should be classified as the same as line1)
      line4: Same line as line2, except uses the same time as line1.
    """
    self.line1 = ("""\
01/22/2012,07:52:33,UTC,MACB,LOG,Syslog,Entry Written,-,-,\
[myhostname.myhost.com] Reporter <client> PID: 30840 (INFO \
No new content.),[myhostname.myhost.com] Reporter <client> PID: \
30840 (INFO No new content.),2,mysyslog,123,-,Log2t::input::syslog,-""")
    self.timestamp1 = 20120122075233
    self.line2 = ("""\
01/22/2012,07:52:45,UTC,MACB,LOG,Syslog,Entry Written,-,-,\
[myhostname.myhost.com] Reporter <client> PID: 30840 (INFO No \
change in [/etc/netgroup]. Done),[myhostname.myhost.com] Reporter \
<client> PID: 30840 (INFO No change in [/etc/netgroup]. Done),2,\
mysyslog,123,-,Log2t::input::syslog,-""")
    self.timestamp2 = 20120122075245
    self.line3 = ("""\
01/22/2012,07:52:33,UTC,MACB,LOG,Syslog,Entry Written,-,-,\
[myhostname.myhost.com] Reporter <client> PID: 30840 (INFO \
No new content.),[myhostname.myhost.com] Reporter <client> PID: \
30840 (INFO No new content.),2,othersyslog,128,-,Log2t::input::syslog,-""")
    self.line4 = ("""\
01/22/2012,07:52:33,UTC,MACB,LOG,Syslog,Entry Written,-,-,\
[myhostname.myhost.com] Reporter <client> PID: 30840 (INFO No \
change in [/etc/netgroup]. Done),[myhostname.myhost.com] Reporter \
<client> PID: 30840 (INFO No change in [/etc/netgroup]. Done),2,\
mysyslog,123,-,Log2t::input::syslog,-""")
    self.line_should_be = ("""\
01/22/2012,07:52:33,UTC,MACB,LOG,Syslog,Entry Written,-,-,\
[myhostname.myhost.com] Reporter <client> PID: 30840 (INFO \
No new content.),[myhostname.myhost.com] Reporter <client> PID: \
30840 (INFO No new content.),2,mysyslog othersyslog,123 128,-,\
Log2t::input::syslog,-""")

  def testLine(self):
    """Do a simple test for the line objects."""
    line1 = lines.L2TLine(self.timestamp1, self.line1)
    line2 = lines.L2TLine(self.timestamp2, self.line2)
    line3 = lines.L2TLine(self.timestamp1, self.line3)

    self.assertEquals(line1.timestamp, self.timestamp1)
    self.assertEquals(line2.timestamp, self.timestamp2)
    self.assertEquals(str(line1), self.line1)
    self.assertEquals(str(line2), self.line2)

    # Append a filename.
    line1.AddFile('othersyslog', 128)
    self.assertEquals(str(line1), self.line_should_be)

    self.assertFalse(line1 == line2)
    self.assertTrue(line1 == line3)

    # Append a filename that is already there (should remain the same).
    line1.AddFile('othersyslog', 128)
    self.assertEquals(str(line1), self.line_should_be)

  def testContainer(self):
    """Test L2tContainer with various operations against it."""
    container = lines.L2tContainer()

    container.AddLine(self.timestamp1, self.line1)
    self.assertEquals(len(container), 1)

    self.assertRaises(lines.WrongTimestamp, container.AddLine, self.timestamp2, self.line2)
    container.AddLine(self.timestamp1, self.line4)
    self.assertEquals(len(container), 2)

    # Add line2, which should raise the "the same" flag.
    self.assertRaises(lines.DuplicateLine, container.AddLine, self.timestamp1, self.line3)

    all_lines = list(container.FlushContainer())
    self.assertEquals(len(all_lines), 2)

    self.assertEquals(str(all_lines[0]), self.line_should_be)
    self.assertEquals(str(all_lines[1]), self.line4)


if __name__ == '__main__':
  unittest.main()
