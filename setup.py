#!/usr/bin/python
"""
This is the setup file for the project. The standard setup rules apply:

  python setup.py build
  sudo python setup.py install

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
import glob
import os
import sys

from distutils.core import setup

def GetTools():
  """List up all scripts that should be runable from the command line."""
  data = []
  for _, _, filenames in os.walk('tools/'):
    for filename in filenames:
      if '.py' in filename and filename != '__init__.py':
        if os.path.isfile(os.path.join('tools', filename)):
          data.append(os.path.join('tools', filename))

  return data

def GetAllYaraRules():
  """Return all the default Yara rules for l2t_find_evil.py."""
  yara_rules = []
  basepath = os.path.join('data', 'rules')
  for filename in glob.glob('%s/*.rules' % basepath):
    yara_rules.append(os.path.join(basepath, filename))

  return yara_rules

setup(name='L2t Tools',
      version='0.1',
      description='Various tools to work with the output from log2timeline.',
      author='Kristinn Gudjonsson',
      author_email='kristinn@log2timeline.net',
      license='GNU GPL v3',
      url='https://code.google.com/p/l2t-tools',
      package_dir={'l2t_tools': '../l2t-tools'},
      scripts=GetTools(),
      packages=['l2t_tools',
                'l2t_tools.lib',
                'l2t_tools.plugins'],
      package_data={'l2t_tools': GetAllYaraRules()},
     )


