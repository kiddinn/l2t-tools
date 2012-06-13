#!/usr/bin/python

import glob
import os
import sys

from distutils.core import setup

DISTUTILS_DEBUG = 'ASDF'

def GetTools():
  data = []
  for _, _, filenames in os.walk('tools/'):
    for filename in filenames:
      if '.py' in filename and filename != '__init__.py':
        if os.path.isfile(os.path.join('tools', filename)):
          data.append(os.path.join('tools', filename))

  return data

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
                'l2t_tools.lib'])


