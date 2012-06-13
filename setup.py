#!/usr/bin/python

import glob
import os

from distutils.core import setup

def FindYaraRules():
  for filename in os.walk('data/rules'):
    if '.rules' in filename:
      yield filename

yara_rules = []
for rule in FindYaraRules():
  yara_rules.append(rule)

setup(name='L2t Tools',
      version='0.1',
      description='Various tools to work with the output from log2timeline.',
      author='Kristinn Gudjonsson',
      author_email='kristinn@log2timeline.net',
      license='GNU GPL v3',
      url='https://code.google.com/p/l2t-tools',
      package_dir={'l2t_tools': '../l2t-tools'},
      packages=['l2t_tools',
                'l2t_tools.lib'])


