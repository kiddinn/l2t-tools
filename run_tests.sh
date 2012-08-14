#!/bin/bash

# A simple way to run all scripts.
export PYTHONPATH="."

# To make sure we can load up everything.
ln -s ../l2t-tools l2t_tools

# Run the tests.
python ./l2t_tools/lib/l2t_sort_test.py
python ./l2t_tools/lib/lines_test.py

# Remove the shortcut.
rm -f l2t_tools
