# Introduction #

There is no real content here as of now... but there will be.

The current version of the l2t\_process.py that is supplied here (as of 06/13/2012) is experimental and should be used as such (that is no warranty of it's quality/everything).

# Details #

This is a complete rewrite from the Perl version of the tool, l2t\_process, that is currently distributed with log2timeline. Therefore it is missing some of it's features as of now. However since this is a complete rewrite it should be done "better", that is the new version is changing the entire way l2t\_process works in order to be more memory efficient and "stable".

The usage of the tool can be determined by running **l2t\_process.py -h** or read here:
```
Usage: 
l2t_process.py [OPTIONS] -b CSV_FILE [DATE_RANGE]

Where DATE_RANGE is MM-DD-YYYY or MM-DD-YYYY..MM-DD-YYYY

Options:
  -h, --help            show this help message and exit
  -b FILE, --file=FILE, --bodyfile=FILE
                        The input CSV file.
  --buffer-size=BUFFER_SIZE, --bs=BUFFER_SIZE
                        The size of the buffer used for external sorting.
  -d, --debug           Turn on debug information.
  -t, --tab             The input file is TAB delimited.
  --chunk_size=CSIZE    The default chunk size for external sorting.
  -o FILE, --output=FILE
                        The output file
```

The current version (again as of 06/13/2012) does only basic sorting and date filtering. It also only works against l2t\_csv (so not tab delimited files, an easy fix though).

## Differences Between This Version and the Old One ##

Some of the highlights are:
  * Instead of reading EVERY line in memory and then sort it splits the file in chunks, sorts each chunk, and then uses sort/merge to get the final sorted version. This in turns makes it write several files to disk (since that is how it stores the chunks before moving on to the next one). The default chunk size is 256 Mb, changeable by the --bs parameter to the tool.
  * _Advanced_ processing, like the scatter plots for outlier detection is (or will be) done in plugins, making the tool modular in approach when it comes to processing/analyzing.
  * Should be faster and more memory efficient (should be as is that is the goal and entire reason for this work in the first place).