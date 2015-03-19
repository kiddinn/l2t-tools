#A cross-platform GUI tool for reviewing log2timeline data

# Introduction #

l2t\_Review (l2t\_R) is a GUI tool for reviewing log2timeline data. Using L2t\_R a user can import one or many log2timeline CSV files into a SQLite database. You can then use l2t\_R's GUI to filter, highlight, sort, tag, bookmark, and search on common log2timeline data fields. Included are basic reporting features as well as the ability to export subsets of data back into the CSV format.

# l2t Design #

The application design consists of the following three main components:

  1. Application: Python 2.7
  1. GUI: WX 2.9
  1. Back-end: SQLite

# Before you get started #

## Dependencies (compiling from source) ##

l2t\_R has been tested to run on Windows XP (x86), Windows 7 (x64/x86), and OSX. The following Python 2.7 (32-bit) module dependencies must be installed on your system if compiling from source. Note specific versions listed are required.

  1. [WXpython 2.9](http://www.wxpython.org/download.php)
  1. [numpy 1.6.2](http://sourceforge.net/projects/numpy/files/matplotlib)
  1. [matplotlib-1.1.1](http://sourceforge.net/projects/matplotlib/files/matplotlib/matplotlib-1.1.1/)

## Launching the application (compiling from source) ##

Edit l2t\_R.py to include PYTHONPATH of your l2t\_R directory:

```
##Set PYTHONPATH variable
sys.path.append('C:/Users/Nides/Documents/l2t_R/')
```

Launch l2t\_R from the cmd line:

```
c:\path_to_utility>python2.7 /tools/l2t_R.py
```

Alternatively, open /tools/l2t\_R.py with IDLE (Python GUI) and select File > Run Module (F5) to launch l2t\_R.

## Launching the application (from binary) ##

**Windows**

  1. Extract Zip archive
  1. Double click on l2t\_Review.exe

**OSX**

  1. Double click on l2t\_R.app
  1. Change permission on l2t\_R.app to make executable:

```
Spica:Desktop davnads$ cd l2t_R.app/Contents/MacOS/ 
Spica:MacOS davnads$ chmod 777 *
```

# Getting Started #

## Import l2t CSV and create l2t\_R Database ##

After successfully launching l2t\_R, the first step is to create a l2t\_R database. This is done by selecting a l2t CSV file and importing the data into a user created l2t\_R database:

  1. File > Create DB from l2t CSV
  1. Select l2t CSV file
  1. Enter DB name and save path
  1. Select DB fields to index. At minimum it is suggested the following fields are used (in bold required): date, time, MACB, host, source, sourcetype, **datetime**, reportnotes, inreport, tag, and **key**. Note the more fields indexed the better performance will be, however the size of the database will increase.

While the database is being created there will be a loading dialog. At anytime a user can check the size of the database on the filesystem and should see the logical size grow. Upon completion you will receive a dialog window with some statistics about the database.

## Open Database ##

Open new or existing l2t\_R database:

  1. Open > Open DB

## Import additional l2t CSV to l2t\_R Database ##

To add additional l2t CSV files to the open database:

  1. File > Append l2t CSV to DB

## Introduction to the Layout panes ##

There are 8 independent panes that make up the overall User Interface (UI). Each pane can be detached from the main UI and repositioned. This can be useful when using multiple displays. Below is a summary of each pane part of the application.

Filtering: SQLite query builder to create criteria and logic for filtering database on one or many fields including log2timeline fields, date/time ranges, and/or keywords. Additionally user can define to enhance filtered data with color-codes based on host or type values.

Data Grid Display: Displays timeline data subsequent to Filtering. User can select columns and resize, sort, or re-order. Additionally user can right click column heading to hide columns. In data grid user can right click to hide and highlight row(s) amongst other features.

All Datetime Activity: Displays all (not paged) timeline data visually subsequent to filtering. The X axis represents Date and Y axis represents frequency of event(s). By design, the chart will not add zeros in date gaps larger than 30 days. If a user clicks on a value, it will automatically update the filtering criteria to reflect only the date clicked.

Display Controls: Button controls for paging through timeline data 1000 rows at a time in Data Grid Display. Additionally, the SQLite query used to filter data and number of rows returned are displayed here and can be edited for custom queries.

Detail View: Double clicking on any row in the Data Grid Display with open a pop up display with information for the currently selected row. This feature reduces the need to scroll horizontally to seek additional details about an event. Once opened, the detail view is locked and will be updated automatically every time a new row is selected.

Reviewer: For one or many selected rows, insert a tag(s), comment, or bookmark.

Custom SQLite Query: Create a custom SQLite query or select saved queries from a plugin file.

Dashboard: Visually display filtered data in interactive pie charts that can be clicked to filter.

## Dashboard Filtering ##

View > Dashboard Filtering

Window gives user the ability to view timeline data in an interactive dashboard subsequent to filtering. This allows you to understand visually what data types are being displayed in your timeline. If there is something that is specifically interesting, such as data from user “John”, if you click on “John” in the pie chart it will automatically redefine your results in the Data Grid View to only show data associated with the user “John”. All pie charts are interactive in the sense you can click on data points and filter the data.

## Reporting ##

Below is an overview of the reporting options.

Report > Create Database Report

Save text file with basic information about the timeline including start and end dates, frequency of source types, list of hosts, list of users, and etc.

Report > Bookmark Report

Save all rows in database marked as Bookmarked to l2t CSV format.

Report > Export Current Page to CSV

Subsequent to filtering, save current page only in data grid view to l2t CSV format.

Report > Export all Pages to CSV

Subsequent to filtering, save all pages in data grid view to l2t CSV format.

## Mounting Image ##

  1. Mount disk image with tool of choice (e.g. imdisk, ftkimager, encase)
  1. Specify in l2t\_R what drive letter is assigned to the mounted disk image in Settings > Image path

### File Viewer ###

Windows version Only. Requires download and installation of [Universal Viewer](http://www.uvviewsoft.com). After mounting image:

  1. Invoke File Viewer by Right Clicking on any line item in your timeline and selecting Open File Viewer
  1. The File Viewer is automatically opened with the file. You can change default view mode (native, hex, text, etc.) using settings. You can also specify in settings whether you want multiple instance of file viewer to be opened simultaneously or not. So every time you open a new file it will either open it in the same instance or a new instance.

### File Hashing ###

After mounting image:

  1. Invoke File Hashing by Right Clicking on any line item in your timeline and selecting Open File Viewer

## Custom Color-Codes ##

Documentation Coming Soon...

## Custom Queries ##

Documentation Coming Soon...



# References #

  * [Timeline Analysis - What's missing & What's coming..](http://davnads.blogspot.com/2012/07/timeline-analysis-whats-missing-whats.html)

  * [SANS DFIR Summit 360 recorded video (1:06:38 mark)](http://www.livestream.com/sansinstitute/video?clipId=pla_5706fd65-e4c3-4503-9af9-4213347687a7&utm_source=lslibrary&utm_medium=ui-thumb)

  * [Review of l2t\_Review by Corey Harrell](http://journeyintoir.blogspot.com/2012/08/linkz-for-tools.html?m=1)



# Q&A #

## How does CSV importing work? ##

First l2t\_R validates the CSV input file contains the log2timeline CSV header:

`date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra`

l2t\_R will then use the Python CSV parser to recursively read each line, formatting it and checking for errors. For every successfully read line, a transaction is made to the SQLite database.

If an error or exception occurs l2t\_R will try to log this in a file (.log) in the source directory. Common errors include fields that contain too many characters, missing fields, and new line characters.


## How do I adjust the number of chars displayed in data grid view fields ##

log2timeline fields can potentially contain 32000 or more characters. This is common with the prefetch parser or if log2timeline in run using the "Detail" flag.

Trying to display 3200 or more characters in l2t\_R's GUI can make the application slow or unresponsive. Therefore l2t\_R includes a user configurable variable that limits the number of items displayed for each field in the data grid view. By default this is set to 320. This variable can be easily changed in the gridview.py file:

model.py
```
# the maximum characters to display for a column
max_dis_char = 60
```


## How do I create a l2l\_R EXE? ##

1. Install py2exe and Gui2exe

**py2exe - http://sourceforge.net/projects/py2exe/files/py2exe/0.6.9/**

**Gui2exe - http://code.google.com/p/gui2exe/downloads/detail?name=GUI2Exe_0.5.3.zip&can=2&q=**

2. Start a new project in Gui2exe, configure for py2exe. specify l2l.py as the main script.

3. Include the following Python Modules:

**wx**numpy
**matplotlib**

4. Export the setup.py into our l2t\_R root directory.

5. In order to make matplotlib working, edit setup.py like this:

data\_files = matplotlib.get\_py2exe\_datafiles()

and add 'matplotlib.backends.backend\_wxagg' in 'includes'.

6. Download the msvcp90.dll on the web, and put it in C:\Python2.7\DLLs

msvcp90.dll - http://www.down-dll.com/index.php?file-download=msvcp90.dll&dsc=Microsoft%AE-C++-Runtime-Library#

7. Open cmd and move to l2t\_R/tools directory and run:

python.exe ../setup.py py2exe

8. Copy l2l.jpg into the dist\ directory created. (You could also specify this data file when configuring Gui2exe)

9. The generated executable is in dist\. before running the l2l.exe,

10. Double click l2l.exe and run.