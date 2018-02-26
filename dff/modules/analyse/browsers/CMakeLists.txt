# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
# This program is free software, distributed under the terms of
# the GNU General Public License Version 2. See the LICENSE file
# at the top of the source tree.
#  
# See http://www.digital-forensic.org for more information about this
# project. Please do not directly contact any of the maintainers of
# DFF for assistance; the project provides a web site, mailing lists
# and IRC channels for your use.
# 
# Author(s):
#  Jeremy MOUNIER <jmo@digital-forensic.org>


add_subdirectory (viewer)

install_file(
  __init__.py
  browser.py
  firefox.py
  opera.py
  internetexplorer.py
  chrome.py
  mork.py
#  queries.py
  browsers.py
  history.py
  inputhistory.py
  config.py
  dtime.py
)
