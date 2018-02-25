# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
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
#  Frederic Baguelin <fba@digital-forensic.org>


dff_cpp_module(CARVER
  CPP_FILES carver.cpp
  INCLUDE_DIRS ${CMAKE_HOME_DIRECTORY}/dff/api/search/
  LINK_LIBRARIES exceptions types vfs
  SWIG_FILE carver.i
  EXTRA_FILES __init__.py carvergui.py carverui.py predef.py userdef.py process.py typeSelection.py utils.py
)
