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

dff_cpp_module(FATFS
  CPP_FILES fatfs.cpp bootsector.cpp fat.cpp fattree.cpp entries.cpp
  SWIG_FILE fatfs.i
  LINK_LIBRARIES ${ICU_LIBRARIES} exceptions types vfs tree
  INCLUDE_DIRS ${ICU_INCLUDE_DIRS} ${CMAKE_HOME_DIRECTORY}/dff/api/tree
)
