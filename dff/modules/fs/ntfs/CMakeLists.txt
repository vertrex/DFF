# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2011 ArxSys
#
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
#  Solal Jacob <sja@digital-forensic.org>

include_directories(${ICU_INCLUDE_DIRS})


dff_cpp_module(ntfs
  CPP_FILES ntfs.cpp
  ntfsopt.cpp
  bootsector.cpp
  mftentrynode.cpp
  mftattribute.cpp
  mftattributecontent.cpp
  mftnode.cpp
  mftmanager.cpp
  unallocated.cpp

  attributes/standardinformation.cpp
  attributes/filename.cpp
  attributes/attributelist.cpp
  attributes/volume.cpp
  attributes/objectid.cpp
  attributes/indexroot.cpp
  attributes/indexallocation.cpp
  attributes/indexentry.cpp
  attributes/data.cpp
  attributes/bitmap.cpp
  attributes/reparsepoint.cpp
  SWIG_FILE ntfs.i
  INCLUDE_DIRS ${ICU_INCLUDE_DIRS}
  LINK_LIBRARIES ${ICU_LIBRARIES} exceptions types vfs
)
