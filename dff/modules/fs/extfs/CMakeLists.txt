# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
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
#  Romain Bertholon <rbe@digital-forensic.org>


dff_cpp_module(EXTFS
  CPP_FILES extfs.cpp 
  Directory.cpp 
  SymLink.cpp 
  Journal.cpp 
  JournalType.tpp 
  FileNameRecovery.cpp
  CustomResults.cpp
  CustomAttrib.cpp
  fsck.cpp
  FsStat.cpp
  InodeStat.cpp
  JournalStat.cpp
  InodesList.cpp
  InodeUtils.cpp
  SuperBlockUtils.cpp
  ExtfsNode.cpp
  ExtfsSlackNode.cpp
  ExtfsRawDataNode.cpp
  ExtfsSymLinkNode.cpp
  BlkList.cpp
  MfsoAttrib.cpp
  Option.cpp
  OrphansInodes.cpp
  data_structure/InodeStructure.cpp
  data_structure/SuperBlock.cpp
  data_structure/GroupDescriptor.cpp
  data_structure/Inode.cpp
  data_structure/DirEntry.cpp
  data_structure/SuperBlockStructure.cpp
  data_structure/ExtendedAttr.cpp
  data_structure/Ext4Extents.cpp
  SWIG_FILE extfs.i
  LINK_LIBRARIES exceptions types vfs tree
  INCLUDE_DIRS ${CMAKE_HOME_DIRECTORY}/dff/api/tree
)
