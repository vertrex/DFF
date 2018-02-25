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
#  Solal Jacob <sja@digital-forensic.org>

IF (${AFF_VERSION} VERSION_GREATER "3.6.6")
  set(definitions -DNEW_AFF_LIB)
ENDIF(${AFF_VERSION} VERSION_GREATER "3.6.6")

if(WIN32)
  set(aff_files ${AFF_DYN_LIBRARIES})
endif(WIN32)

dff_cpp_module(AFF
  CPP_FILES aff.cpp affnode.cpp
  SWIG_FILE aff.i
  INCLUDE_DIRS ${AFF_INCLUDE_DIR}
  LINK_LIBRARIES exceptions types vfs ${AFF_LIBRARY}
  DEFINITIONS ${definitions}
  EXTRA_FILES ${aff_files}
  )
