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


if(WIN32)
  set(definitions -DHAVE_INT8_T -DHAVE_STDINT_H -DLIBBDE_HAVE_BFIO -D_LIBBDE_TYPES_H_INTEGERS -D_LIBBFIO_TYPES_H_INTEGERS)
endif()

dff_cpp_module(BITLOCKER
  CPP_FILES bitlocker.cpp bitlockernode.cpp
  SWIG_FILE bitlocker.i
  DEFINITIONS ${definitions}
  LINK_LIBRARIES exceptions types vfs ${LIBBDE_LIBRARY}
  INCLUDE_DIRS ${LIBBDE_INCLUDE_DIR} ${LIBBFIO_INCLUDE_DIR}
  )
