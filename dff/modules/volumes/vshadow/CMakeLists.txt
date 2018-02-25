# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2014 ArxSys
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


if(WIN32)
  set(definitions -DHAVE_INT8_T -DLIBVSHADOW_HAVE_BFIO -D_LIBVSHADOW_TYPES_H_INTEGERS -D_LIBBFIO_TYPES_H_INTEGERS)
endif()

dff_cpp_module(VSHADOW
  CPP_FILES vshadow.cpp
  SWIG_FILE vshadow.i
  DEFINITIONS ${definitions}
  LINK_LIBRARIES exceptions types vfs ${LIBVSHADOW_LIBRARY}
  INCLUDE_DIRS ${LIBVSHADOW_INCLUDE_DIR} ${LIBBFIO_INCLUDE_DIR}
  EXTRA_FILES ${LIBVSHADOW_RUNTIME_LIBRARY}
  )
