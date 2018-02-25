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

if (LIBARCHIVE_FOUND)
  message(STATUS "Archive library found")
  dff_cpp_module(decompressor
    CPP_FILES decompressor.cpp decompressornode.cpp
    SWIG_FILE decompressor.i
    INCLUDE_DIRS ${ICU_INCLUDE_DIRS} ${LIBARCHIVE_INCLUDE_DIR}
    LINK_LIBRARIES ${ICU_LIBRARIES} exceptions types vfs ${LIBARCHIVE_LIBRARY}
    EXTRA_FILES ${LIBARCHIVE_RUNTIME_LIBRARIES}
    )
else (LIBARCHIVE_FOUND)
  message(STATUS "Archive library not found")
endif (LIBARCHIVE_FOUND)
