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
#  Solal Jacob <sja@digital-forensic.org>


set(vfs_src 
   rc.cpp 
   tags.cpp 
   node.cpp 
   vlink.cpp 
   vfile.cpp 
   vfs.cpp 
   fso.cpp 
   mfso.cpp 
   filemapping.cpp 
   fdmanager.cpp 
   cache.cpp 
   iostat.cpp 
   rootnode.cpp)

if (LIBBFIO_FOUND)
 set(vfs_src ${vfs_src} libbfio_wrapper.cpp)
 if(WIN32)
  set(definitions -DHAVE_INT8_T -D_LIBBFIO_TYPES_H_INTEGERS)
 endif()
endif(LIBBFIO_FOUND)

dff_cpp_api(vfs 
  SWIG_FILE libvfs.i
  CPP_FILES ${vfs_src}
  LINK_LIBRARIES datatype search exceptions types events ${LIBBFIO_LIBRARY}
  DEFINITIONS ${definitions}
  INCLUDE_DIRS ${LIBBFIO_INCLUDE_DIR}
  EXTRA_FILES vfs.py __init__.py iodevice.py extract.py
  )
