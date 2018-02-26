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


install_file(__init__.py)

# compiled

add_subdirectory (exceptions)

STRING (REGEX MATCH "Linux" LINUX ${CMAKE_SYSTEM_NAME})
if(LINUX OR WIN32)
  #add_subdirectory (crashreporter)
endif(LINUX OR WIN32)
add_subdirectory (events)
add_subdirectory (loader)
add_subdirectory (module)
add_subdirectory (types)
add_subdirectory (vfs)
add_subdirectory (search)
add_subdirectory (filters)
add_subdirectory (tree)

if (LINUX OR WIN32)
  add_subdirectory (magic)
endif (LINUX OR WIN32)

# python only
add_subdirectory (taskmanager)
add_subdirectory (manager)
add_subdirectory (datatype)
add_subdirectory (gui)
add_subdirectory (devices)
add_subdirectory (apswvfs)
add_subdirectory (report)
