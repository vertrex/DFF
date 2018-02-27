# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
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

if (MSVC)
  set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /D__value=_value")
endif(MSVC)

include_directories(api/destruct)
include_directories(api/destruct/procol)
include_directories(api/destruct/python)
include_directories(api/include)

add_subdirectory(api)
add_subdirectory(modules)
add_subdirectory(ui)

if (BUILD_UNSUPPORTED)
  add_subdirectory(unsupported)
endif()

install_file(__init__.py.in)
