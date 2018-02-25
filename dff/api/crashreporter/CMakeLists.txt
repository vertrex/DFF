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

include_directories("${CMAKE_SOURCE_DIR}/dff/api/crashreporter/breakpad")

add_subdirectory(breakpad)
add_subdirectory(reporter)

STRING (REGEX MATCH "Linux" PROJECT_OS_LINUX ${CMAKE_SYSTEM_NAME})

if (WIN32)
  add_definitions(-DUNICODE -D_UNICODE)
  set(libbreakpad "${CMAKE_BINARY_DIR}/dff/api/crashreporter/breakpad/breakpad.lib")
elseif (UNIX)
  set(libbreakpad "${CMAKE_BINARY_DIR}/dff/api/crashreporter/breakpad/libbreakpad.a")
endif(WIN32)

dff_cpp_api(crashhandler
  CPP_FILES handler.cpp
  SWIG_FILE libcrashreporter.i
  EXTRA_FILES __init__.py
  LINK_LIBRARIES ${libbreakpad}
  INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/dff/api/crashreporter/breakpad"
  )

add_dependencies(crashhandler breakpad)
