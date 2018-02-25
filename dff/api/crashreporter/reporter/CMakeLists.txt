# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2015 ArxSys
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

cmake_minimum_required (VERSION 2.6)

project (CrashReporter)

set (CrashReporter_VERSION_MAJOR 1)
set (CrashReporter_VERSION_MINOR 0)

find_package(Qt4 REQUIRED QtCore QtGui)

if (!QT4_FOUND)
   message(error "Qt Not found!")
endif()

qt4_wrap_cpp(CrashDialog_MOC crashdialog.hpp)

include(${QT_USE_FILE})

include_directories("${CMAKE_SOURCE_DIR}/dff/api/crashreporter/breakpad")

add_definitions(${QT_DEFINITIONS})

include_directories(${CMAKE_CURRENT_BINARY_DIR})

if (WIN32)
  add_definitions(-DUNICODE -D_UNICODE)
  add_executable(CrashReporter main.cpp crashdumpinfo.cpp crashreporter.cpp crashdialog.cpp ${CrashDialog_MOC})
  target_link_libraries (CrashReporter Qt4::QtCore Qt4::QtGui wininet "${CMAKE_BINARY_DIR}/dff/api/crashreporter/breakpad/breakpad.lib")
  set_target_properties (CrashReporter PROPERTIES
    SUFFIX ".exe"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
    )
  install (TARGETS CrashReporter DESTINATION dff/dff/api/crashreporter/reporter)
else (WIN32)
  add_executable(CrashReporter main.cpp crashdumpinfo.cpp crashreporter.cpp crashdialog.cpp ${CrashDialog_MOC})
  target_link_libraries (CrashReporter Qt4::QtCore Qt4::QtGui dl "${CMAKE_BINARY_DIR}/dff/api/crashreporter/breakpad/libbreakpad.a")
  install (TARGETS CrashReporter DESTINATION dff/api/crashreporter/reporter)
endif (WIN32)

add_dependencies(CrashReporter breakpad)

