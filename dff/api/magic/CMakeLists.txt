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


include(CheckIncludeFiles)
INCLUDE (CheckFunctionExists)

check_function_exists(acstime_r HAVE_ASCTIME_R)
check_function_exists(asprintf HAVE_ASPRINTF)
check_function_exists(ctime_r HAVE_CTIME_R)
check_function_exists(fmtcheck HAVE_FMTCHECK)
check_function_exists(fork HAVE_FORK)
check_function_exists(freelocale HAVE_FREELOCALE)
check_function_exists(getline HAVE_GETLINE)
check_function_exists(gmtime_r HAVE_GMTIME_R)

check_include_files(inttypes.h HAVE_INTTYPES_H)
check_include_files(limits.h HAVE_LIMITS_H)
check_include_files(locale.h HAVE_LOCALE_H)

check_function_exists(localtime_r HAVE_LOCALTIME_R)
check_function_exists(mmap HAVE_MMAP)
check_function_exists(newlocale HAVE_NEWLOCALE)
check_function_exists(pread HAVE_PREAD)

check_include_files(stddef.h HAVE_STDDEF_H)
check_include_files(stdint.h HAVE_STDINT_H)
check_include_files(stdlib.h HAVE_STDLIB_H)

check_function_exists(strcasestr HAVE_STRCASESTR)
check_function_exists(strerror HAVE_STRERROR)
check_function_exists(strlcat HAVE_STRLCAT)
check_function_exists(strlcpy HAVE_STRLCPY)
check_function_exists(strndup HAVE_STRNDUP)
check_function_exists(strtof HAVE_STRTOF)
check_function_exists(strtoul HAVE_STRTOUL)

check_function_exists(snprintf HAVE_SNPRINTF)

check_include_files(sys/mman.h HAVE_SYS_MMAN_H)
check_include_files(unistd.h HAVE_UNISTD_H)

check_function_exists(uselocale HAVE_USELOCALE)
check_function_exists(utime HAVE_UTIME)
check_function_exists(utimes HAVE_UTIMES)
check_function_exists(vasprintf HAVE_VASPRINTF)

check_include_files(wchar.h HAVE_WCHAR_H)
check_include_files(wctype.h HAVE_WCTYPE_H)

check_function_exists(wcwidth HAVE_WCWIDTH)

check_include_files(xlocale.h HAVE_XLOCALE_H)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

file(COPY magic DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

set(magic_sources
  apprentice.c
  softmagic.c
  funcs.c
  strlcpy.c
  strlcat.c
  fmtcheck.c
  magic.c
  print.c
  encoding.c
  )

if (WIN32)
  set(magic_sources ${magic_sources}
    getline.c
    asprintf.c
    vasprintf.c
    asctime_r.c
    gmtime_r.c
    localtime_r.c
    )
endif (WIN32)

add_definitions(-DHAVE_CONFIG_H)

add_library(cmagic SHARED ${magic_sources})

add_executable(magict test.cpp)
target_link_libraries (magict cmagic)

if (WIN32)
  set_target_properties (cmagic PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
    )
  set_target_properties (magict PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
    )
  set(magic_library cmagic.dll)
else (WIN32)
  set(magic_library libcmagic.so)
endif (WIN32)

add_custom_command(TARGET magict POST_BUILD COMMAND magict WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

install_file(
  __init__.py
  magic.py
  ${magic_library}
  magic.mgc
  )
