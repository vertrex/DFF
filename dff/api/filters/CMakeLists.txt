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


#INCLUDE_DIRECTORIES(${PYTHON_INCLUDE_PATH})
#INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
#INCLUDE_DIRECTORIES(../include)

# you can use -DAPI_FILTER_DEV to call flex and bison for each make

if (API_FILTER_DEV)

  find_package(BISON REQUIRED)
  BISON_TARGET(parser parser.y ${CMAKE_CURRENT_SOURCE_DIR}/parser.cpp)
  find_package(FLEX REQUIRED)
  FLEX_TARGET(scanner scanner.l ${CMAKE_CURRENT_SOURCE_DIR}/scanner.cpp)

else (API_FILTER_DEV)

  if ( NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/parser.cpp )
    message(STATUS "bison files NOT generated, Bison executable is required")
    find_package(BISON REQUIRED)
    BISON_TARGET(parser parser.y ${CMAKE_CURRENT_SOURCE_DIR}/parser.cpp)
  else ( NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/parser.cpp )
    set(BISON_parser_OUTPUTS ${CMAKE_CURRENT_SOURCE_DIR}/parser.cpp)
    message(STATUS "BISON files already generated and setted to ${CMAKE_CURRENT_SOURCE_DIR}/parser.c") 
  endif ( NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/parser.cpp )

  if ( NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/scanner.cpp )
    message(STATUS "flex files NOT generated, Flex executable is required")
    find_package(FLEX REQUIRED)
    FLEX_TARGET(scanner scanner.l ${CMAKE_CURRENT_SOURCE_DIR}/scanner.cpp)
  else (NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/scanner.cpp )
    message(STATUS "FLEX files already generated and setted to ${CMAKE_CURRENT_SOURCE_DIR}/scanner.c")
    set(FLEX_scanner_OUTPUTS ${CMAKE_CURRENT_SOURCE_DIR}/scanner.cpp)
  endif ( NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/scanner.cpp )

endif (API_FILTER_DEV)

message(STATUS ${FLEX_scanner_OUTPUTS} ${BISON_parser_OUTPUTS})

# does not seem to be mandatory. Here just in case and as a reminder...
#ADD_FLEX_BISON_DEPENDENCY(scanner parser)

dff_cpp_api(filters
  SWIG_FILE libfilters.i
  CPP_FILES factory.cpp dictionnary.cpp filter.cpp astnodes.cpp timeline.cpp ${BISON_parser_OUTPUTS} ${FLEX_scanner_OUTPUTS}
  LINK_LIBRARIES events vfs types search
  EXTRA_FILES __init__.py
  )
