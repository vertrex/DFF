# Locate libyal
# This module defines
# LIZMQ_LIBRARIES
# LIBZMQ_FOUND, if false, do not try to link to ffmpeg
# LIBZMQ_INCLUDE_DIR, where to find the headers
#
# $LIBZMQ_DIR is an environment variable that would
# correspond to the ./configure --prefix=$LIBZMQ_DIR
#
# Create by Frederic Baguelin based on Robert Osfield's work for FindFFmpeg.cmake.


FIND_PATH(LIBZMQ_INCLUDE_DIR zmq.h
  PATHS
  ${DEPENDENCIES_INCLUDE_DIR}
  ${LIBZMQ_ROOT}/include
  $ENV{LIBZMQ_DIR}/include
  ~/Library/Frameworks
  /Library/Frameworks
  /usr/local/include
  /usr/include
  /sw/include # Fink
  /opt/local/include # DarwinPorts
  /opt/csw/include # Blastwave
  /opt/include
  /usr/freeware/include
  DOC "Location of LIBZMQ Headers"
  )

FIND_LIBRARY(LIBZMQ_LIBRARY
  NAMES zmq
  PATHS
  ${DEPENDENCIES_LIBRARIES_DIR}
  ${LIBZMQ_ROOT}/lib
  $ENV{LIBZMQ_DIR}/lib
  ~/Library/Frameworks
  /Library/Frameworks
  /usr/local/lib
  /usr/local/lib64
  /usr/lib
  /usr/lib64
  /usr/lib/x86_64-linux-gnu/
  /sw/lib
  /opt/local/lib
  /opt/csw/lib
  /opt/lib
  /usr/freeware/lib64
  DOC "Location of LIBZMQ Libraries"
  )


if(EXISTS "${LIBZMQ_INCLUDE_DIR}/zmq.h")
  file(READ "${LIBZMQ_INCLUDE_DIR}/zmq.h" LIBZMQ_DEFINITIONS)
  string(REGEX REPLACE ".*#define[\t ]*ZMQ_VERSION_MAJOR[\t ]*([0-9]+).*" "\\1" LIBZMQ_VERSION_MAJOR  "${LIBZMQ_DEFINITIONS}")
  string(REGEX REPLACE ".*#define[\t ]*ZMQ_VERSION_MINOR[\t ]*([0-9]+).*" "\\1" LIBZMQ_VERSION_MINOR  "${LIBZMQ_DEFINITIONS}")
  string(REGEX REPLACE ".*#define[\t ]*ZMQ_VERSION_PATCH[\t ]*([0-9]+).*" "\\1" LIBZMQ_VERSION_PATCH  "${LIBZMQ_DEFINITIONS}")
  set(LIBZMQ_VERSION "${LIBZMQ_VERSION_MAJOR}.${LIBZMQ_VERSION_MINOR}.${LIBZMQ_VERSION_PATCH}")
  message("LIBZMQ version: ${LIBZMQ_VERSION}")
endif()

    
IF (WIN32)
  
  FILE(GLOB LIBZMQ_RUNTIME_LIBRARY ${DEPENDENCIES_RUNTIME_DIR}/libzmq*.dll)
  MESSAGE("LIBZMQ_RUNTIME_LIBRARY : ${LIBZMQ_RUNTIME_LIBRARY}")
  
ENDIF(WIN32)

IF (LIBZMQ_LIBRARY AND LIBZMQ_INCLUDE_DIR)
  SET(LIBZMQ_FOUND 1)
ENDIF (LIBZMQ_LIBRARY AND LIBZMQ_INCLUDE_DIR)
