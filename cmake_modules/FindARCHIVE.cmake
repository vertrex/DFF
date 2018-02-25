FIND_PATH(LIBARCHIVE_INCLUDE_DIR archive.h
  PATHS
  ${DEPENDENCIES_INCLUDE_DIR}
  ${LIBARCHIVE_ROOT}
  ~/Library/Frameworks
  /Library/Frameworks
  /usr/local/include
  /usr/include
  /sw/include # Fink
  /opt/local/include # DarwinPorts
  /opt/csw/include # Blastwave
  /opt/include
  /usr/freeware/include
  DOC "Location of LIBARCHIVE Headers"
  )

FIND_LIBRARY(LIBARCHIVE_LIBRARY
  NAMES archive
  PATHS
  ${DEPENDENCIES_LIBRARIES_DIR}
  ${LIBARCHIVE_ROOT}
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
  DOC "Location of LIBARCHIVE Libraries"
  )

IF (WIN32)
  FILE(GLOB LIBARCHIVE_RUNTIME_LIBRARY ${DEPENDENCIES_RUNTIME_DIR}/libarchive*.dll)
  FILE(GLOB LIBZLIB_RUNTIME_LIBRARY ${DEPENDENCIES_RUNTIME_DIR}/zlib*.dll)
  SET(LIBARCHIVE_RUNTIME_LIBRARIES ${LIBARCHIVE_RUNTIME_LIBRARY} ${LIBZLIB_RUNTIME_LIBRARY})
  MESSAGE("LIBARCHIVE_RUNTIME_LIBRARY : ${LIBARCHIVE_RUNTIME_LIBRARY}")
  MESSAGE("LIBARCHIVE_RUNTIME_LIBRARIES : ${LIBARCHIVE_RUNTIME_LIBRARIES}")  
ENDIF(WIN32)


IF (LIBARCHIVE_LIBRARY AND LIBARCHIVE_INCLUDE_DIR)
  SET(LIBARCHIVE_FOUND 1)
ENDIF (LIBARCHIVE_LIBRARY AND LIBARCHIVE_INCLUDE_DIR)
