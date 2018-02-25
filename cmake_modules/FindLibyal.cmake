# Locate libyal
# This module defines
# LIBYAL_LIBRARIES
# LIBYAL_FOUND, if false, do not try to link to ffmpeg
# LIBYAL_INCLUDE_DIR, where to find the headers
#
# $LIBYAL_DIR is an environment variable that would
# correspond to the ./configure --prefix=$LIBYAL_DIR
#
# Create by Frederic Baguelin based on Robert Osfield's work for FindFFmpeg.cmake.

#Then we need to include ${LIBYAL_libname_INCLUDE_DIRS} 
#and ${LIBYAL_libname_INCLUDE_DIRS/libname}


# Macro to find header and lib directories
# example: LIBYAL_FIND(BDE bde libbde.h)
MACRO(LIBYAL_FIND varname shortname headername)
    FIND_PATH(LIBYAL_${varname}_INCLUDE_DIR ${headername}
        PATHS
        ${DEPENDENCIES_INCLUDE_DIR}
        ${LIBYAL_ROOT}/include
        $ENV{LIBYAL_DIR}/include
        ~/Library/Frameworks
        /Library/Frameworks
        /usr/local/include
        /usr/include
        /sw/include # Fink
        /opt/local/include # DarwinPorts
        /opt/csw/include # Blastwave
        /opt/include
        /usr/freeware/include
        DOC "Location of LIBYAL Headers"
    )

    FIND_LIBRARY(LIBYAL_${varname}_LIBRARY
        NAMES ${shortname}
        PATHS
	${DEPENDENCIES_LIBRARIES_DIR}
        ${LIBYAL_ROOT}/lib
        $ENV{LIBYAL_DIR}/lib
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
        DOC "Location of LIBYAL Libraries"
    )

    if(EXISTS "${LIBYAL_${varname}_INCLUDE_DIR}/lib${shortname}/definitions.h")
      file(READ "${LIBYAL_${varname}_INCLUDE_DIR}/lib${shortname}/definitions.h" LIBYAL_${varname}_DEFINITIONS)
      string(REGEX REPLACE ".*#define[\t ]*${varname}_VERSION[\t ]*([0-9]+).*" "\\1" ${varname}_VERSION  "${LIBYAL_${varname}_DEFINITIONS}")
      message("${varname} version: ${${varname}_VERSION}")
    endif()

    
    IF (WIN32)
    
      FILE(GLOB LIBYAL_${varname}_RUNTIME_LIBRARY ${DEPENDENCIES_RUNTIME_DIR}/lib${shortname}*.dll)
      SET(${varname}_RUNTIME_LIBRARY ${LIBYAL_${varname}_RUNTIME_LIBRARY})
      SET(LIBYAL_RUNTIME_LIBRARIES ${LIBYAL_RUNTIME_LIBRARIES} ${${varname}_RUNTIME_LIBRARY})
      MESSAGE("LIBYAL_${varname}_RUNTIME_LIBRARY : ${LIBYAL_${varname}_RUNTIME_LIBRARY}")

    ENDIF(WIN32)

    message("${LIBYAL_${varname}_LIBRARY}")
    message("${LIBYAL_${varname}_INCLUDE_DIR}")
  
    IF (LIBYAL_${varname}_LIBRARY AND LIBYAL_${varname}_INCLUDE_DIR)
      SET(LIBYAL_${varname}_FOUND 1)
      SET(${varname}_FOUND 1)
      SET(${varname}_INCLUDE_DIR ${LIBYAL_${varname}_INCLUDE_DIR})
      SET(${varname}_LIBRARY ${LIBYAL_${varname}_LIBRARY})
      message("${varname_FOUND} : ${${varname}_FOUND}")
      message("${varname}_INCLUDE_DIR: ${${varname}_INCLUDE_DIR}")
      message("${varname}_LIBRARY: ${${varname}_LIBRARY}")
      IF (WIN32)
      ENDIF(WIN32)
    ENDIF(LIBYAL_${varname}_LIBRARY AND LIBYAL_${varname}_INCLUDE_DIR)

ENDMACRO(LIBYAL_FIND)

SET(LIBYAL_ROOT "$ENV{LIBYAL_DIR}" CACHE PATH "Location of LIBYAL")

LIBYAL_FIND(LIBBFIO     bfio     libbfio.h)
LIBYAL_FIND(LIBEWF      ewf      libewf.h)
LIBYAL_FIND(LIBPFF      pff      libpff.h)
LIBYAL_FIND(LIBBDE      bde      libbde.h)
LIBYAL_FIND(LIBVSHADOW  vshadow  libvshadow.h)

SET(LIBYAL_FOUND FALSE)

IF  (LIBYAL_LIBBFIO_FOUND AND LIBYAL_LIBEWF_FOUND AND LIBYAL_LIBPFF_FOUND AND LIBYAL_LIBBDE_FOUND AND LIBYAL_LIBVSHADOW_FOUND)

    SET(LIBYAL_FOUND TRUE)

    SET(LIBYAL_INCLUDE_DIRS ${LIBYAL_LIBBFIO_INCLUDE_DIRS})

    SET(LIBYAL_LIBRARY_DIRS ${LIBYAL_LIBBFIO_LIBRARY_DIRS})

    SET(LIBYAL_LIBRARIES
        ${LIBYAL_LIBBFIO_LIBRARY}
        ${LIBYAL_LIBEWF_LIBRARY}
        ${LIBYAL_LIBPFF_LIBRARY}
        ${LIBYAL_LIBBDE_LIBRARY}
        ${LIBYAL_LIBVSHADOW_LIBRARY}
	)

ELSE (LIBYAL_LIBBFIO_FOUND AND LIBYAL_LIBEWF_FOUND AND LIBYAL_LIBPFF_FOUND AND LIBYAL_LIBBDE_FOUND AND LIBYAL_LIBVSHADOW_FOUND)

ENDIF(LIBYAL_LIBBFIO_FOUND AND LIBYAL_LIBEWF_FOUND AND LIBYAL_LIBPFF_FOUND AND LIBYAL_LIBBDE_FOUND AND LIBYAL_LIBVSHADOW_FOUND)
