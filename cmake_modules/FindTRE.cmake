# - Find TRE
# This module finds an installed TRE.  It sets the following variables:
#  TRE_FOUND - set to true if TRE is found
#  TRE_LIBRARY - dynamic libraries for aff
#  TRE_INCLUDE_DIR - the path to the include files
#  TRE_VERSION   - the version number of the aff library
#

FIND_PATH(LIBTRE_INCLUDE_DIR tre.h
  PATHS
  ${DEPENDENCIES_INCLUDE_DIR}/tre
  ${LIBTRE_ROOT}/tre
  ~/Library/Frameworks/tre
  /Library/Frameworks/tre
  /usr/local/include/tre
  /usr/include/tre
  /sw/include/tre # Fink
  /opt/local/include/tre # DarwinPorts
  /opt/csw/include/tre # Blastwave
  /opt/include/tre
  /usr/freeware/include/tre
  DOC "Location of LIBTRE Headers"
  )

FIND_LIBRARY(LIBTRE_LIBRARY
  NAMES tre
  PATHS
  ${DEPENDENCIES_LIBRARIES_DIR}
  ${LIBTRE_ROOT}
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
  DOC "Location of LIBTRE Libraries"
  )

IF (WIN32)
  FILE(GLOB LIBTRE_RUNTIME_LIBRARY ${DEPENDENCIES_RUNTIME_DIR}/tre.dll)
  #SET(LIBTRE_RUNTIME_LIBRARY ${LIBTRE_RUNTIME_LIBRARY})
  MESSAGE("------- LIBTRE_RUNTIME_LIBRARY : ${LIBTRE_RUNTIME_LIBRARY}")  
ENDIF(WIN32)


IF (LIBTRE_LIBRARY AND LIBTRE_INCLUDE_DIR)
  SET(LIBTRE_FOUND 1)
  message("${LIBTRE_INCLUDE_DIR}")
  if(EXISTS "${LIBTRE_INCLUDE_DIR}/tre-config.h")
       file(READ "${LIBTRE_INCLUDE_DIR}/tre-config.h" _tre_contents)
       #generally, to match dot you have to escape but cmake complains... so leave the interpreted dot version
       string(REGEX REPLACE ".*# *define *TRE_VERSION *\"([0-9].[0-9].[0-9])\".*" "\\1" TRE_VERSION "${_tre_contents}")
       string(REGEX REPLACE ".*# *define *TRE_APPROX *([0-9]+).*" "\\1" TRE_HAVE_APPROX "${_tre_contents}")
       string(REGEX REPLACE ".*# *define *TRE_WCHAR *([0-9]+).*" "\\1" TRE_HAVE_WCHAR "${_tre_contents}")
       string(REGEX REPLACE ".*# *define *TRE_MULTIBYTE *([0-9]+).*" "\\1" TRE_HAVE_MULTIBYTE "${_tre_contents}")
   endif(EXISTS "${LIBTRE_INCLUDE_DIR}/tre-config.h")
   message("Tre version: ${TRE_VERSION}")  
ENDIF (LIBTRE_LIBRARY AND LIBTRE_INCLUDE_DIR)
