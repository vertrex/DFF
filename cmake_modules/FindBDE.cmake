# - Find BDE
# This module finds an installed BDE.  It sets the following variables:
#  BDE_FOUND - set to true if BDE is found
#  BDE_LIBRARY - dynamic libraries for bde
#  BDE_INCLUDE_DIR - the path to the include files
#  BDE_VERSION   - the version number of the bde library
#

SET(BDE_FOUND FALSE)

FIND_LIBRARY(BDE_LIBRARY bde)

IF (BDE_LIBRARY)
  FIND_FILE(BDE_INCLUDE_FILE libbde.h)
  IF (BDE_INCLUDE_FILE)
    IF (CMAKE_GENERATOR MATCHES "Visual Studio")
      STRING(REPLACE "libbde.h" "" BDE_INCLUDE_DIR "${BDE_INCLUDE_FILE}")
      STRING(REPLACE "libbde.lib" "" BDE_DYN_LIB_PATH "${BDE_LIBRARY}")
      SET (BDE_DYN_LIBRARIES ${BDE_DYN_LIB_PATH}/libbde-1.dll)
      FILE(COPY ${BFIO_DYN_LIBRARIES} ${BDE_DYN_LIBRARIES} DESTINATION ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/Debug/)
    ENDIF (CMAKE_GENERATOR MATCHES "Visual Studio")
    FILE(WRITE ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/bdeversion.c
      "#ifdef WIN32
			#if _MSC_VER >= 1600
				#include <stdint.h>
			#else
				#include <wstdint.h>
			#endif
	   #endif
	   #include <libbde.h>
       #include <stdio.h>
       int main()
       {
	 const char*   version;

	 version = libbde_get_version();
  	 printf(\"%s\", version);
	 return 1;
       }")
    IF (UNIX)
      SET(COMP_BDE_DEF "-DHAVE_STDINT_H -DHAVE_INTTYPES_H -D_LIBBDE_TYPES_H_INTEGERS -DHAVE_WCHAR_H")
    ENDIF (UNIX)
    TRY_RUN(BDE_RUN_RESULT BDE_COMP_RESULT
      ${CMAKE_BINARY_DIR}
      ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/bdeversion.c
      CMAKE_FLAGS -DINCLUDE_DIRECTORIES:STRING=${BDE_INCLUDE_DIR} -DLINK_LIBRARIES:STRING=${BDE_LIBRARY}
      COMPILE_DEFINITIONS ${COMP_BDE_DEF}
      COMPILE_OUTPUT_VARIABLE COMP_OUTPUT
      RUN_OUTPUT_VARIABLE RUN_OUTPUT)
    IF (BDE_COMP_RESULT)
      IF (BDE_RUN_RESULT)
	SET(BDE_FOUND TRUE)
	SET(BDE_VERSION ${RUN_OUTPUT})
      ENDIF (BDE_RUN_RESULT)
    ELSE (BDE_COMP_RESULT)
      message(STATUS "${COMP_OUTPUT}")
    ENDIF (BDE_COMP_RESULT)
  ENDIF (BDE_INCLUDE_FILE)
ENDIF (BDE_LIBRARY)