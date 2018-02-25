# - Find VSHADOW
# This module finds an installed VSHADOW.  It sets the following variables:
#  VSHADOW_FOUND - set to true if VSHADOW is found
#  VSHADOW_LIBRARY - dynamic libraries for vshadow
#  VSHADOW_INCLUDE_DIR - the path to the include files
#  VSHADOW_VERSION   - the version number of the vshadow library
#

SET(VSHADOW_FOUND FALSE)

FIND_LIBRARY(VSHADOW_LIBRARY vshadow)

IF (VSHADOW_LIBRARY)
   FIND_FILE(VSHADOW_INCLUDE_FILE libvshadow.h)
   IF (VSHADOW_INCLUDE_FILE)
	  IF (CMAKE_GENERATOR MATCHES "Visual Studio")
		STRING(REPLACE "libvshadow.h" "" VSHADOW_INCLUDE_DIR "${VSHADOW_INCLUDE_FILE}")
		STRING(REPLACE "libvshadow.lib" "" VSHADOW_DYN_LIB_PATH "${VSHADOW_LIBRARY}")
		SET (VSHADOW_DYN_LIBRARIES ${VSHADOW_DYN_LIB_PATH}/libvshadow-1.dll)
		FILE(COPY ${BFIO_DYN_LIBRARIES} ${VSHADOW_DYN_LIBRARIES} DESTINATION ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/Debug/)
	  ENDIF (CMAKE_GENERATOR MATCHES "Visual Studio")
      FILE(WRITE ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/vshadowversion.c
      "#ifdef WIN32
			#if _MSC_VER >= 1600
				#include <stdint.h>
			#else
				#include <wstdint.h>
			#endif
	   #endif
	   #include <libvshadow.h>
       #include <stdio.h>
       int main()
       {
	 const char*   version;

	 version = libvshadow_get_version();
  	 printf(\"%s\", version);
	 return 1;
       }")
      TRY_RUN(VSHADOW_RUN_RESULT VSHADOW_COMP_RESULT
	${CMAKE_BINARY_DIR}
      	${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/vshadowversion.c
	CMAKE_FLAGS -DINCLUDE_DIRECTORIES:STRING=${VSHADOW_INCLUDE_DIR} -DLINK_LIBRARIES:STRING=${VSHADOW_LIBRARY}
	COMPILE_DEFINITIONS ${COMP_VSHADOW_DEF}
	COMPILE_OUTPUT_VARIABLE COMP_OUTPUT
	RUN_OUTPUT_VARIABLE RUN_OUTPUT)
      IF (VSHADOW_COMP_RESULT)
      	 IF (VSHADOW_RUN_RESULT)
	    SET(VSHADOW_FOUND TRUE)
	    SET(VSHADOW_VERSION ${RUN_OUTPUT})
	 ENDIF (VSHADOW_RUN_RESULT)
      ELSE (VSHADOW_COMP_RESULT)
      	   message(STATUS "${COMP_OUTPUT}")
      ENDIF (VSHADOW_COMP_RESULT)
   ENDIF (VSHADOW_INCLUDE_FILE)
 ENDIF (VSHADOW_LIBRARY)