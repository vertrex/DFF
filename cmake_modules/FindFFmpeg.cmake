# Locate ffmpeg
# This module defines
# FFMPEG_LIBRARIES
# FFMPEG_FOUND, if false, do not try to link to ffmpeg
# FFMPEG_INCLUDE_DIR, where to find the headers
#
# $FFMPEG_DIR is an environment variable that would
# correspond to the ./configure --prefix=$FFMPEG_DIR
#
# Created by Robert Osfield.


#In ffmpeg code, old version use "#include <header.h>" and newer use "#include <libname/header.h>"
#In OSG ffmpeg plugin, we use "#include <header.h>" for compatibility with old version of ffmpeg

#We have to search the path which contain the header.h (usefull for old version)
#and search the path which contain the libname/header.h (usefull for new version)

#Then we need to include ${FFMPEG_libname_INCLUDE_DIRS} (in old version case, use by ffmpeg header and osg plugin code)
#                                                       (in new version case, use by ffmpeg header) 
#and ${FFMPEG_libname_INCLUDE_DIRS/libname}             (in new version case, use by osg plugin code)


# Macro to find header and lib directories
# example: FFMPEG_FIND(AVFORMAT avformat avformat.h)
MACRO(FFMPEG_FIND varname shortname headername)
    # old version of ffmpeg put header in $prefix/include/[ffmpeg]
    # so try to find header in include directory
    FIND_PATH(FFMPEG_${varname}_INCLUDE_DIRS ${headername}
        PATHS
        ${FFMPEG_ROOT}/include
        $ENV{FFMPEG_DIR}/include
        $ENV{OSGDIR}/include
        $ENV{OSG_ROOT}/include
        ~/Library/Frameworks
        /Library/Frameworks
        /usr/local/include
        /usr/include
        /sw/include # Fink
        /opt/local/include # DarwinPorts
        /opt/csw/include # Blastwave
        /opt/include
        /usr/freeware/include
        PATH_SUFFIXES ffmpeg
        DOC "Location of FFMPEG Headers"
    )

    # newer version of ffmpeg put header in $prefix/include/[ffmpeg/]lib${shortname}
    # so try to find lib${shortname}/header in include directory
    IF(NOT FFMPEG_${varname}_INCLUDE_DIRS)
        FIND_PATH(FFMPEG_${varname}_INCLUDE_DIRS lib${shortname}/${headername}
			PATHS
            ${FFMPEG_ROOT}/include
            $ENV{FFMPEG_DIR}/include
            $ENV{OSGDIR}/include
            $ENV{OSG_ROOT}/include
            ~/Library/Frameworks
            /Library/Frameworks
            /usr/local/include
            /usr/include/
            /sw/include # Fink
            /opt/local/include # DarwinPorts
            /opt/csw/include # Blastwave
            /opt/include
            /usr/freeware/include
            PATH_SUFFIXES ffmpeg
            DOC "Location of FFMPEG Headers"
        )
    ENDIF(NOT FFMPEG_${varname}_INCLUDE_DIRS)

    
    FIND_LIBRARY(FFMPEG_${varname}_LIBRARIES
        NAMES ${shortname}
        PATHS
        ${FFMPEG_ROOT}/lib
	${FFMPEG_ROOT}/lib64
        $ENV{FFMPEG_DIR}/lib
	$ENV{FFMPEG_DIR}/lib64
        $ENV{OSGDIR}/lib
        $ENV{OSG_ROOT}/lib
        ~/Library/Frameworks
        /Library/Frameworks
        /usr/local/lib
        /usr/local/lib64
	/usr/lib/x86_64-linux-gnu
        /usr/lib
        /usr/lib64
        /sw/lib
        /opt/local/lib
        /opt/csw/lib
        /opt/lib
        /usr/freeware/lib64
        DOC "Location of FFMPEG Libraries"
    )

    IF (FFMPEG_${varname}_LIBRARIES AND FFMPEG_${varname}_INCLUDE_DIRS)
        SET(FFMPEG_${varname}_FOUND 1)
    ENDIF(FFMPEG_${varname}_LIBRARIES AND FFMPEG_${varname}_INCLUDE_DIRS)

    IF (WIN32)
    
      FILE(GLOB FFMPEG_${varname}_RUNTIME_LIBRARY ${DEPENDENCIES_RUNTIME_DIR}/${shortname}*.dll)
      SET(${varname}_RUNTIME_LIBRARY ${FFMPEG_${varname}_RUNTIME_LIBRARY})
      SET(FFMPEG_RUNTIME_LIBRARIES ${FFMPEG_RUNTIME_LIBRARIES} ${${varname}_RUNTIME_LIBRARY})
      MESSAGE("FFMPEG_${varname}_RUNTIME_LIBRARY : ${FFMPEG_${varname}_RUNTIME_LIBRARY}")
 
    ENDIF(WIN32)

    
ENDMACRO(FFMPEG_FIND)

SET(FFMPEG_ROOT "$ENV{FFMPEG_DIR}" CACHE PATH "Location of FFMPEG")

FFMPEG_FIND(LIBAVFORMAT avformat avformat.h)
FFMPEG_FIND(LIBAVFILTER avfilter avfilter.h)
FFMPEG_FIND(LIBAVDEVICE avdevice avdevice.h)
FFMPEG_FIND(LIBAVCODEC  avcodec  avcodec.h)
FFMPEG_FIND(LIBAVUTIL   avutil   avutil.h)
FFMPEG_FIND(LIBSWSCALE  swscale  swscale.h)
if (WIN32)
  FFMPEG_FIND(LIBSWRESAMPLE swresample swresample.h)
else (WIN32)
  message("Looking for libavresample")
  FFMPEG_FIND(LIBSWRESAMPLE avresample avresample.h)
endif (WIN32)
FFMPEG_FIND(LIBPOSTPROC postproc postprocess.h)

SET(FFMPEG_FOUND FALSE)
# Note we don't check FFMPEG_LIBAVFILTER and LIBPOSTPROC because we don't need them
IF (FFMPEG_LIBAVFORMAT_FOUND AND FFMPEG_LIBAVDEVICE_FOUND AND FFMPEG_LIBAVCODEC_FOUND AND FFMPEG_LIBAVUTIL_FOUND AND FFMPEG_LIBSWSCALE_FOUND AND FFMPEG_LIBSWRESAMPLE_FOUND)

    SET(FFMPEG_FOUND TRUE)

    message("FFmpeg found")
    
    SET(FFMPEG_INCLUDE_DIRS ${FFMPEG_LIBAVFORMAT_INCLUDE_DIRS})

    SET(FFMPEG_LIBRARY_DIRS ${FFMPEG_LIBAVFORMAT_LIBRARY_DIRS})

    # Note we don't add FFMPEG_LIBSWSCALE_LIBRARIES here, it will be added if found later.
    SET(FFMPEG_LIBRARIES
      ${FFMPEG_LIBAVFORMAT_LIBRARIES}
      #${FFMPEG_LIBAVFILTER_LIBRARIES}
      ${FFMPEG_LIB_LIBRARIES}
      ${FFMPEG_LIBAVDEVICE_LIBRARIES}
      ${FFMPEG_LIBAVCODEC_LIBRARIES}
      ${FFMPEG_LIBAVUTIL_LIBRARIES}
      ${FFMPEG_LIBSWSCALE_LIBRARIES}
      ${FFMPEG_LIBSWRESAMPLE_LIBRARIES}
      #${FFMPEG_LIBPOSTPROC_LIBRARIES}
      )
      
    SET(FFMPEG_RUNTIME_LIBRARIES
      ${FFMPEG_LIBAVFORMAT_RUNTIME_LIBRARY}
      #${FFMPEG_LIBAVFILTER_RUNTIME_LIBRARY}
      ${FFMPEG_LIBAVDEVICE_RUNTIME_LIBRARY}
      ${FFMPEG_LIBAVCODEC_RUNTIME_LIBRARY}
      ${FFMPEG_LIBAVUTIL_RUNTIME_LIBRARY}
      ${FFMPEG_LIBSWSCALE_RUNTIME_LIBRARY}
      ${FFMPEG_LIBSWRESAMPLE_RUNTIME_LIBRARY}
      #${FFMPEG_LIBPOSTPROC_RUNTIME_LIBRARY}
      )
    
ELSE (FFMPEG_LIBAVFORMAT_FOUND AND FFMPEG_LIBAVDEVICE_FOUND AND FFMPEG_LIBAVCODEC_FOUND AND FFMPEG_LIBAVUTIL_FOUND AND FFMPEG_LIBSWSCALE_FOUND AND FFMPEG_LIBSWRESAMPLE_FOUND)

  message(STATUS "Could not find FFMPEG")

ENDIF (FFMPEG_LIBAVFORMAT_FOUND AND FFMPEG_LIBAVDEVICE_FOUND AND FFMPEG_LIBAVCODEC_FOUND AND FFMPEG_LIBAVUTIL_FOUND AND FFMPEG_LIBSWSCALE_FOUND AND FFMPEG_LIBSWRESAMPLE_FOUND)

