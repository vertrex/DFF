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


FILE(GLOB dependencies ${CMAKE_CURRENT_BINARY_DIR}/*)

foreach(file ${dependencies})
  IF (NOT IS_DIRECTORY(${file}))
    split_path_file_extension(${file})
    string(TOLOWER ${__FILE__} file_lower)
    IF (NOT PYTHON_INSTALLER)
      STRING(REGEX MATCH "^python.*" PYTHON_INSTALLER "${file_lower}")
      if (NOT PYTHON_INSTALLER STREQUAL "")
	set (PYTHON_INSTALLER ${__FILE__})
      endif ()
    ENDIF (NOT PYTHON_INSTALLER)
    IF (NOT PYQT_INSTALLER)
      STRING(REGEX MATCH "^pyqt.*" PYQT_INSTALLER "${file_lower}")
      if (NOT PYQT_INSTALLER STREQUAL "")
	set (PYQT_INSTALLER ${__FILE__})
      endif ()
    ENDIF (NOT PYQT_INSTALLER)
    IF (NOT VCREDIST_INSTALLER)
      STRING(REGEX MATCH "^vcredist.*" VCREDIST_INSTALLER "${file_lower}")
      if (NOT VCREDIST_INSTALLER STREQUAL "")
	set (VCREDIST_INSTALLER ${__FILE__})
      endif ()
    ENDIF (NOT VCREDIST_INSTALLER)
    IF (NOT APSW_INSTALLER)
      STRING(REGEX MATCH "^apsw.*" APSW_INSTALLER "${file_lower}")
      if (NOT APSW_INSTALLER STREQUAL "")
	set (APSW_INSTALLER ${__FILE__})
      endif ()
    ENDIF (NOT APSW_INSTALLER)
    IF (NOT PIL_INSTALLER)
      STRING(REGEX MATCH "^pil.*" PIL_INSTALLER "${file_lower}")
      if (NOT PIL_INSTALLER STREQUAL "")
	set (PIL_INSTALLER ${__FILE__})
      endif ()
    ENDIF ()
    if (BUILD_UNSUPPORTED)
      if (NOT MATPLOTLIB_INSTALLER)
	STRING(REGEX MATCH "^matplotlib.*" MATPLOTLIB_INSTALLER "${file_lower}")
	if (NOT MATPLOTLIB_INSTALLER STREQUAL "")
	  set (MATPLOTLIB_INSTALLER ${__FILE__})
	endif ()
      endif ()
      if (NOT NUMPY_INSTALLER)
	STRING(REGEX MATCH "^numpy.*" NUMPY_INSTALLER "${file_lower}")
	if (NOT NUMPY_INSTALLER STREQUAL "")
	  set (NUMPY_INSTALLER ${__FILE__})
	endif ()
      endif ()
    endif()
  ENDIF (NOT IS_DIRECTORY(${file}))
endforeach()

set(PYTHON_INSTALLER ${PYTHON_INSTALLER} PARENT_SCOPE)
set(PYQT_INSTALLER ${PYQT_INSTALLER} PARENT_SCOPE)
set(VCREDIST_INSTALLER ${VCREDIST_INSTALLER} PARENT_SCOPE)
set(APSW_INSTALLER ${APSW_INSTALLER} PARENT_SCOPE)
set(PIL_INSTALLER ${PIL_INSTALLER} PARENT_SCOPE)
if (BUILD_UNSUPPORTED)
  set(MATPLOTLIB_INSTALLER ${MATPLOTLIB_INSTALLER} PARENT_SCOPE)
  set(NUMPY_INSTALLER ${NUMPY_INSTALLER} PARENT_SCOPE)
endif()

set(dependencies 
  ${PYTHON_INSTALLER}
  ${PYQT_INSTALLER}
  ${VCREDIST_INSTALLER}
  ${APSW_INSTALLER}
  ${PIL_INSTALLER}
  )

if (BUILD_UNSUPPORTED)
  set(dependencies 
    ${dependencies}
    ${MATPLOTLIB_INSTALLER}
    ${NUMPY_INSTALLER}
    )
endif()

install_file(${dependencies})
