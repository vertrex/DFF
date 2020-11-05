# Check 64 bit
if( "${CMAKE_SIZEOF_VOID_P}" EQUAL 4 )
  set( HAVE_64_BITS 0 )
else( "${CMAKE_SIZEOF_VOID_P}" EQUAL 4 )
  if (WIN32)
    set(CMAKE_SWIG_FLAGS ${CMAKE_SWIG_FLAGS} -DSWIGWORDSIZE32)
  else()
    set(CMAKE_SWIG_FLAGS ${CMAKE_SWIG_FLAGS} -DSWIGWORDSIZE64)
  endif()
  set( HAVE_64_BITS 1 )
endif( "${CMAKE_SIZEOF_VOID_P}" EQUAL 4 )

#### Create Global variables used by install targets and cpack

if(PROJECT_EDITION)
  string(TOLOWER ${PROJECT_EDITION} PROJECT_EDITION_LOWER)
  set(CONSOLE_SCRIPT "dff-${PROJECT_EDITION_LOWER}.py")
  set(GRAPHICAL_SCRIPT "dff-${PROJECT_EDITION_LOWER}-gui.py")
else()
  set(CONSOLE_SCRIPT "dff.py")
  set(GRAPHICAL_SCRIPT "dff-gui.py")
endif()


#### Basic Cmake definitions
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake_modules/")


## Swig We need at least version 2.0.7 of SWIG
find_package(SWIG REQUIRED)
if (${SWIG_VERSION_MAJOR} LESS 2 OR (${SWIG_VERSION_MAJOR} EQUAL 2 AND ${SWIG_VERSION_PATCH} LESS 7))
  message(FATAL_ERROR "Need SWIG version >= 2.0.7 (current version is ${SWIG_VERSION})")
else()
  message(STATUS "Found compatible SWIG version (${SWIG_VERSION})")
endif()
include(${SWIG_USE_FILE})


set(CMAKE_INCLUDE_PATH "${INCLUDEDIR}")
set(CMAKE_LIBRARY_PATH "${LIBDIR}")

# Optional dependencies required version
set(LIBEWF_REQUIRED_VERSION "20141030")
set(LIBBFIO_REQUIRED_VERSION "20130927")
set(LIBPFF_REQUIRED_VERSION "20150714")
set(LIBVSHADOW_REQUIRED_VERSION "20150905")
set(LIBBDE_REQUIRED_VERSION "20150905")


# Set installation mode, include all items (*.py, ...) Default is development mode
option(DEVELOP "Start installation mode ?" OFF)
IF(DEVELOP)
  message("          /==========================\\")
  message("          | Running development mode |")
  message("          \\==========================/")
ENDIF(DEVELOP)

IF (NOT ${CMAKE_BINARY_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
  SET(DEDICATED_BUILD_DIR 1)
  message(STATUS "Building project in dedicated build directory : ${CMAKE_BINARY_DIR}")
ENDIF (NOT ${CMAKE_BINARY_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})

option(BUILD_UNSUPPORTED "Build unsupported modules ?" OFF)

option(ENABLE_DEBUG "Compile using -g flag ? Useful for debugging" OFF)
add_definitions(-D__STDC_LIMIT_MACROS -std=c++11)
#add_definitions(-D__STDC_LIMIT_MACROS -std=c++98)
if(UNIX)
  if (ENABLE_LEAK_DETECTION)
    set (CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -fsanitize=leak")
    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=leak")
    set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=leak")
    add_definitions(-D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -g -Wall -O1 -fsanitize=leak -fno-omit-frame-pointer -fno-optimize-sibling-calls)
    message(STATUS "Compile using lsan library to detect memory leak, use LD_PRELOAD=path_to_gcc_lsan.so ./dff.py to run")
  elseif(ENABLE_DEBUG)
    add_definitions(-D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -g  -Wno-deprecated -Wno-deprecated-declarations)# -Wall
    message(STATUS "Compile using -g and no optimization")
  else(ENABLE_LEAK_DETECTION)
#change flag here
    add_definitions(-D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -O2 -Wno-deprecated -Wno-deprecated-declarations)
    message(STATUS "Compile with optimization")
  endif(ENABLE_LEAK_DETECTION)
endif(UNIX)
# $> cmake -DENABLE_DEBUG:BOOLEAN=OFF

option(WITH_IOSTAT "enable statistics on input / output comsumption ?" OFF)
if (WITH_IOSTAT)
  add_definitions(-DWITH_IOSTAT=1)
  message(STATUS "input / output stats enabled")
else (WITH_IOSTAT)
  message(STATUS "input / output stats disabled")
endif (WITH_IOSTAT)

option(WITH_TTT_DEBUG "Compile with two three tree debugging" OFF)
if (WITH_TTT_DEBUG)
  add_definitions(-DTWO_THREE_TREE_DEBUG=1)
  message(STATUS "Compile WITH TwoThreeTree debug information")
else (WITH_TTT_DEBUG)
  message(STATUS "Compile WITHOUT TwoThreeTree debug information")
endif (WITH_TTT_DEBUG)

IF (WIN32)
  option(WINALL "Package with windows Dependencies ?" OFF)
  IF(WINALL)
    message(STATUS "Packaging windows version with dependencies")
  ELSE(WINALL)
    message(STATUS "Packaging windows version without dependencies")
  ENDIF(WINALL)
ENDIF(WIN32)

if (WIN32)
  if (DEPENDENCIES_PATH)
    set(DEPENDENCIES_INCLUDE_DIR ${DEPENDENCIES_PATH}/include)
    if (HAVE_64_BITS)
      set(DEPENDENCIES_LIBRARIES_DIR ${DEPENDENCIES_PATH}/lib64)
      set(DEPENDENCIES_RUNTIME_DIR ${DEPENDENCIES_PATH}/bin64)
    else (HAVE_64_BITS)
      set(DEPENDENCIES_LIBRARY_DIR ${DEPENDENCIES_PATH}/lib)
      set(DEPENDENCIES_RUNTIME_DIR ${DEPENDENCIES_PATH}/bin)
    endif(HAVE_64_BITS)
    message("Headers path ${DEPENDENCIES_INCLUDE_DIR}")
    message("Libraries path ${DEPENDENCIES_LIBRARIES_DIR}")
    message("Runtime path ${DEPENDENCIES_RUNTIME_DIR}")
  else (DEPENDENCIES_PATH)
    message(FATAL_ERROR "On Windows platform DEPENDENCIES_PATH must be provided and point to the directory containing include lib[64] and bin[64] folders")
  endif(DEPENDENCIES_PATH)  
endif(WIN32)


if (WIN32)
  set(ICU_INCLUDE_PATH ${DEPENDENCIES_INCLUDE_DIR}/icu)
  set(ICU_LIBRARIES_PATH ${DEPENDENCIES_LIBRARIES_DIR})
  set(ICU_DYNLIB_PATH ${DEPENDENCIES_RUNTIME_DIR})
  message(${ICU_INCLUDE_PATH})
endif (WIN32)

find_package(ICU REQUIRED)


message("ICU INCLUDE DIRS: ${ICU_INCLUDE_DIRS} ${ICU_INCLUDE_PATH}")

find_package(AFF)


find_package(ZMQ)

set(LIBYAL_ROOT "${DEPENDENCIES_PATH}")
find_package(Libyal)

find_package(TRE)

find_package(ARCHIVE)

set(FFMPEG_ROOT "${DEPENDENCIES_PATH}")

find_package(FFmpeg)

if (UNIX)
  find_package(UDEV)
  if (UDEV_FOUND)
    SET(HAVE_UDEV TRUE)
    message(STATUS "udev include and libraries: FOUND")
  endif (UDEV_FOUND)
endif(UNIX)


if (FFMPEG_FOUND)
  message(STATUS "FFmpeg includes and libraries found video module: ENABLED")
else ()
  message(STATUS "FFmpeg includes and libraries not found video module: DISABLED")
endif (FFMPEG_FOUND)


IF (LIBTRE_FOUND)
   add_definitions(-DHAVE_TRE)
   include_directories(${LIBTRE_INCLUDE_DIR})
   message(STATUS "TRE installed version: ${TRE_VERSION}
   approximative matching support : ${TRE_HAVE_APPROX}
   wide character support         : ${TRE_HAVE_WCHAR}
   multibyte character support    : ${TRE_HAVE_MULTIBYTE}")
ENDIF (LIBTRE_FOUND)

if(LIBEWF_FOUND)
   if("${LIBEWF_VERSION}" VERSION_EQUAL "${LIBEWF_REQUIRED_VERSION}" OR "${LIBEWF_VERSION}" VERSION_GREATER "${LIBEWF_REQUIRED_VERSION}")
     message(STATUS "LIBEWF installed version: ${LIBEWF_VERSION}
   >= ${LIBEWF_REQUIRED_VERSION} -- yes")
   else("${LIBEWF_VERSION}" VERSION_EQUAL "${LIBEWF_REQUIRED_VERSION}" OR "${LIBEWF_VERSION}" VERSION_GREATER "${LIBEWF_REQUIRED_VERSION}")
     message(STATUS "LIBEWF installed version: ${LIBEWF_VERSION}
   >= ${LIBEWF_REQUIRED_VERSION} -- no")
     unset(LIBEWF_FOUND)
     unset(LIBEWF_VERSION)
   endif("${LIBEWF_VERSION}" VERSION_EQUAL "${LIBEWF_REQUIRED_VERSION}" OR "${LIBEWF_VERSION}" VERSION_GREATER "${LIBEWF_REQUIRED_VERSION}")
endif(LIBEWF_FOUND)

if(LIBBFIO_FOUND)
   if("${LIBBFIO_VERSION}" VERSION_EQUAL "${LIBBFIO_REQUIRED_VERSION}" OR "${LIBBFIO_VERSION}" VERSION_GREATER "${LIBBFIO_REQUIRED_VERSION}")
     message(STATUS "BFIO installed version: ${LIBBFIO_VERSION}
   >= ${LIBBFIO_REQUIRED_VERSION} -- yes")
   else("${BFIO_VERSION}" VERSION_EQUAL "${LIBBFIO_REQUIRED_VERSION}" OR "${LIBBFIO_VERSION}" VERSION_GREATER "${LIBBFIO_REQUIRED_VERSION}")
     message(STATUS "BFIO installed version: ${LIBBFIO_VERSION}
   >= ${LIBBFIO_REQUIRED_VERSION} -- no")
     unset(LIBBFIO_FOUND)
     unset(LIBBFIO_VERSION)
   endif("${LIBBFIO_VERSION}" VERSION_EQUAL "${LIBBFIO_REQUIRED_VERSION}" OR "${LIBBFIO_VERSION}" VERSION_GREATER "${LIBBFIO_REQUIRED_VERSION}")
endif(LIBBFIO_FOUND)

if(LIBPFF_FOUND)
   if("${LIBPFF_VERSION}" VERSION_EQUAL "${LIBPFF_REQUIRED_VERSION}" OR "${LIBPFF_VERSION}" VERSION_GREATER "${LIBPFF_REQUIRED_VERSION}")
     message(STATUS "PFF installed version: ${LIBPFF_VERSION}
   >= ${LIBPFF_REQUIRED_VERSION} -- yes")
   else("${LIBPFF_VERSION}" VERSION_EQUAL "${LIBPFF_REQUIRED_VERSION}" OR "${LIBPFF_VERSION}" VERSION_GREATER "${LIBPFF_REQUIRED_VERSION}")
     message(STATUS "PFF installed version: ${PFF_VERSION}
   >= ${LIBPFF_REQUIRED_VERSION} -- no")
     unset(LIBPFF_FOUND)
     unset(LIBPFF_VERSION)
   endif("${LIBPFF_VERSION}" VERSION_EQUAL "${LIBPFF_REQUIRED_VERSION}" OR "${LIBPFF_VERSION}" VERSION_GREATER "${LIBPFF_REQUIRED_VERSION}")
endif(LIBPFF_FOUND)

if(LIBVSHADOW_FOUND)
   if("${LIBVSHADOW_VERSION}" VERSION_EQUAL "${LIBVSHADOW_REQUIRED_VERSION}" OR "${LIBVSHADOW_VERSION}" VERSION_GREATER "${LIBVSHADOW_REQUIRED_VERSION}")
     message(STATUS "LIBVSHADOW installed version: ${LIBVSHADOW_VERSION}
   >= ${LIBVSHADOW_REQUIRED_VERSION} -- yes")
   else("${LIBVSHADOW_VERSION}" VERSION_EQUAL "${LIBVSHADOW_REQUIRED_VERSION}" OR "${LIBVSHADOW_VERSION}" VERSION_GREATER "${LIBVSHADOW_REQUIRED_VERSION}")
     message(STATUS "LIBVSHADOW installed version: ${LIBVSHADOW_VERSION}
   >= ${LIBVSHADOW_REQUIRED_VERSION} -- no")
     unset(LIBVSHADOW_FOUND)
     unset(LIBVSHADOW_VERSION)
   endif("${LIBVSHADOW_VERSION}" VERSION_EQUAL "${LIBVSHADOW_REQUIRED_VERSION}" OR "${LIBVSHADOW_VERSION}" VERSION_GREATER "${LIBVSHADOW_REQUIRED_VERSION}")
endif(LIBVSHADOW_FOUND)

if(LIBBDE_FOUND)
   if("${LIBBDE_VERSION}" VERSION_EQUAL "${LIBBDE_REQUIRED_VERSION}" OR "${LIBBDE_VERSION}" VERSION_GREATER "${LIBBDE_REQUIRED_VERSION}")
     message(STATUS "LIBBDE installed version: ${LIBBDE_VERSION}
   >= ${LIBBDE_REQUIRED_VERSION} -- yes")
   else("${LIBBDE_VERSION}" VERSION_EQUAL "${LIBBDE_REQUIRED_VERSION}" OR "${LIBBDE_VERSION}" VERSION_GREATER "${LIBBDE_REQUIRED_VERSION}")
     message(STATUS "LIBBDE installed version: ${LIBBDE_VERSION}
   >= ${LIBBDE_REQUIRED_VERSION} -- no")
     unset(LIBBDE_FOUND)
     unset(LIBBDE_VERSION)
   endif("${LIBBDE_VERSION}" VERSION_EQUAL "${LIBBDE_REQUIRED_VERSION}" OR "${LIBBDE_VERSION}" VERSION_GREATER "${LIBBDE_REQUIRED_VERSION}")
endif(LIBBDE_FOUND)


IF (WIN32)
  IF (ICU_FOUND)
    file(COPY ${ICU_RUNTIME_LIBRARIES} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin)
  ENDIF(ICU_FOUND)
  IF (LIBYAL_FOUND)
    message("${LIBYAL_RUNTIME_LIBRARIES}")
    file(COPY ${LIBYAL_RUNTIME_LIBRARIES} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin)
  ENDIF(LIBYAL_FOUND)
  IF (LIBTRE_FOUND)
    file(COPY ${LIBTRE_RUNTIME_LIBRARY} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin)
  ENDIF(LIBTRE_FOUND)
  IF (LIBARCHIVE_FOUND)
    file(COPY ${LIBARCHIVE_RUNTIME_LIBRARY} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin)
  ENDIF(LIBARCHIVE_FOUND)
  IF (FFMPEG_FOUND)
    message("${FFMPEG_RUNTIME_LIBRARIES}")
    file(COPY ${FFMPEG_RUNTIME_LIBRARIES} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin)
  ENDIF(FFMPEG_FOUND)
  file(COPY ${DEPENDENCIES_RUNTIME_DIR}/libiconv-2.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin)
  file(COPY ${DEPENDENCIES_RUNTIME_DIR}/libregfi.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin)
  file(COPY ${DEPENDENCIES_RUNTIME_DIR}/libtalloc.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin)
  file(COPY ${DEPENDENCIES_RUNTIME_DIR}/pthreadGC2.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin)
  file(COPY ${DEPENDENCIES_PATH}/third-party/pyregfi DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/third-party)
  file(COPY ${DEPENDENCIES_PATH}/third-party/volatility DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/third-party)
  file(COPY ${DEPENDENCIES_RUNTIME_DIR}/clamav DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/third-party)
  file(COPY ${CMAKE_SOURCE_DIR}/ressources/dff.ico DESTINATION ${CMAKE_BINARY_DIR})
  file(GLOB MS_CORE_RUNTIME_LIBRARIES ${DEPENDENCIES_RUNTIME_DIR}/api-ms*.dll)
  file(COPY ${MS_CORE_RUNTIME_LIBRARIES} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin)
  file(GLOB MSVC_RUNTIME_LIBRARIES ${DEPENDENCIES_RUNTIME_DIR}/msvc*.dll)
  file(COPY ${MSVC_RUNTIME_LIBRARIES} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin)
  file(GLOB UCRT_RUNTIME_LIBRARY ${DEPENDENCIES_RUNTIME_DIR}/ucrtbase*.dll)
  file(COPY ${UCRT_RUNTIME_LIBRARY} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin)
  file(GLOB VC_RUNTIME_LIBRARY ${DEPENDENCIES_RUNTIME_DIR}/vcruntime*.dll)
  file(COPY ${VC_RUNTIME_LIBRARY} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/third-party/bin)
ENDIF(WIN32)


if(AFF_FOUND)
  message(STATUS "AFF installed version: ${AFF_VERSION}")
endif(AFF_FOUND)

# Project-wide swig options
#SET(CMAKE_SWIG_FLAGS "-py3")

option(DISABLE_SWIG_THREADING "Wrap cpp code to python without -threads" OFF)
if(DISABLE_SWIG_THREADING)
  message(STATUS "Will we use swig -threads -- no")
else()
  #message(STATUS "Will we use swig -threads -- yes")
  #set(CMAKE_SWIG_FLAGS ${CMAKE_SWIG_FLAGS} -O -threads)
  set(CMAKE_SWIG_FLAGS ${CMAKE_SWIG_FLAGS} -threads)
endif(DISABLE_SWIG_THREADING)
# $> cmake -DDISABLE_SWIG_THREADING:BOOLEAN=ON

find_library(HAVE_FUSE NAMES fuse)
if(NOT HAVE_FUSE)
  message(STATUS "(Optional) fuse library not found; file system module 'fuse' will not be built")
endif(NOT HAVE_FUSE)


IF(WIN32)
  SET(CMAKE_SWIG_FLAGS ${CMAKE_SWIG_FLAGS} -DWIN32 -DSWIGWIN)
  add_definitions("/W3 /D_CRT_SECURE_NO_WARNINGS /wd4290 /nologo")
ENDIF(WIN32)


## Python check
FIND_PACKAGE(PythonInterp REQUIRED)

if (WIN32)
  find_package(PythonLibs)
  SET(PYTHON_BIN_PATH ${PYTHON_EXECUTABLE})
# FIXME for windows validate presence of Python.h in PYTHON_INCLUDE_PATH
endif()

FIND_PACKAGE(PythonLibrary REQUIRED)

# Get Python site packages for installation target
execute_process ( COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())" OUTPUT_VARIABLE PYTHON_SITE_PACKAGES_PATH OUTPUT_STRIP_TRAILING_WHITESPACE)

INCLUDE(PythonMacros)

IF (NOT MSVC)
  ADD_DEFINITIONS(-fPIC)
ENDIF ()


if(UNIX)
# Search for gzip program, to compress manpage for Unix
  find_program(GZIP_TOOL
               NAMES gzip
               PATHS /bin
               /usr/bin
               /usr/local/bin)
  if(NOT GZIP_TOOL)
    message(FATAL_ERROR "Unable to find 'gzip' program")
  endif(NOT GZIP_TOOL)
endif(UNIX)

## Python-magic check for Unix only
if(UNIX)
  execute_process(COMMAND ${PYTHON_EXECUTABLE} -c "import magic; print magic.__file__" OUTPUT_VARIABLE PYTHON_MAGIC_PATH ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT PYTHON_MAGIC_PATH)
    message(STATUS "Python magic not found. Not needed at build step but mandatory to start DFF.")
  else(NOT PYTHON_MAGIC_PATH)
    message(STATUS "Python magic found: ${PYTHON_MAGIC_PATH}")
  endif(NOT PYTHON_MAGIC_PATH)
endif(UNIX)

## Python-QT bindings check
execute_process(COMMAND ${PYTHON_EXECUTABLE} -c "import PyQt4; print PyQt4.__path__[0]" OUTPUT_VARIABLE PYTHON_QT4_PATH ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT PYTHON_QT4_PATH)
  message(STATUS "Python QT4 bindings not found. Not needed at build step but mandatory to start DFF.")
else(NOT PYTHON_QT4_PATH)
  message(STATUS "Python QT4 libraries found: ${PYTHON_QT4_PATH} (version: ${PYQT4_VERSION_STR})")
endif(NOT PYTHON_QT4_PATH)

## PyQt linguist transalation updater check, to create or update translation
## files
find_program(PYTHON_QT4_LANGUAGE NAMES pylupdate4 PATHS	${CMAKE_SYSTEM_PROGRAM_PATH} ${PYTHON_QT4_PATH}/bin ${PYTHON_QT4_PATH})
if(PYTHON_QT4_LANGUAGE)
  message(STATUS "Python Qt4 linguist translation files updater found: ${PYTHON_QT4_LANGUAGE}")
else(PYTHON_QT4_LANGUAGE)
  message(STATUS "Python Qt4 linguist translation files updater not found, unable to check for new tranlatable strings.")
endif(PYTHON_QT4_LANGUAGE)

## QT .ts to .qm compiler, used by translator objects
find_program(QT_LANGUAGE_COMPILER NAMES lrelease lrelease-qt4 PATHS ${CMAKE_SYSTEM_PROGRAM_PATH} ${PYTHON_QT4_PATH}/bin ${PYTHON_QT4_PATH})
if(QT_LANGUAGE_COMPILER)
  message(STATUS "QT translation compiler found: ${QT_LANGUAGE_COMPILER}")
else(QT_LANGUAGE_COMPILER)
  message(ERROR "QT translation compiler not found.")
endif(QT_LANGUAGE_COMPILER)

## PyQt UI compiler check, to generate widgets
find_program(PYTHON_QT4_UIC NAMES pyuic4 pyuic4.bat PATHS ${CMAKE_SYSTEM_PROGRAM_PATH} ${PYTHON_QT4_PATH}/bin ${PYTHON_QT4_PATH})
if(PYTHON_QT4_UIC)
  message(STATUS "Python Qt4 user interface compiler found: ${PYTHON_QT4_UIC}")
else(PYTHON_QT4_UIC)
  message(SEND_ERROR "Python Qt4 user interface compiler not found.")
endif(PYTHON_QT4_UIC)

## PyQt resource compiler check, to generate icons
find_program(PYTHON_QT4_RCC NAMES pyrcc4 PATHS ${CMAKE_SYSTEM_PROGRAM_PATH} ${PYTHON_QT4_PATH}/bin ${PYTHON_QT4_PATH})
if(PYTHON_QT4_RCC)
  message(STATUS "Python Qt4 resource compiler found: ${PYTHON_QT4_RCC}")
else(PYTHON_QT4_RCC)
  message(SEND_ERROR "Python Qt4 resource compiler not found.")
endif(PYTHON_QT4_RCC)
