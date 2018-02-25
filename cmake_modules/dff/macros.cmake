# Backing up original install prefix, some files have to sit elsewhere than python path, see at the end of this file.
SET(CMAKE_INSTALL_ORIG_PREFIX ${CMAKE_INSTALL_PREFIX})
# Install prefix used by Python installer.
SET(CMAKE_INSTALL_PREFIX ${PYTHON_SITE_PACKAGES_PATH}/${CMAKE_PROJECT_NAME}/)

#message("${CMAKE_INSTALL_ORIG_PREFIX}")

if (WIN32)
  set(INSTALL_FILE_DESTINATION "dff")
elseif (UNIX)
  set(INSTALL_FILE_DESTINATION ${PYTHON_SITE_PACKAGES_PATH})
endif (WIN32)

## Main purpose of this macro if to copy Python files at install.
# It also deploys .py files in build directory if there is one.
LIST(APPEND PYC_FILES "")
set_property(GLOBAL PROPERTY PYC_FILES)
FILE(WRITE "${CMAKE_BINARY_DIR}/installed_files.log" "")

FILE(APPEND "${CMAKE_BINARY_DIR}/targets" "")

LIST(APPEND CUSTOM_DEPENDENCIES "")
set_property(GLOBAL PROPERTY CUSTOM_DEPENDENCIES)

LIST(APPEND CREATED_TARGETS "")
set_property(GLOBAL PROPERTY CREATED_TARGET)


macro(log text)
  if (LOG_BUILD)
    message(${text})
  endif (LOG_BUILD)
endmacro(log text)

macro(SPLIT_PATH_FILE_EXTENSION item)
  file(TO_CMAKE_PATH ${item} path)
  string(FIND "${path}" "/" slash_rpos REVERSE)
  if (slash_rpos EQUAL -1)
    set(__FILE__ ${path})
    set(__PATH__ "")
  else()
    math(EXPR slash_rpos "${slash_rpos} + 1")
    string(SUBSTRING ${path} ${slash_rpos} -1 __FILE__)
    string(SUBSTRING ${path} 0 ${slash_rpos} __PATH__)
  endif()
  string(FIND "${__FILE__}" "." dot_rpos REVERSE)
  if (dot_rpos EQUAL -1)
    set(__EXTENSION__ "")
  else()
    math(EXPR dot_rpos "${dot_rpos} + 1")
    string(SUBSTRING ${__FILE__} ${dot_rpos} -1 __EXTENSION__)
  endif()
endmacro()

#split_path_file_extension("/usr/lib/pouet.py")
#message("path: ${__PATH__} -- file: ${__FILE__} -- extension: ${__EXTENSION__}")

#split_path_file_extension("/usr\\\\lib\\\\pouet.py")
#message("path: ${__PATH__} -- file: ${__FILE__} -- extension: ${__EXTENSION__}")

#split_path_file_extension("/usr/lib/pouet")
#message("path: ${__PATH__} -- file: ${__FILE__} -- extension: ${__EXTENSION__}")

#split_path_file_extension("pouet")
#message("path: ${__PATH__} -- file: ${__FILE__} -- extension: ${__EXTENSION__}")

#split_path_file_extension("pouet.py")
#message("path: ${__PATH__} -- file: ${__FILE__} -- extension: ${__EXTENSION__}")


macro(DFF_CPP_CONTEXT_INIT library_name)
  INCLUDE_DIRECTORIES(../include)

  list(APPEND arguments CPP_FILES SWIG_FILE LINK_LIBRARIES SWIG_FLAGS DEFINITIONS EXTRA_FILES INCLUDE_DIRS INCLUDE_FILES NO_SWIG_LIB_PREFIX)
  set(arglist "${ARGN}")
  foreach(argument ${arguments})
    list(REMOVE_ITEM arguments ${argument})
    string(FIND "${arglist}" ${argument} start_pos)
    if (NOT ${start_pos} EQUAL -1)
      string(LENGTH "${arglist}" end_pos)
      foreach(delim_arg ${arguments})
	string(FIND "${arglist}" ${delim_arg} idx)
	if (idx GREATER start_pos AND idx LESS end_pos)
	  set(end_pos ${idx})
	endif()
      endforeach()
      math(EXPR length "${end_pos} - ${start_pos}")
      string(SUBSTRING "${arglist}" ${start_pos} ${length} extracted)
      string(REPLACE "${extracted}" "" arglist "${arglist}")
      string(LENGTH "${argument}" val_start)
      string(SUBSTRING "${extracted}" ${val_start} -1 __${argument}__)
      string(STRIP "${__${argument}__}" __${argument}__)
      log("Values for ${argument} : ${__${argument}__}")
    else ()
      list(REMOVE_ITEM arguments ${argument})
    endif ()
  endforeach()
endmacro()


macro(VS_LIBRARY_PROPERTIES library_name extension)
  set_target_properties (${library_name} PROPERTIES
    SUFFIX "${extension}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
    )
endmacro()

macro(DFF_COMPILE_HEAD)
  # setting default context when compiling CPP
  dff_cpp_context_init(library_name ${ARGN})


  # getting target from path
  path_to_target()

  #include(${SWIG_USE_FILE})
  include_directories(${PYTHON_INCLUDE_PATH})
  include_directories(${CMAKE_CURRENT_SOURCE_DIR})
  include_directories(${CMAKE_HOME_DIRECTORY}/dff/api/include)

  if (NOT "${__INCLUDE_DIRS__}" STREQUAL "")
    include_directories(${__INCLUDE_DIRS__})
  endif ()
  if (NOT "${__INCLUDE__}" STREQUAL "")
    include("${__INCLUDE__}")
  endif()

  if (NOT "${__DEFINITIONS__}" STREQUAL "")
    add_definitions(${__DEFINITIONS__})
  endif()

  if (NOT "${__SWIG_FLAGS__}" STREQUAL "")
    set(CMAKE_SWIG_FLAGS ${CMAKE_SWIG_FLAGS} ${__SWIG_FLAGS__})
  endif()
endmacro()

# Following macro is used to generate DFF's API and Python bindings libraries
#
# First argument to provide is the name of the library to create then
# 
# Mandatory arguments are :
#  - CPP_FILES followed by .cpp files
#  - SWIG_FILE followed by .i files
#
# Optional arguments are :
#  - LINK_LIBRARIES followed by needed library
#  - SWIG_FLAGS followed by needed flags
#  - DEFINITIONS followed by needed definitions
#  - EXTRA_FILES followed by extra files you need to install
#  - INCLUDE_DIRS followed by absolute path to include directories
#    By default following include dirs are managed 
#      * ${CMAKE_CURRENT_SOURCE_DIR}
#      * ${CMAKE_HOME_DIRECTORY}/dff/api/include
#      * ${PYTHON_INCLUDE_PATH}
#  - INCLUDE followed by files to include
#    By Default ${SWIG_USE_FILE} are included
#
# Ex: to create library foo which needs to be linked with
#     library 'bar'
#
# DFF_CPP_API(foo 
#   CPP_FILES foo.cpp 
#   SWIG_FILE libfoo.i
#   LINK_LIBRARIES bar
#   DEFINITIONS -D__STDC_LIMIT_MACROS
#   SWIG_FLAGS -threads -fvirtual -fastdispatch
#   EXTRA_FILES __init__.py
#   )
macro(DFF_CPP_API library_name)
  # Setting default context to compile cpp / swig libraries
  dff_compile_head(${ARGN})

  # General purpose DFF's library generation
  add_library(${library_name} SHARED ${__CPP_FILES__})
  target_link_libraries(${library_name} ${__LINK_LIBRARIES__})
  if ( CMAKE_GENERATOR MATCHES "Visual Studio")
    vs_library_properties(${library_name} ".dll")
    file(APPEND "${CMAKE_BINARY_DIR}/installed_files.log" "${rpath}/${library_name}.dll\n")
    install(TARGETS ${library_name} DESTINATION ${INSTALL_FILE_DESTINATION}/${rpath})
  elseif (UNIX)
    set_target_properties(${library_name} PROPERTIES
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/../"
      )
    install(TARGETS ${library_name} DESTINATION "${CMAKE_INSTALL_ORIG_PREFIX}/lib/dff/")    
  endif ()

  # Python's binding library generation
  if (${__NO_SWIG_LIB_PREFIX__})
    set(swig_lib_name "${library_name}")
  else()
    set(swig_lib_name "lib${library_name}")
  endif()
  set_source_files_properties(${__SWIG_FILE__} PROPERTIES CPLUSPLUS ON)
  swig_add_module(${swig_lib_name} python ${__SWIG_FILE__})
  swig_link_libraries(${swig_lib_name} ${PYTHON_LIBRARIES} ${library_name})
  if ( CMAKE_GENERATOR MATCHES "Visual Studio")
    vs_library_properties(${SWIG_MODULE_${swig_lib_name}_REAL_NAME} ".pyd")
    file(APPEND "${CMAKE_BINARY_DIR}/installed_files.log" "${rpath}/${SWIG_MODULE_${swig_lib_name}_REAL_NAME}.pyd\n")
    install (TARGETS ${SWIG_MODULE_${swig_lib_name}_REAL_NAME} DESTINATION ${INSTALL_FILE_DESTINATION}/${rpath})
  elseif (UNIX)
    set_target_properties(${SWIG_MODULE_${swig_lib_name}_REAL_NAME} PROPERTIES
      SKIP_BUILD_RPATH FALSE
      BUILD_WITH_INSTALL_RPATH FALSE
      INSTALL_RPATH "${CMAKE_INSTALL_ORIG_PREFIX}/lib/dff/"
      INSTALL_RPATH_USE_LINK_PATH TRUE
      )
    file(APPEND "${CMAKE_BINARY_DIR}/installed_files.log" "${rpath}/${SWIG_MODULE_${swig_lib_name}_REAL_NAME}.so\n")
    install(TARGETS ${SWIG_MODULE_${swig_lib_name}_REAL_NAME} DESTINATION ${PYTHON_SITE_PACKAGES_PATH}/${rpath})
  endif()

  # Final rules
  install_file("${swig_lib_name}.py" ${__EXTRA_FILES__})
  add_dependencies(${current_target} ${library_name} ${SWIG_MODULE_${library_name}_REAL_NAME})
endmacro()

macro(DFF_CPP_MODULE library_name)
  # Setting default context to compile cpp / swig libraries
  dff_compile_head(${ARGN})

  set_source_files_properties(${__SWIG_FILE__} PROPERTIES CPLUSPLUS ON)
  swig_add_module(${library_name} python ${__SWIG_FILE__} ${__CPP_FILES__})
  swig_link_libraries(${library_name} ${PYTHON_LIBRARIES} ${__LINK_LIBRARIES__})

  if ( CMAKE_GENERATOR MATCHES "Visual Studio")
    vs_library_properties(${SWIG_MODULE_${library_name}_REAL_NAME} ".pyd")
    file(APPEND "${CMAKE_BINARY_DIR}/installed_files.log" "${rpath}/${SWIG_MODULE_${library_name}_REAL_NAME}.pyd\n")
    install (TARGETS ${SWIG_MODULE_${library_name}_REAL_NAME} DESTINATION ${INSTALL_FILE_DESTINATION}/${rpath})
  elseif (UNIX)
    #set_target_properties(${SWIG_MODULE_${library_name}_REAL_NAME} PROPERTIES
    #  SKIP_BUILD_RPATH FALSE
    #  BUILD_WITH_INSTALL_RPATH FALSE
    #  INSTALL_RPATH "${CMAKE_INSTALL_ORIG_PREFIX}/lib/dff/"
    #  INSTALL_RPATH_USE_LINK_PATH TRUE
    #  )
    file(APPEND "${CMAKE_BINARY_DIR}/installed_files.log" "${rpath}/${SWIG_MODULE_${library_name}_REAL_NAME}.so\n")
    install(TARGETS ${SWIG_MODULE_${library_name}_REAL_NAME} DESTINATION ${PYTHON_SITE_PACKAGES_PATH}/${rpath})
  endif ( CMAKE_GENERATOR MATCHES "Visual Studio" )

  install_file("${library_name}.py" ${__EXTRA_FILES__})
  add_dependencies(${current_target} ${SWIG_MODULE_${library_name}_REAL_NAME})
endmacro()

macro(PATH_TO_TARGET)
  # Obtain relative path
  file(RELATIVE_PATH rpath ${CMAKE_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR})
  # Replace all '/' with '.' resulting variable becomes current_target 
  string(REPLACE "/" "." current_target "${rpath}")
  # From current_target, extract the parent_target
  # parent_target completion depends on all its sub current_target
  string(FIND "${current_target}" "." dot_rpos REVERSE)
  if (${dot_rpos} EQUAL -1)
    set(parent_target "ALL")
  else (${dot_rpos} EQUAL -1)
    string(SUBSTRING ${current_target} 0 ${dot_rpos} parent_target)
  endif (${dot_rpos} EQUAL -1)
  log("[CONTEXT] :
  current target : ${current_target}
  parent target  : ${parent_target}
  relative path  : ${rpath}")
endmacro()

macro(install_rule file)
  split_path_file_extension(${file})
  if (NOT DEVELOP)
    if (NOT ${__PATH__} STREQUAL "")
       file(COPY ${file} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
    endif()
    if (${__EXTENSION__} STREQUAL "in")
      string(REPLACE ".${__EXTENSION__}" "" __FILE__ ${__FILE__})
      message("-- Configuring ${file} ---> ${__FILE__}")
      configure_file(${CMAKE_CURRENT_SOURCE_DIR}/${file} ${CMAKE_CURRENT_BINARY_DIR}/${__FILE__})
    endif()
    if ("${rpath}" STREQUAL "")
       set(ifile "${__FILE__}")
    else ("${rpath}" STREQUAL "")
       set(ifile "${rpath}/${__FILE__}")
    endif ("${rpath}" STREQUAL "")
    file(APPEND "${CMAKE_BINARY_DIR}/installed_files.log" "${ifile}\n")
    if (${ifile} MATCHES "^.*\\.py$")
      string(REPLACE "\\" "\\\\" pyc_file "${ifile}")
      string(REPLACE "/" "\\\\" pyc_file "${pyc_file}")
      get_property(pyc_list GLOBAL PROPERTY PYC_FILES)
      list(APPEND pyc_list "${pyc_file}c")
      set_property(GLOBAL PROPERTY PYC_FILES ${pyc_list})
    endif (${ifile} MATCHES "^.*\\.py$")
    log("    install rule : ${CMAKE_CURRENT_BINARY_DIR}/${__FILE__} DESTINATION ${INSTALL_FILE_DESTINATION}/${rpath}")
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${__FILE__} DESTINATION ${INSTALL_FILE_DESTINATION}/${rpath})
  endif (NOT DEVELOP)
endmacro()

macro(install_file)
  # Create empty strings which will contain all commands for the resulting current_target
  set(cmds "")
  path_to_target()
  # this loop iter on all files provided in ${ARGN} :
  #   * In install mode (default)
  #     - generate install rules
  #     - For windows targeted platfrom, generate all .py to .pyc to remove
  #       pyc files during desinstallation
  #   * all mode with build_dir != src_dir
  #     - create 'copy if different' command for each .py
  foreach(file ${ARGV})
    install_rule(${file})
    if (DEDICATED_BUILD_DIR)
      #message("Copying ${CMAKE_CURRENT_SOURCE_DIR}/${file} in ${CMAKE_CURRENT_BINARY_DIR}")
      # SWIG generated files are already present in CMAKE_CURRENT_BINARY_DIR
      if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${file})
	 if (cmds)
	    set(cmds ${cmds} &&)
	 endif (cmds)
	 set(cmds ${cmds} ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/${file} ${CMAKE_CURRENT_BINARY_DIR}/${file})
      endif(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${file})
    endif (DEDICATED_BUILD_DIR)
  endforeach(file ${ARGN})
  if ("${current_target}" STREQUAL "")
    set(current_target "root")
  endif()
  add_custom_target(${current_target} ALL ${cmds})
  set_target_properties(${current_target} PROPERTIES CREATED "true")
  get_property(created_targets GLOBAL PROPERTY CREATED_TARGETS)
  list(APPEND created_targets "${current_target}")
  set_property(GLOBAL PROPERTY CREATED_TARGETS ${created_targets})
  log("\n")
endmacro(install_file)


## Macro to copy lib at install
macro(install_lib target_name)
  file(RELATIVE_PATH rpath ${CMAKE_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR})
  string(REPLACE "/" "." current_target ${rpath})
  # From current_target, extract the parent_target
  # parent_target completion depends on all its sub current_target
  string(FIND "${current_target}" "." dot_rpos REVERSE)
  if (${dot_rpos} EQUAL -1)
    set(parent_target "ALL")
  else (${dot_rpos} EQUAL -1)
    string(SUBSTRING ${current_target} 0 ${dot_rpos} parent_target)
  endif (${dot_rpos} EQUAL -1)
  log("[CONTEXT] :
  current target : ${current_target}
  parent target  : ${parent_target}
  relative path  : ${rpath}")

endmacro(install_lib)

if (APPLE)
  SET(CMAKE_SHARED_LIBRARY_SUFFIX ".so")
  SET(CMAKE_SHARED_MODULE_SUFFIX ".so")
endif(APPLE)

## Macro to convert XML ui files to Python Qt widget code
# We are unable to use pyuic4 with QTreeWidget as base class
# It is why <widget class="QWidget" name="useless" /> has to be appended to .ui
# files using QTreeWidget. Be carreful, QtDesigner place this second widget at
# the end of the .ui file ; which make pyuic4 fails to compile.
macro(gui_resources_files target_name)
  path_to_target()
  set(cmds "")
  foreach(file ${ARGV})
    string(FIND ${file} "." ext_pos REVERSE)
    math(EXPR ext_pos "${ext_pos} + 1")
    string(SUBSTRING ${file} ${ext_pos} -1 extension)
    if (extension STREQUAL "ui")
      string(REGEX REPLACE "^(.*)\\.ui$" "ui_\\1.py" PYUICFILE ${file})
      set(cmd ${PYTHON_QT4_UIC} -o ${CMAKE_CURRENT_BINARY_DIR}/${PYUICFILE} ${CMAKE_CURRENT_SOURCE_DIR}/${file})
      install_rule(${PYUICFILE})
    elseif (extension STREQUAL "qrc")
      string(REGEX REPLACE "^(.*)\\.qrc$" "\\1_rc.py" PY_QRC_FILE ${file})
      set(cmd ${PYTHON_QT4_RCC} ${CMAKE_CURRENT_SOURCE_DIR}/${file} -o ${CMAKE_CURRENT_BINARY_DIR}/${PY_QRC_FILE})
      install_rule(${PY_QRC_FILE})
    elseif (extension STREQUAL "py")
      if (DEDICATED_BUILD_DIR)
	if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${file})
	  set(cmd ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/${file} ${CMAKE_CURRENT_BINARY_DIR}/${file})
	endif(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${file})
      endif (DEDICATED_BUILD_DIR)
      install_rule(${file})
    endif ()
    if (cmds)
      set(cmds ${cmds} && ${cmd})
    else()
      set(cmds ${cmd})
    endif()
  endforeach()
  add_custom_target(${current_target} ALL ${cmds})
  set_target_properties(${current_target} PROPERTIES CREATED "true")
  get_property(created_targets GLOBAL PROPERTY CREATED_TARGETS)
  list(APPEND created_targets "${current_target}")
  set_property(GLOBAL PROPERTY CREATED_TARGETS ${created_targets})
endmacro()
