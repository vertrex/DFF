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
#  Solal Jacob <sja@digital-forensic.org>

find_program(QHELPGENERATOR_EXECUTABLE qhelpgenerator)
find_program(QCOLLECTIONGENERATOR_EXECUTABLE qcollectiongenerator)
if(DOC_GENERATE_QHC AND QHELPGENERATOR_EXECUTABLE AND QCOLLECTIONGENERATOR_EXECUTABLE)
  add_custom_target(doc.qhc)
  add_dependencies(doc doc.qhc)

  if(DOC_GENERATE_GUIDE_HTML AND DOC_GENERATE_GUIDE_QHP)
    foreach(lang ${DOC_GUIDE_LANGUAGES})
      list(APPEND QHC_GUIDE_DEPENDENCIES doc.guide.${lang}.qhc)
      list(APPEND QCH_GUIDE_FILES ${DOC_GUIDE_QHP_FILE_NAME_PREFIX}_${lang}.qch)
      list(APPEND DOC_QHC_COLLECTION_FILES_XML  "<file>${DOC_GUIDE_QHP_FILE_NAME_PREFIX}_${lang}.qch</file>")
      add_custom_target(doc.guide.${lang}.qhc
                      DEPENDS doc.guide.${lang}.html
                      COMMAND ${QHELPGENERATOR_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/../guide/${DOC_GUIDE_QHP_FILE_NAME_PREFIX}_${lang}.qhp -o ${CMAKE_CURRENT_BINARY_DIR}/dff_guide_${lang}.qch 
                      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/../guide)
      set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ${CMAKE_CURRENT_SOURCE_DIR}/${DOC_GUIDE_QHP_FILE_NAME_PREFIX}_${lang}.qch) 
      install(FILES ${CMAKE_CURRENT_BINARY_DIR}/dff_guide_${lang}.qch
              DESTINATION ${DOC_INSTALL_DIR}/qhc/
              COMPONENT doc
              OPTIONAL)
    endforeach(lang)
  endif(DOC_GENERATE_GUIDE_HTML AND DOC_GENERATE_GUIDE_QHP)

  if(DOC_GENERATE_DEVELOPER) 
    list(APPEND DOC_QHC_COLLECTION_FILES_XML  "<file>${DOC_DEVELOPER_QCH_OUTPUT_FILE}</file>")
    string (REPLACE ";" "" DOC_QHC_COLLECTION_FILES_XML "${DOC_QHC_COLLECTION_FILES_XML}")
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${DOC_DEVELOPER_QCH_OUTPUT_FILE}
            DESTINATION ${DOC_INSTALL_DIR}/qhc/
            COMPONENT doc
            OPTIONAL)
  endif(DOC_GENERATE_DEVELOPER)

  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/${DOC_QHC_COLLECTION_PROJECT_FILE_IN}
                 ${CMAKE_CURRENT_BINARY_DIR}/${DOC_QHC_COLLECTION_PROJECT_FILE}
                 @ONLY)
  add_custom_target(doc.qhc.collection
                    DEPENDS ${QHC_GUIDE_DEPENDENCIES} doc.developer.qch
                    COMMAND ${QCOLLECTIONGENERATOR_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/${DOC_QHC_COLLECTION_PROJECT_FILE} -o ${DOC_QHC_COLLECTION_FILE} 
                    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${DOC_QHC_COLLECTION_FILE}
          DESTINATION ${DOC_INSTALL_DIR}/qhc/
          COMPONENT doc
          OPTIONAL) 
  set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${DOC_QHC_COLLECTION_FILE};${DOC_DEVELOPER_QCH_OUTPUT_FILE};${QCH_GUIDE_FILES}")

  add_dependencies(doc.qhc ${QHC_GUIDE_DEPENDENCIES} doc.qhc.collection)
else(DOC_GENERATE_QHC AND QHELPGENERATOR_EXECUTABLE AND QCOLLECTIONGENERATOR_EXECUTABLE)
  set(DOC_GENERATE_QHC OFF)
endif(DOC_GENERATE_QHC AND QHELPGENERATOR_EXECUTABLE AND QCOLLECTIONGENERATOR_EXECUTABLE)
