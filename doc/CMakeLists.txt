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

option(DOC_GENERATE "Generate documentation" OFF)

if (DOC_GENERATE)
  add_custom_target(doc)
  add_dependencies(dff doc)
  set(DOC_INSTALL_DIR ${CMAKE_INSTALL_ORIG_PREFIX}/share/doc/${CMAKE_PROJECT_NAME}-${PROJECT_VERSION})

#
### DOXYGEN / DOC DEVELOPER CONFIGURATION
#
  option(DOC_GENERATE_DEVELOPER "Build developer guide" ON)

  set(DOC_DEVELOPER_PROJECT_NAME "${PROJECT_NAME}")
  set(DOC_DEVELOPER_PROJECT_BRIEF "${PROJECT_FULL_NAME}")
  set(DOC_DEVELOPER_LOGO_FILE_PATH ${CMAKE_SOURCE_DIR}/"ressources/dff.png")
  set(DOC_DEVELOPER_VERSION "${PROJECT_VERSION}")
  set(DOC_DEVELOPER_OUTPUT_TYPES HTML QCH) #LATEX
  #set(DOC_DEVELOPER_LATEX_OUTPUT_FILE "refman.tex")
  set(DOC_DEVELOPER_HTML_OUTPUT_FILE "index.html")
  set(DOC_DEVELOPER_QCH_OUTPUT_FILE "dff_developer.qch")
  set(DOC_DEVELOPER_SOURCES
  "${CMAKE_SOURCE_DIR}/dff/api/include/vfs.hpp"
  "${CMAKE_SOURCE_DIR}/dff/api/include/node.hpp"
  "${CMAKE_SOURCE_DIR}/dff/api/include/filemapping.hpp"
  "${CMAKE_SOURCE_DIR}/dff/api/include/fso.hpp"
  "${CMAKE_SOURCE_DIR}/dff/api/include/mfso.hpp"
  "${CMAKE_SOURCE_DIR}/dff/api/vfs/vfs.cpp"
  "${CMAKE_SOURCE_DIR}/dff/api/vfs/node.cpp"
  "${CMAKE_SOURCE_DIR}/dff/api/vfs/filemapping.cpp"
  "${CMAKE_SOURCE_DIR}/dff/api/vfs/fso.cpp"
  "${CMAKE_SOURCE_DIR}/dff/api/vfs/mfso.cpp"
  "${CMAKE_SOURCE_DIR}/doc/developer/dff.coverpage")
  add_subdirectory(developer)

#
# DOCBOOK / GUIDE CONFIGURATION
#
  option(DOC_GENERATE_GUIDE_HTML "Build HTML application guide" ON)
  option(DOC_GENERATE_GUIDE_QHP  "Build QHP application guide" ON)
  # Languages specifig settings
  set(DOC_GUIDE_LANGUAGES "en" "fr")

  # English settings
  set(DOC_GUIDE_QHP_SECTION_MAIN_NAME_EN "English guide")
  set(DOC_GUIDE_QHP_SECTION_CHAPTER_NAME_EN "Chapter")
  set(DOC_GUIDE_QHP_FILES_EN "en/resources/*" "en/html/*.html")

  # French settings
  set(DOC_GUIDE_QHP_SECTION_MAIN_NAME_FR "Guide Francais")
  set(DOC_GUIDE_QHP_SECTION_CHAPTER_NAME_FR "Chapitre")
  set(DOC_GUIDE_QHP_FILES_FR "en/resources/*" "fr/html/*.html")
  
  # Common settings
  set(DOC_GUIDE_XML_MAIN_FILE "main.xml")
  set(DOC_GUIDE_QHP_VIRTUAL_FOLDER "doc")
  set(DOC_GUIDE_QHP_FILE_NAME_PREFIX "dff_guide")
  set(DOC_GUIDE_QHP_NAMESPACE_PREFIX "org.digital-forensic")
  set(DOC_GUIDE_QHP_PROJECT_NAME "${PROJECT_NAME}")
  set(DOC_GUIDE_QHP_PROJECT_VERSION "${PROJECT_VERSION}")
  set(DOC_GUIDE_QHP_FILTER ${DOC_GUIDE_PROJECT_NAME} ${DOC_GUIDE_QHP_PROJECT_VERSION})
  add_subdirectory(guide)

  
#
# QT / GENERATOR / COLLECTION CONFIGURATIOB
#
  option(DOC_GENERATE_QHC "Build QHC documentation resource file" ON)

  set(DOC_QHC_COLLECTION_PROJECT_FILE_IN "dff_doc.qhcp.in")
  set(DOC_QHC_COLLECTION_PROJECT_FILE "dff_doc.qhcp")
  set(DOC_QHC_COLLECTION_FILE "dff_doc.qhc")
  add_subdirectory(qhc)

endif(DOC_GENERATE)
