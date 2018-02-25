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

macro(GENERATE_GUIDE lang)
  if(DOC_GENERATE_GUIDE_HTML)
    find_package(Docbook)
    include (${Docbook_USE_FILE})
    include (UseDocbook)
    set (DOC_GUIDE_XML_MAIN_FILE_ABS "${CMAKE_CURRENT_SOURCE_DIR}/../xml/${DOC_GUIDE_XML_MAIN_FILE}")


    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../resources")
      file(COPY ../resources DESTINATION .)
      install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../resources"
              DESTINATION ${DOC_INSTALL_DIR}/guide/${lang}/
              COMPONENT documentation
              OPTIONAL)
    endif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../resources")


    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../images")
      file(COPY ../images DESTINATION .)
      install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../images"
              DESTINATION ${DOC_INSTALL_DIR}/guide/${lang}/
              COMPONENT documentation
              OPTIONAL)

    endif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../images")


    docbook_generate(html "${DOC_GUIDE_XML_MAIN_FILE_ABS}" XSLT_FILES_HTML)
    foreach(file ${XSLT_FILES_HTML})
      list(APPEND DOC_GUIDE_${lang}_FILES ${file})
    endforeach(file)

    if(DOC_GUIDE_${lang}_FILES)
      install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
	      DESTINATION ${DOC_INSTALL_DIR}/guide/${lang}/
              COMPONENT documentation
              OPTIONAL)
      set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "*.html")
      add_custom_target(doc.guide.${lang}.html DEPENDS ${DOC_GUIDE_${lang}_FILES})
      add_dependencies(doc.guide.${lang} doc.guide.${lang}.html)
    endif(DOC_GUIDE_${lang}_FILES)
  endif(DOC_GENERATE_GUIDE_HTML)
endmacro()

find_package(Docbook)
if(Docbook_FOUND)
  if (DOC_GENERATE_GUIDE_HTML)
    include (${Docbook_USE_FILE})

    add_custom_target(doc.guide)
    add_dependencies(doc.guide doc)

    foreach(lang ${DOC_GUIDE_LANGUAGES})
      add_custom_target(doc.guide.${lang})
      add_dependencies(doc.guide doc.guide.${lang})
      add_subdirectory(${lang})

      string(TOUPPER "${lang}" lang_up)
      if(DOC_GENERATE_GUIDE_QHP)
        set(DOC_GUIDE_QHP_NAMESPACE "${DOC_GUIDE_QHP_NAMESPACE_PREFIX}.${DOC_GUIDE_QHP_FILE_NAME_PREFIX}_${lang}")
        set(DOC_GUIDE_QHP_SECTION_MAIN_NAME ${DOC_GUIDE_QHP_SECTION_MAIN_NAME_${lang_up}})
        set(DOC_GUIDE_QHP_TOC "<section title=\"${DOC_GUIDE_QHP_SECTION_MAIN_NAME}\" ref=\"${lang}/html/index.html\"></section>")
        foreach(file ${DOC_GUIDE_QHP_FILES_${lang_up}})
          list(APPEND DOC_GUIDE_QHP_FILES "<file>${file}</file>")
        endforeach(file)
        string(REPLACE ";" "" DOC_GUIDE_QHP_FILES "${DOC_GUIDE_QHP_FILES}")

        configure_file(${CMAKE_CURRENT_SOURCE_DIR}/${DOC_GUIDE_QHP_FILE_NAME_PREFIX}.qhp.in
                   ${CMAKE_CURRENT_BINARY_DIR}/${DOC_GUIDE_QHP_FILE_NAME_PREFIX}_${lang}.qhp
                   @ONLY)
      endif(DOC_GENERATE_GUIDE_QHP)
    endforeach(lang)
  endif(DOC_GENERATE_GUIDE_HTML)
else(Docbook_FOUND)
  set(DOC_GENERATE_GUIDE_HTML OFF)
endif(Docbook_FOUND)
