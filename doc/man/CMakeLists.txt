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

add_custom_target(man)

find_package (Docbook)
#USE OLD man OR DOCBOOK ?

#if (Docbook_FOUND)
  #include (${Docbook_USE_FILE})
  #if (UNIX)
    #option (BUILD_APPS_HELP_MAN "Build manpage application help files" ON)
    #option (BUILD_APPS_HELP_HTML "Build HTML application help files" OFF)
  #else (UNIX)
    #option (BUILD_APPS_HELP_HTML "Build HTML application help files" ON)
  #endif (UNIX)

  #set (OPENOBEX_APP_XML_FILE "${CMAKE_CURRENT_SOURCE_DIR}/openobex-apps.xml")
  #if (BUILD_APPS_HELP_MAN)
    #docbook_generate (manpage "${OPENOBEX_APP_XML_FILE}" XSLT_FILES_MAN)
    #foreach (file ${XSLT_FILES_MAN})
      #list (APPEND OPENOBEX_HELP_FILES ${file})
      #get_filename_component ( fileExt ${file} EXT)
      #string (REGEX REPLACE "^[.]" "" fileExt ${fileExt})
      #install (
	#FILES ${CMAKE_CURRENT_BINARY_DIR}/${file}
	#DESTINATION ${MANPAGE_INSTALL_DIR}/man${fileExt}
	#PERMISSIONS OWNER_READ OWNER_WRITE
                    #GROUP_READ
                    #WORLD_READ
	#COMPONENT documentation
	#OPTIONAL
      #)
    #endforeach (file)
  #endif (BUILD_APPS_HELP_MAN)

  #if (BUILD_APPS_HELP_HTML)
    #include (UseDocbook)
    #docbook_generate (html "${OPENOBEX_APP_XML_FILE}" XSLT_FILES_HTML)
    #foreach (file ${XSLT_FILES_HTML})
      #list (APPEND OPENOBEX_HELP_FILES ${file})
      #install (
	#FILES ${CMAKE_CURRENT_BINARY_DIR}/${file}
	#DESTINATION ${DOCUMENTATION_INSTALL_DIR}
	#PERMISSIONS OWNER_READ OWNER_WRITE
                    #GROUP_READ
                    #WORLD_READ
        #COMPONENT documentation
        #OPTIONAL
      #)
    #endforeach ( file )
  #endif (BUILD_APPS_HELP_HTML)

  #if (OPENOBEX_HELP_FILES)
    #add_custom_target (openobex-apps-doc DEPENDS ${OPENOBEX_HELP_FILES})
    #add_dependencies (openobex-apps openobex-apps-doc)
    #add_dependencies (doc openobex-apps-doc)
  #endif (OPENOBEX_HELP_FILES)
#endif (Docbook_FOUND)
