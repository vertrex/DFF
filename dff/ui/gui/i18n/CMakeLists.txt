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
#  Christophe Malinge <cma@digital-forensic.org>

# please keep the list of supported languages sorted alphabetically
set(DFF_SUPPORTED_LANGUAGES "de" "en" "es" "fr" "it" "nl" "zh")

# Please also take care of dff.pro file !

# Configure step
execute_process(COMMAND ${PYTHON_QT4_LANGUAGE} -verbose "${CMAKE_CURRENT_SOURCE_DIR}/dff.pro")

foreach(LANGUAGE ${DFF_SUPPORTED_LANGUAGES})
  set(QM_OUTPUT_FILES ${QM_OUTPUT_FILES} "Dff_${LANGUAGE}.qm")
# Build step
  add_custom_target(gui_translation_${LANGUAGE} ALL
    COMMAND ${QT_LANGUAGE_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR}/Dff_${LANGUAGE}.ts -qm ${CMAKE_CURRENT_BINARY_DIR}/Dff_${LANGUAGE}.qm
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/Dff_${LANGUAGE}.ts
    )
endforeach(LANGUAGE ${DFF_SUPPORTED_LANGUAGES})

install_file(${QM_OUTPUT_FILES})
