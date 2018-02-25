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
#  Solal Jacob <sja@digital-forensic.org>

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/gui.py ${CMAKE_CURRENT_BINARY_DIR}/gui.py)

install_file(
  __init__.py
  gui.py
  mainwindow.py
  translator.py
)

add_subdirectory(resources)
add_subdirectory(i18n)
add_subdirectory(ide)
add_subdirectory(utils)
add_subdirectory(widget)
add_subdirectory(dialog)
add_subdirectory(csv)
