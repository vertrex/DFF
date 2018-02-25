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

install_file(__init__.py)

include_directories("${CMAKE_SOURCE_DIR}/dff/api/exceptions/breakpad")

add_subdirectory (archive)
add_subdirectory (volumes)
add_subdirectory (fs)
add_subdirectory (builtins)
add_subdirectory (search)
add_subdirectory (viewer)
add_subdirectory (statistics)
add_subdirectory (ram)
add_subdirectory (node)
add_subdirectory (connector)
add_subdirectory (hash)
add_subdirectory (metadata)
add_subdirectory (databases)
add_subdirectory (mailbox)
add_subdirectory (export)
