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

install_file(
  __init__.py
  )

add_subdirectory(devices)

add_subdirectory (local)
IF (LIBEWF_FOUND)
  add_subdirectory (ewf)
ELSE (LIBEWF_FOUND)
  message(STATUS "EWF library not found. Ewf module will not be built.")
ENDIF (LIBEWF_FOUND)

if (AFF_FOUND)
   add_subdirectory(aff)
else (AFF_FOUND)
    message(STATUS "AFF library not found. Connector module will not be built.")
endif(AFF_FOUND)
