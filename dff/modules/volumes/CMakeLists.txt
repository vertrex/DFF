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

add_subdirectory(partition)
add_subdirectory(vmware)

if(LIBVSHADOW_FOUND AND LIBBFIO_FOUND)
  add_subdirectory (vshadow)
else(LIBVSHADOW_FOUND AND LIBBFIO_FOUND)
  message(STATUS "VSHADOW or BFIO library not found. Vshadow module will not be built.")
endif(LIBVSHADOW_FOUND AND LIBBFIO_FOUND)


install_file(
  __init__.py
)
