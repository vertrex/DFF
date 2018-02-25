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

install_file(
  __init__.py
  structparser.py
)

add_subdirectory (metaexif)
add_subdirectory (prefetch)
add_subdirectory (lnk)
add_subdirectory (compoundfile)
add_subdirectory (skindetection)
