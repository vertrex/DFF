# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
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
#  Romain Bertholon <rbe@digital-forensic.org>

install_file(
  __init__.py
  Chunk.py
  decoder.py
  dtime.py
  evtx.py
  evtx_xml.py
  evtx_header.py
  record.py
  manager.py
  sub_array.py
  template.py
  xml_headers.py
  xml_node.py
)
