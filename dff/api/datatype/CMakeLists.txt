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
#  Christophe Malinge <cma@digital-forensic.org>
#  Frederic Baguelin <fba@digital-forensic.org>
#  Solal Jacob <sja@digital-forensic.org>

if (WIN32)
  set(link_libraries types events)
else ()
  set(link_libraries pthread types events)
endif ()

dff_cpp_api(datatype 
  SWIG_FILE libdatatype.i
  CPP_FILES datatype.cpp
  LINK_LIBRARIES ${link_libraries}
  EXTRA_FILES __init__.py mimetree.py magichandler.py   
  )
