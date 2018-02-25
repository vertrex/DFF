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


set(swig_flags ${CMAKE_SWIG_FLAGS} -threads -fvirtual -fastdispatch)
IF (WIN32)
  set(swig_flags ${swig_flags} -DWIN32)	
ENDIF(WIN32)

dff_cpp_api(types
  CPP_FILES constant.cpp argument.cpp config.cpp path.cpp datetime.cpp variant.cpp confmanager.cpp threading.cpp ../vfs/rc.cpp
  SWIG_FILE libtypes.i
  DEFINITIONS -D__STDC_LIMIT_MACROS
  SWIG_FLAGS ${swig_flags}
  LINK_LIBRARIES exceptions
  EXTRA_FILES __init__.py
  )
