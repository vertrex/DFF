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

if (UNIX)
  set(local_srcs
    ulocal.cpp
    ulocalnode.cpp
    )
else (UNIX)
  add_definitions(-DUNICODE -D_UNICODE)
  set(local_srcs
    wlocal.cpp
    wlocalnode.cpp
    )
endif(UNIX)

dff_cpp_module(LOCAL
  CPP_FILES ${local_srcs}
  SWIG_FILE local.i
  LINK_LIBRARIES exceptions types vfs
  EXTRA_FILES __init__.py
  )
