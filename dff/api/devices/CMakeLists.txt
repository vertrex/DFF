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

if (UNIX)
  if (HAVE_UDEV)
    set(cpp_files device.cpp udevice.cpp)
    set(swig_flags "-DHAVE_LIBUDEV_H=1")
    set(definitions "-DHAVE_LIBUDEV_H")
    set(link_libraries ${UDEV_LIBRARY})
  else ()
    set(cpp_files device.cpp)
  endif()
  dff_cpp_api(devices
    SWIG_FILE libdevices.i
    CPP_FILES ${cpp_files}
    LINK_LIBRARIES ${link_libraries}
    DEFINITIONS ${definitions}
    SWIG_FLAGS ${swig_flags}
    EXTRA_FILES __init__.py devices.py dbushaldev.py
    )
else (UNIX)
  add_definitions(-DUNICODE -D_UNICODE)
  dff_cpp_api(devices
    SWIG_FILE libdevices.i
    CPP_FILES device.cpp logicaldrive.cpp wmidev.cpp
    EXTRA_FILES __init__.py devices.py
    #LINK_LIBRARIES Shlwapi
    )
endif(UNIX)
