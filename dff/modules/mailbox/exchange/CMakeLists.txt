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

if(WIN32)
  set(definitions -DHAVE_INT8_T -DLIBPFF_HAVE_BFIO -D_LIBPFF_TYPES_H_INTEGERS -D_LIBBFIO_TYPES_H_INTEGERS)
endif()

dff_cpp_module(PFF
  CPP_FILES pff.cpp
  pff_info.cpp
  pff_export.cpp
  pff_item_info.cpp
  pff_node_data.cpp
  pff_node_task.cpp
  pff_node_folder.cpp
  pff_node_contact.cpp
  pff_node_attachment.cpp
  pff_node_appointment.cpp
  pff_node_unallocated_blocks.cpp
  pff_node_email.cpp
  pff_node_email_message.cpp
  pff_node_email_attributes.cpp
  pff_node_email_transport_headers.cpp
  SWIG_FILE pff.i
  DEFINITIONS ${definitions}
  LINK_LIBRARIES exceptions types vfs ${LIBPFF_LIBRARY}
  INCLUDE_DIRS ${LIBPFF_INCLUDE_DIR} ${LIBBFIO_INCLUDE_DIR}
  EXTRA_FILES ${LIBPFF_RUNTIME_LIBRARY}
  )
