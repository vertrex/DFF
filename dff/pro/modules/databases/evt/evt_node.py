# DFF -- An Open Source Digital Forensics Framework
#
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
#  Romain BERTHOLON < rbe@digital-forensic.fr>
#

from dff.api.vfs import *
from dff.api.types.libtypes import Variant, VList, VMap, Argument, Parameter, typeId
from dff.api.vfs.libvfs import *

class EvtNode(Node):
    def __init__(self, event_id, size, parent, mfso, evt_record):
        Node.__init__(self, event_id, size, parent, mfso)
        self.__disown__()
        self.evt_record = evt_record

    def _attributes(self):
      attr = VMap()
      attr.thisown = False

      try:
          vlist = Variant(self.evt_record.getStrings(), typeId.String)
          vlist.thisown = False
          attr["Log strings"] = vlist
      except RuntimeError:
          pass

      s_name = Variant(self.evt_record.sourceName())
      attr["Source name"] = s_name

      c_name = Variant(self.evt_record.computerName())
      attr["Computer name"] = c_name

      event_type = Variant(self.evt_record.eventType())
      attr["Event type"] = event_type

      time_gen = Variant(self.evt_record.getTimeGenerated())
      attr["Time generated"] = time_gen

      time_written = Variant(self.evt_record.getTimeWritten())
      attr["Time written"] = time_written

      return attr
