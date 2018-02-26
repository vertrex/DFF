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

__dff_module_evt_version__ = "1.0.0"

from dff.api.vfs.libvfs import mfso 
from dff.api.module.module import Module
from dff.api.types.libtypes import Argument, typeId
from dff.api.exceptions.libexceptions import vfsError
from dff.api.module.manager import ModuleProcessusManager

from dff.modules.evt.evt_header import *
from dff.modules.evt.evt_node import EvtNode
from dff.modules.evt.manager import EvtManager
        
ModuleProcessusManager().register(EvtManager('evt'))

class EVT(mfso):
    def __init__(self):
        mfso.__init__(self, "evt")
        self.name = "evt"
        self.__disown__()
        self.record_list = []
        self.offset = 0

    def start(self, args):
        try:
            self.node = args['file'].value()
        except KeyError:
            print "Missing argument file. Cannot proceed. Exiting."
            return
        vfile = None
        try:
            vfile = self.node.open()
        except vfsError:
            print 'Evt : could not open node \'%s\'. Exiting.' % (node.name(), )
        #getting header
        try:
            evt_header = Header(vfile)
            if not evt_header.isValid():
                print "Evt header not valid"
                return

            end_offset = evt_header.EndOffset
            evt_eof = EofRecord(vfile, end_offset, EVENTEOFRECORD)
            if not evt_eof.isValid():
                print "The EOF structure does not seem to be valid : the signature does not match."
            # getting all records
            self.offset = evt_header.StartOffset
            while self.offset != end_offset:
                evt_record = Record(vfile, self.offset, EVENTLOGRECORD)
                if not evt_record.isValid():
                    print "Invalid record : the signature does not match."
                    break
                vfile.seek(self.offset + evt_record.templateSize())

                # get content of the current record
                self.readRecordContent(evt_record, evt_header, vfile)	
                evt_record.parseContent()
                self.record_list.append(evt_record)
        except Exception as e:
	    raise e
        finally:
            vfile.close()

    def readRecordContent(self, evt_record, evt_header, vfile):
        """
        This method reads the content of a record according to the record header `evt_record`
        and the current offset. It wrappes from the end to the begening of the file if
        necessary.
        """

        if not evt_header.Retention and (evt_record.Length + self.offset > evt_header.MaxSize):
            reminder = (evt_header.MaxSize - (self.offset + evt_record.templateSize()))
            buff = vfile.read(reminder)

            vfile.seek(evt_header.headerSize)
            buff += vfile.read(evt_record.Length - reminder)

            self.offset = evt_record.Length - reminder + evt_header.headerSize \
                - evt_record.templateSize()
            evt_record.setBuff(bytearray(buff))
            return buff

        buff = vfile.read(evt_record.Length - evt_header.templateSize())
        evt_record.setBuff(bytearray(buff))
        self.offset += evt_record.Length
        return buff

class evt(Module):
  """This modules permit to virtualy reconstruct windows NT event log files."""
  def __init__(self):
    Module.__init__(self, "evt", EVT)
    self.conf.addArgument({"name": "file",
                           "description": "MS Windows NT event logs",
                           "input": Argument.Required|Argument.Single|typeId.Node})

    self.conf.addConstant({"name": "mime-type",
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["evt-log"]})
    self.tags = "Databases"
    self.icon = ":database"
