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

# size of a chunk
CHUNK_NORRIS = 65536

#criticity level
SUCCESS = 0
ERROR = 2
WARNING = 3
INFORMATION = 4

__dff_module_evtx_version__ = "1.0.0"

from types import *

from dff.api.vfs.libvfs import mfso 
from dff.api.types.libtypes import Argument, typeId, Variant, VMap
from dff.api.module.module import Module 
from dff.api.module.manager import ModuleProcessusManager

from dff.modules.evtx.evtx_header import EvtxHeader 
from dff.modules.evtx.template import Template
from dff.modules.evtx.Chunk import Chunk
from dff.modules.evtx.record import Record
from dff.modules.evtx.manager import EvtxManager

ModuleProcessusManager().register(EvtxManager('evtx'))

class EVTX(mfso):
    def __init__(self):
        mfso.__init__(self, "evtx")
        self.name = "evtx"
        self.__disown__()
        self.node = None
        self.attributeHandler = None
        self.chunks = []

    def start(self, args):

        try:
            self.node = args['file'].value()
        except KeyError:
            print "Missing argument '--file'. Cannot proceed. Exiting."
            return

        # get evtx header
        vfile = self.node.open()
        evtx_header = EvtxHeader(vfile)

        try:
            if evtx_header.Magic != "ElfFile\0":
                print "Bad evtx file : magic does not match 'ElfFile'"
            else:
                # the first chunk starts where the file header's end
                offset = evtx_header.HeaderSize

                # for all chunks in the file
                for i in range(evtx_header.ChunkCount):
                    # get their headers
                    current_chunk = Chunk(vfile, offset)

                    # get all event s stored in the current chunk
                    current_chunk.getEvents()

                    # store the chunk in the chunk list and increment offset to the
                    # beginning of the next chunk
                    self.chunks.append(current_chunk)
                    offset += CHUNK_NORRIS
        except:
            pass
        finally:
            vfile.close()

    def light_parser(self, node):
        data = {}
        try:
            vfile = node.open()
            evtx_header = EvtxHeader(vfile)

            data['File'] = node.name()
            data['Oldest'] =  str(evtx_header.OldestChunk)
            data['Current'] = str(evtx_header.CurrentChunkNum)
            data['Next'] = str(evtx_header.NextRecordNum)
            data['Min'] = str(evtx_header.MinorVersion)
            data['Maj'] = str(evtx_header.MajorVersion)
            data['chunk_nb'] = str(evtx_header.ChunkCount)

            offset = evtx_header.HeaderSize

            # for all chunks in the file
            for i in range(evtx_header.ChunkCount):
                # get their headers
                current_chunk = Chunk(vfile, offset)
                key =  str(i)
                data[key] = [ str(current_chunk.evtx_chunk.NumLogRecFirst), \
                                  str(current_chunk.evtx_chunk.NumLogRecLast), str(offset)]
                offset += CHUNK_NORRIS
        except:
            print "Error"
            pass
        finally:
            vfile.close()
        return data

    def chunks(self):
        return self.__chunks

class evtx(Module):
  """This modules permit to virtualy reconstruct windows vista/7 event log files (evtx)."""
  def __init__(self):
    Module.__init__(self, "evtx", EVTX)
    self.conf.addArgument({"name": "file",
                           "description": "MS Windows Vista Event Log file",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type",
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["evtx-log"]})
    self.tags = "Databases"
    self.icon = ":database"
