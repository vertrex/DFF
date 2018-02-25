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
# 

from dff.modules.evtx.evtx_header import *
from dff.modules.evtx.record import Record

class Chunk:
    def __init__(self, vfile, offset):
        self.__vfile = vfile
        self.__offset = offset
        self.__events = {}
        self.__is_valid = True
        self.__record_nb = 0

        self.__vfile.seek(self.__offset)
        self.__chunk_stream = self.__vfile.read(65536)
        self.evtx_chunk = EvtxChunk(self.__chunk_stream, 0)

        if self.evtx_chunk.Magic != "ElfChnk\0":
            print "Bad evtx chunk : magic does not match 'ElfChnk'"
            self.__is_valid = False
        else:
            self.__record_nb = self.evtx_chunk.NumLogRecLast - self.evtx_chunk.NumLogRecFirst + 1

    def getEvents(self):
        offset_rec = self.evtx_chunk.templateSize()
        size = 0
        for j in range(self.__record_nb):
            record = Record(self.__chunk_stream, offset_rec, size)
            size += record.len
            offset_rec += record.len
            
            event = {'id': record.id, 'source': record.source.replace('Microsoft-Windows-', ''), \
                         'date': record.date, 'level': record.lvl}
            self.__events[record._offset_rec] = event

    def nbRecord(self):
        return len(self.__events)

    def getEvent(self, offset):
        try:
            event = {}
            event[offset] = self.__events[offset]
            return event
        except KeyError:
            return {}

    def events(self):
        return self.__events

    # used for debug
    def dispEvents(self):
        for i in self.__events:
            print "---- Event at ", i
            print "\i" , self.__events[i]

    def offset(self):
        return self.__offset
