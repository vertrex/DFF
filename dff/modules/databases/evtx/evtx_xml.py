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

import datetime
from datetime import *
from types import StringType

from dff.api.module.manager import ModuleProcessusManager

from dff.modules.evtx.Chunk import Chunk
from dff.modules.evtx.record import Record

class EvtxXml:
    def __init__(self, chunks, node):
        self.node = node

    def getEventById(self, event_id):
        return self.getEventByParam('id', event_id)

    def getEventByDate(self, date):
        return self.getEventByParam('date', date)
    
    def getEventBySource(self, source):
        return self.getEventByParam('source', source)

    def getEventBylevel(self, level):
        return self.getEventByParam('level', level)

    def getEventsBetween(self, date_begin, date_end):
        processus_manager = ModuleProcessusManager()
        evtx = processus_manager.get('evtx')
        chunks = evtx.data(self.node.uid())

        try:
            date_begin_t = date_begin
            if type(date_begin) is StringType:
                date_begin_t = datetime.strptime(date_begin, "%Y-%m-%dT%H:%M:%S")
            else:
                date_begin_t = datetime.fromtimestamp(date_begin)

            date_end_t = date_end
            if type(date_end) is StringType:
                date_end_t = datetime.strptime(date_end, "%Y-%m-%dT%H:%M:%S")
            else:
                date_end_t = datetime.fromtimestamp(date_end)

            tmp_list = []
            count = 0
            chunk_nb = 0
            for chunk in chunks:
                events = chunk.events()
                tmp_map = {}
                for event in events:
                    event_date = datetime.strptime(events[event]['date'], "%Y-%m-%dT%H:%M:%S")                    
                    if event_date >= date_begin_t and event_date <= date_end_t:
                        tmp_map[event] = events[event]
                        tmp_map[event]['chunk_nb'] = chunk_nb
                        #self.getXML(count, event)
                count += 1
                tmp_list.append(tmp_map)
                chunk_nb += 1
            return tmp_list
        except ValueError:
            print "One of the date you are trying to use is invalid."
            return []

    def getEventByParam(self, param, value):
        if self.node is None:
            return []

        tmp_list = []
        nb_chunk = 0

        processus_manager = ModuleProcessusManager()
        evtx = processus_manager.get('evtx')
        chunks = evtx.data(self.node.uid())

        for chunk in chunks:
            events = chunk.events()
            tmp_map = {}
            for event in events:
                if events[event][param] == value:
                    tmp_map[event] = events[event]
                    tmp_map[event]['chunk_nb'] = nb_chunk
            tmp_list.append(tmp_map)
            nb_chunk += 1
        return tmp_list

    def getXML(self, chunk, offset, node=None):
        processus_manager = ModuleProcessusManager()
        evtx = processus_manager.get('evtx')

        if node is not None:
            self.node = node

        return evtx.getxml(chunk, offset, node)
