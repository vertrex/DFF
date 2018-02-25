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

from xml.dom.minidom import parseString
from xml.etree.ElementTree import tostring, tostringlist, Element

from PyQt4.QtCore import Qt, QCoreApplication
from PyQt4.QtGui import QTableWidgetItem, QIcon, QPixmap, QListWidget, QSplitter, QListWidgetItem, QWidget, QVBoxLayout, QLabel

from dff.api.vfs.libvfs import VFS
from dff.api.module.manager import ModuleProcessusHandler, ModuleProcessusManager

#from dff.pro.api.report.document import ReportFramedDocument, ReportDocument, ReportFragmentTable, ReportFragmentHtml, ReportManager

from dff.modules.evtxviewer.evtxviewerpanel import EventLogViewer
from dff.modules.evt.manager import EvtControlPannel
from dff.modules.evtx.record import Record, EvtxInfo

class EvtxManager(ModuleProcessusHandler):
    def __init__(self, name):
        ModuleProcessusHandler.__init__(self, name)
        self.node_name = {}
        self.vfs = VFS.Get()

    def update(self, processus):
        self.node_name[processus.node.uid()] = processus.chunks

    def getbyid(self, evtx_id, method, root='/', **kwargs):
        return res

    def getWidgetById(self, evtx_id, root):
        widget = EventLogViewer(None)
        widget.admin_pannel.hide()
        
        for ptr, chunks in self.getData():
            node = self.vfs.getNodeById(ptr)

            if node.absolute()[:len(root)] != root: continue
    
            count = 0
            for chunk in self.node_name[ptr]:
                for event in chunk.events():
                    match = True
                    for f in evtx_id:
                        match = chunk.events()[event][f] in evtx_id[f]
                        if not match : break
                    if match:
                        self.add_event_to_widget(event, chunk.events()[event], count, ptr, widget)
                count += 1

    def getXmlById(self, evtx_id, root):
        dict_attr = {}
        for i in evtx_id:
            dict_attr[i] = ''
            for j in evtx_id[i]:
                dict_attr[i] += (str(j) + ', ')

        root_xml = Element('Events', dict_attr)

        for ptr, chunks in self.getData():
            node = self.vfs.getNodeById(ptr)

            if node.absolute()[:len(root)] != root: continue

            count = 0
            for chunk in self.node_name[ptr]:
                for event in chunk.events():
                    match = True
                    for f in evtx_id:
                        match = chunk.events()[event][f] in evtx_id[f]
                        if not match : break
                    if match:
                        xml = self.getxml(count, event, node)
                        root_xml.append(xml)
                count += 1
        return root_xml

    def getxml(self, chunk, offset, node, root='/'):
        if type(node) == long:
          chunk_t = self.node_name[node][chunk]
          node = self.vfs.getNodeById(node)
        else:
          chunk_t = self.node_name[node.uid()][chunk]
        stream = None
        try:
            vfile = node.open()
            vfile.seek(chunk_t.offset())
            stream = vfile.read(65536)
        except:
            pass
        finally:
            vfile.close()
            if stream is not None:
                return Record(stream, offset, 0).root
            return None
        
    def getall(self, root):
      try : 
        return EvtxWidget(self, root)
      except Exception as e:
        print e

    def getData(self):
        for node_ptr, chunks in self.node_name.items():
            yield node_ptr, chunks

    def data(self, node):
        try:
            return self.node_name[node]
        except:
            return []

class EvtxWidget(EventLogViewer):
  def __init__(self, evtxManager, root):
     EventLogViewer.__init__(self, None)
     self.evtxManager = evtxManager
     self.vfs = VFS.Get()

     self.evtx_table_view.setColumnCount(7)
     self.evtx_table_view.hideColumn(4)
     self.evtx_table_view.hideColumn(5)
     self.evtx_table_view.hideColumn(6)

     self.admin_pannel.hide()

     self.list_widget = QListWidget()
     file_names = QLabel('Windows events')

     ww = QWidget()
     l = QVBoxLayout(ww)
     l.addWidget(file_names)
     l.addWidget(self.list_widget)
     l.setSpacing(2)
     l.setContentsMargins(2, 2, 2, 2)

     for node_name, chunks in self.evtxManager.getData():
        node = self.vfs.getNodeById(node_name)

        if node.absolute()[:len(root)] != root: 
          continue

        item = QListWidgetItem(QIcon(':/toggle_log'), node.name().replace('Microsoft-Windows-', '').replace('.evtx', ''))
        item.setData(QListWidgetItem.UserType, long(node_name))
        self.list_widget.addItem(item)

     self.list_widget.sortItems()

     self.list_widget.itemClicked.connect(self.fill_log_viewer)

     self.splitter.insertWidget(0, ww)
     ctrl = EvtControlPannel(self.evtx_table_view)
     self.splitter.insertWidget(2, ctrl)

     self.list_widget.itemClicked.connect(ctrl.reload)

  def report(self):
     reportManager = ReportManager()
     events = self.evtx_table_view.selectedEvents()
     eventsByNode = {}
     for event in events:
        try:
          eventsByNode[event.node()].append(event)
        except KeyError:
          eventsByNode[event.node()] = [event]
     
     for eventsNode in eventsByNode:
       node = self.vfs.getNodeById(eventsNode)
       doc = EvtxDocument(eventsByNode[eventsNode], node.name(), 'Case/Events')
       reportManager.addReportDocument(doc)


class EvtxFilteredWidget(QSplitter):
  def __init__(self, parent, name, events):
     QSplitter.__init__(self, Qt.Horizontal)
     self.__name = name
     self.__parent = parent
     self.reportBase = "Analyse/"
     self.evtxViewer = EventLogViewer()
     self.evtxViewer.admin_pannel.hide()
     self.evtxViewer.addEvents(events)

     self.addWidget(self.evtxViewer)
     self.addWidget(EvtControlPannel(self.evtxViewer.evtx_table_view))
     self.setStretchFactor(0, 2)

  def parentName(self):
     return self.__parent.name

  def report(self):
     reportManager = ReportManager()
     events = self.evtxViewer.evtx_table_view.selectedEvents()
     if events and len(events):
       doc = EvtxDocument(events, str(self.__name), str(self.reportBase + self.parentName()))
       reportManager.addReportDocument(doc)

#class EvtxDocument(ReportFramedDocument):
  #level = [
            #'Audit success',
            #'Audit failure',
            #'Error',
            #'Warning',
            #'Information',
            #'Comment'
            #]
  #def __init__(self, events, name = "Evtx", path = "Case"):
     #ReportFramedDocument.__init__(self, name, path)   
     #self.__name = name
     #self.events = events
     #self.evtxManager = ModuleProcessusManager().get('evtx') 
     #if len(self.events):
       #frame = self.generateFrame()
       #self.addFrames(name, frame)
       #self.generatePageEventsTable(frame)
       #self.generatePagesEvent(frame)
        
  #def generateFrame(self):
     #frame = ReportDocument(self.__name)
     #frame.addHtml('<html><body style="position: absolute;top: 0;bottom: 0;left: 0;right: 0;overflow: hidden;"><iframe src="eventtable.html" name="eventtable" width="100%" style="height: 50%;border: 0px;margin: 0px;padding: 0px;border-bottom:1px solid black"> </iframe> <iframe name="result" src=1.html stlye="border:0" style="border: 0px !important;margin: 0px; width: 100%;height: 50%;margin: 0px;border: 0px;padding: 0px;background: white;"> </iframe></body></html>')
     #return frame

  #def generatePageEventsTable(self, frame):
     #eventsTable = ReportDocument("eventtable", frame.path() + "/" + frame.name())
     #eventsTable.addHtml('<h1>' + 'Event' + '</h1><br>')
     #table = ReportFragmentTable()
     #table.setRowStyle(table.rows(), "background-color:rgb(4,59,76); color:white;")
     #table.insertRowHtml(table.rows(), ('<h2>Date</h2>', '<h2>Id</h2>','<h2>source</h2>', '<h2>level</h2>', ))
     #count = 1 
     #for event in self.events:
        #chunk = event.event()
        #try:
          #level = EvtxDocument.level[chunk['level']]
        #except:
          #level = chunk['level']
	#table.insertRowText(table.rows(), ('<a href=dff-frame-page:' + str(count) + '.html target=result>' + str(chunk['date']) + '</a>', str(chunk['id']), str(chunk['source']), str(level)))
        #count += 1
     #eventsTable.addFragment(table)
     #self.addFrames("eventtable", eventsTable)

  #def generatePagesEvent(self, frame):
     #count = 1
     #for event in self.events:
        #chunk = event.event()
        #eventDocument = ReportDocument(str(count), frame.path() + "/" + frame.name())
        #table = ReportFragmentTable()
        #try:
          #level = EvtxDocument.level[chunk['level']]
        #except:
          #level = chunk['level']
        
        #xml = self.evtxManager.getxml(event.count(), event.offset(), event.node())
        #xmltext = tostring(xml, 'utf-8')
        #xml = parseString(xmltext).toprettyxml()
        #xml = xml.replace('<', '&lt;')
        #xml = xml.replace('>', '&gt;')
        #message = "<pre><code>"
        #message += xml
        #message += "</code><pre>"
        #tableText = (("Event Id", str(chunk['id'])),
                     #("Source Name", str(chunk['source'])),
                     #("Level", str(level)),
                     #("Date", str(chunk['date'])),
                     #("Message", message,)
                    #)
        #table.insertTableHtml(tableText)
        #eventDocument.addFragment(table)
        #self.addPages(str(count) + ".html" , eventDocument)
        #count += 1
