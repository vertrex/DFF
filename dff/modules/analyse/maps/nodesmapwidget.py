from qgmap import QGoogleMap, InversedGeoCoder

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import QByteArray, QBuffer, QIODevice, QString, SIGNAL
from PyQt4.QtGui import QPixmap, QWidget, QVBoxLayout, QSizePolicy, QApplication, QTreeWidget, QTreeWidgetItem, QSplitter, QMenu, QClipboard

from dff.api.vfs.libvfs import VFS

class Address(object):
  def __init__(self, decoded, originalCoord):
    self.coord = originalCoord
    if not decoded:
      self.country = "Unknown country"
      self.county = "Unknown county"
      self.street = "Unknown street"
    else:
      address = decoded["address"]
      self.coord = originalCoord 
      try:
        self.country = address["country"]
      except:
        self.country = "unknown country"
      try:
        self.county = address["county"]
      except:
        self.county = "unknown county"
      try:
        house_number = address["house_number"]
      except :
        house_number = None
      try:
        road = address["road"]
      except:
        road = None
      self.street = ""
      if house_number:
        self.street = house_number + ", "
      if road:
        self.street += road
      if self.street == "":
        self.street = "unknown street"

  def __str__(self):
     return self.street + ", " + self.county + ", " + self.country

class NodeAddressItem(QTreeWidgetItem):
  def __init__(self, parent, node, address):
    QTreeWidgetItem.__init__(self, parent, (node.name(),))
    self.address = address
    self.nodeuid = node.uid()

class AddressItemMenu(QMenu):
  def __init__(self, parent, item):
    QMenu.__init__(self, parent)
    self.item = item
    action = self.addAction(self.tr("Copy address"))
    self.connect(action, SIGNAL("triggered()"), self.copyAddress)
    action = self.addAction(self.tr("Copy coordinates"))
    self.connect(action, SIGNAL("triggered()"), self.copyCoordinates)
    action = self.addAction(self.tr("Open parent folder"))
    self.connect(action, SIGNAL("triggered()"), self.openParentDirectory)

  def copyAddress(self):
     address = str(self.item.address)
     QApplication.clipboard().setText(address, QClipboard.Clipboard) 
     QApplication.clipboard().setText(address, QClipboard.Selection) 
  
  def copyCoordinates(self):
     coord = self.item.address.coord 
     coordinates = str(coord[0]) + "," + str(coord[1])
     QApplication.clipboard().setText(coordinates, QClipboard.Clipboard) 
     QApplication.clipboard().setText(coordinates, QClipboard.Selection) 

  def openParentDirectory(self):
     node = VFS.Get().getNodeById(self.item.nodeuid)
     QApplication.instance().mainWindow.addNodeBrowser(node.parent()) 
                                #set selection to node would be great

class NodesAddressWidget(QTreeWidget):
  def __init__(self, parent = None):
    QTreeWidget.__init__(self, parent)
    self.vfs = VFS.Get()
    self.nodesMapWidget = parent
    self.mainWindow = QApplication.instance().mainWindow
    self.countryLevel = {} 
    self.countyLevel = {}
    self.streetLevel = {}
    self.nodeLevel = {}
    self.connect(self, SIGNAL("itemClicked(QTreeWidgetItem*, int)"), self.clicked)
    self.connect(self, SIGNAL("focusOnNode"), self.focusOnNodeItem)
    headerItem = self.headerItem().setText(0, "No images found")
    self.imageCount = 0

  def clicked(self, item, column):
     if type(item) == NodeAddressItem:
       self.setCurrentItem(item)
       node = self.vfs.getNodeById(item.nodeuid)
       self.mainWindow.emit(SIGNAL("previewUpdate"), node)
       self.emit(SIGNAL("center"), item.address.coord)

  def contextMenuEvent(self, event):
    if event.reason() == event.Mouse:
      pos = event.globalPos()
      item = self.itemAt(event.pos())
      if type(item) == NodeAddressItem:
        addressItemMenu = AddressItemMenu(self, item)
        addressItemMenu.popup(pos)
      event.accept()

  def focusOnNodeItem(self, nodeuid):
     try:
       nodeLevelItem = self.nodeLevel[nodeuid]
       self.scrollToItem(nodeLevelItem)
       self.setCurrentItem(nodeLevelItem)
     except KeyError:
       pass

  def addNodeAddress(self, node, address):
     #if address is not put in 'unresolved'
     country = address.country
     try:
       countryLevelItem = self.countryLevel[country]
     except KeyError:
       countryLevelItem = QTreeWidgetItem(self, (country,))
       self.addTopLevelItem(countryLevelItem)
       self.countryLevel[country] = countryLevelItem

     county = address.county
     full = county + country
     try:
       countyLevelItem = self.countyLevel[full]
     except KeyError:
       countyLevelItem = QTreeWidgetItem(countryLevelItem, (county,))
       self.countyLevel[full] = countyLevelItem

     street = address.street
     full = street + full
     try:
       streetLevelItem = self.streetLevel[full]
     except KeyError:
       streetLevelItem = QTreeWidgetItem(countyLevelItem, (street,))
       self.streetLevel[full] = streetLevelItem

     nodeAddressItem = NodeAddressItem(streetLevelItem, node, address)
     self.nodeLevel[node.uid()] = nodeAddressItem     

     self.imageCount += 1
     self.headerItem().setText(0, str(self.imageCount) + " images") 

class NodesMapWidget(QWidget):
  def __init__(self):
    QWidget.__init__(self)
    self.inversedGeoCoder = InversedGeoCoder()
    self.vfs = VFS.Get()
    self.mainWindow = QApplication.instance().mainWindow
    self.vboxLayout = QVBoxLayout(self)
    self.vboxLayout.setSpacing(0)
    self.vboxLayout.setMargin(0)
    self.setLayout(self.vboxLayout)
    self.splitter = QSplitter()

    self.mapWidget = QGoogleMap(self) 
    self.mapWidget.markerClicked.connect(self.markerClicked)
    self.mapWidget.waitUntilReady()
    self.splitter.addWidget(self.mapWidget)

    self.nodesAddressWidget = NodesAddressWidget(self)
    self.connect(self.nodesAddressWidget, SIGNAL("center"), self.center)
    self.splitter.addWidget(self.nodesAddressWidget)
    self.vboxLayout.addWidget(self.splitter)

    self.mapWidget.centerAt(43.776037, -31.330157)
    self.mapWidget.setZoom(3)

  def center(self, coord):
     self.mapWidget.centerAt(*coord) 
     self.mapWidget.setZoom(14)

  def addNodeCoord(self, node, coord):
     (latitude, longitude,) = self.nodeCoord[node]
     res = self.mapWidget.addMarker(str(node.uid()), latitude, longitude, **dict( 
  	 icon="http://google.com/mapfiles/ms/micons/green-dot.png",
	 draggable=False,
         name=node.name()))
     try:
       decoded = self.inversedGeoCoder.decode(coord)
     except Exception as e: #limit usage or somethings else
       decoded = None 
     self.nodesAddressWidget.addNodeAddress(node, Address(decoded, coord))

  def markerClicked(self, key):
    nodeuid = long(key)
    node = self.vfs.getNodeById(nodeuid)
    self.mainWindow.emit(SIGNAL("previewUpdate"), node)
    self.nodesAddressWidget.emit(SIGNAL("focusOnNode"), nodeuid)
