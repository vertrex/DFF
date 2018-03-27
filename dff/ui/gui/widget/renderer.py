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
#  Solal Jacob <sja@digital-forensic.org>
#

from urllib import quote

from PyQt4.QtCore import SIGNAL, QBuffer, QByteArray, QIODevice, QFile, QString, QVariant, QUrl, QTimer, SLOT
from PyQt4.QtGui import QPixmap, QImage, QPainter
from PyQt4.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest

from dff.api.vfs.vfs import vfs
from dff.api.vfs.iodevice import IODevice
from dff.ui.gui.thumbnail import Thumbnailer
from dff.api.report.manager import ReportManager

class NodeThumbnailRenderReply(QNetworkReply):
  def __init__(self, parent, request):
     QNetworkReply.__init__(self, parent)
     self.qbuffer = None
     self.connect(self, SIGNAL('abouteToClose()'), self.__close)
     self.byteArray = QByteArray()
     self.qbuffer = QBuffer(self.byteArray)
     self.node = vfs().getnode(str(request.url().path().toUtf8()))
     self.thumbnailer = Thumbnailer()
     self.connect(self.thumbnailer, SIGNAL("ThumbnailUpdate"), self.updateThumbnail) 
     self.setRequest(request)
     self.setOperation(QNetworkAccessManager.GetOperation)
     mime = "image/jpg"
     self.setHeader(QNetworkRequest.ContentTypeHeader, QVariant(mime))
     self.open()
     self.setUrl(request.url())
     self.connect(parent, SIGNAL("ready"), self.ready)
     self.ready()

  def ready(self):
     if self.node.dataType().find('video') != -1:
       pixmap = self.thumbnailer.generate(self.node, iconSize = 128, frames = 10)
     else:
       pixmap = self.thumbnailer.generate(self.node, iconSize = 256, frames = 10)
     if pixmap:
       self.updateThumbnail(self.node, pixmap)

  def updateThumbnail(self, node, pixmap):
     if pixmap == None:
       pixmap = QPixmap(":file_broken.png") 
     pixmap.save(self.qbuffer, 'JPG')
     self.qbuffer.seek(0)
     QTimer.singleShot(0, self, SIGNAL("readyRead()"))
     QTimer.singleShot(0, self, SIGNAL("finished()"))

  def abort(self):
     self.close()

  def __del__(self):
     self.thumbnailer.unregister()

  def open(self, mode = None):
     try:
        self.qbuffer.open(QIODevice.ReadWrite | QIODevice.Unbuffered)
        self.setOpenMode(QIODevice.ReadWrite | QIODevice.Unbuffered)
	return True
     except (AttributeError, IOError):
        return False	

  def seek(self, pos):
     if self.qbuffer:
       return self.qbuffer.seek(pos)
     return False

  def __close(self):
     if self.qbuffer:
       self.qbuffer.close()
       self.qbuffer = None
     return True

  def readData(self, size):
     if self.qbuffer:
       return self.qbuffer.read(size)
     return ""

  def pos(self):
     if self.qbuffer:
       return self.qbuffer.pos()
     return 0

  def isSequential(self):
     if self.qbuffer:
       return self.qbuffer.isSequential()
     return False

  def size(self):
     return self.qbuffer.size()

  def reset(self):
     if self.qbuffer:
       self.qbuffer.seek(0)
       return True
     return False

  def atEnd(self):
     if self.qbuffer:
       return self.qbuffer.atEnd()
     return False

class ResourceRenderReply(QNetworkReply):
  def __init__(self, parent, request):
    QNetworkReply.__init__(self, parent)
    res = ":" + str(request.url().path().toUtf8())
    self.file = None
    self.filepath = res 
    self.connect(self, SIGNAL('aboutToClose()'), self.__close)

    self.setRequest(request)
    self.setOperation(QNetworkAccessManager.GetOperation)
    self.open()
    self.setUrl(request.url())
    self.connect(parent, SIGNAL("ready"), self.ready)

  def ready(self): 
    self.emit(SIGNAL("readyRead()"))
    self.emit(SIGNAL("finished()"))

  def abort(self):
     self.close()

  def __del__(self):
     if self.file:
	self.__close()

  def open(self, mode = None):
     try:
	self.file = QFile(self)
        self.file.setFileName(QString(self.filepath))
        self.file.open(QIODevice.ReadOnly | QIODevice.Unbuffered)
        self.setOpenMode(QIODevice.ReadOnly | QIODevice.Unbuffered)
        return True
     except (AttributeError, IOError):
	return False

  def seek(self, pos):
     if self.file:
       return self.file.seek(pos)
     return  False

  def __close(self):
     if self.file:
       self.file.close()
       self.file = None	
     return True

  def readData(self, size):
     if self.file:
       return self.file.read(size)
     return ""

  def pos(self):
     if self.file:
       self.file.pos()
     return 0

  def isSequential(self):
     if self.file:
       return self.file.isSequential()
     return False

  def size(self):
     return self.file.size()

  def reset(self):
     if self.file:
       self.file.seek(0)
       return True
     return False

  def atEnd(self):
     if self.file:
       return self.file.atEnd()
     return False

class ReportJSRenderReply(QNetworkReply):
  def __init__(self, parent, request):
     QNetworkReply.__init__(self, parent)
     self.__parent = parent
     self.qbuffer = None
     self.connect(self, SIGNAL('abouteToClose()'), self.__close)
     self.byteArray = QByteArray()
     self.qbuffer = QBuffer(self.byteArray)
     self.setRequest(request)
     self.setOperation(QNetworkAccessManager.GetOperation)
     self.setHeader(QNetworkRequest.ContentTypeHeader, QVariant('"text/javascript" charset="utf-8" language="javascript"'))
     self.setAttribute(QNetworkRequest.CacheLoadControlAttribute, QVariant(QNetworkRequest.AlwaysNetwork))
     self.open()
     self.setUrl(request.url())
     self.writeJS()

     QTimer.singleShot(0, self, SIGNAL("readyRead()"))
     QTimer.singleShot(0, self, SIGNAL("finished()"))

  def writeJS(self):
     pageName = self.url().path()
     pageName = unicode(pageName).encode('UTF-8', 'replace')
     buff = ""
     try:
       buff = self.__parent.pages[pageName]
     except KeyError:
        print "can't get page " + pageName
     self.qbuffer.write(buff)
     self.qbuffer.seek(0)

  def abort(self):
     self.close() 

  def __del__(self):
      pass

  def open(self, mode = None):
     try:
        self.qbuffer.open(QIODevice.ReadWrite | QIODevice.Unbuffered)
        self.setOpenMode(QIODevice.ReadWrite | QIODevice.Unbuffered)
	return True
     except (AttributeError, IOError):
        return False	

  def seek(self, pos):
     if self.qbuffer:
       return self.qbuffer.seek(pos)
     return False

  def __close(self):
     if self.qbuffer:
       self.qbuffer.close()
       self.qbuffer = None
     return True

  def readData(self, size):
     if self.qbuffer:
       return self.qbuffer.read(size)
     return ""

  def pos(self):
     if self.qbuffer:
       return self.qbuffer.pos()
     return 0

  def isSequential(self):
     if self.qbuffer:
       return self.qbuffer.isSequential()
     return False

  def size(self):
     return self.qbuffer.size()

  def reset(self):
     if self.qbuffer:
       self.qbuffer.seek(0)
       return True
     return False

  def atEnd(self):
     if self.qbuffer:
       return self.qbuffer.atEnd()
     return False
 
 
class UrlRenderer(QNetworkAccessManager):
  def __init__(self, parent):
     QNetworkAccessManager.__init__(self, parent)
     self.setNetworkAccessible(QNetworkAccessManager.Accessible)
     self.pages = {}

  def setPages(self, pages):
     self.pages = pages 

  def createRequest(self, op, request, outgoingData):
     if op == QNetworkAccessManager.GetOperation:
       try:
         urlPath = unicode(request.url().path()).encode('UTF-8', 'replace')
         if urlPath.rfind('.js') != -1 and urlPath.rfind('assets') == -1: 
           reply = ReportJSRenderReply(self, request)
           return reply 
         elif  request.url().scheme() == "dff-node-thumbnail":
	   reply = NodeThumbnailRenderReply(self, request)
	   return reply
       except Exception as e:
 	 print 'UrlRenderer error: ' + str(e)
     request = QNetworkAccessManager.createRequest(self, op, request, outgoingData) 
     return request
