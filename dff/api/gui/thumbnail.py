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
#

import re

from PyQt4.QtCore import pyqtSlot, Qt, QObject, SIGNAL, SLOT, QSize, QThread, QEvent, QThreadPool, QRunnable, QEventLoop
from PyQt4.QtGui import QApplication, QImage, QPixmap, QPixmapCache, QPainter

from dff.api.types.libtypes import Variant, VMap
from dff.api.vfs.libvfs import AttributesHandler, Node

try:
  from dff.api.gui.video import video
  VIDEO_API_EXISTS = True
except ImportError as e:
  VIDEO_API_EXISTS = False
  print "Can't load video api : " + str(e)

class CorruptedPictureHandler(AttributesHandler):
  def __init__(self):
     AttributesHandler.__init__(self, "Corrupted")
     self.__disown__()
     self.nodes = [] 

  def setAttributes(self, node):
     self.nodes.append((node.uid()))
     node.registerAttributes(self)

  def isCorrupted(self, node):
     if node.uid() in self.nodes:
	return True
     return False

  def attributes(self, node):
     attr = VMap()
     attr["Picture"] = Variant("Corrupted")
     return attr

class Scaler(QObject):
  def __init__(self):
     QObject.__init__(self)
     self.img = None
     self.imageMaximumSize = 100000000 #don't try to create thumbnail for image larger than size (To avoid false positive)
        
  def event(self, event):
     if (event.type() == 11003):
       try:
	 self.convert(event)
       except Exception as e: 
         print 'Thumbnailer event exceptions ' + e
	 self.emit(SIGNAL("scaledFinished"), event.config, None)
       return True
     return QObject.event(self, event)

  def convert(self, event):
    node = event.config.node
    buff = ""
    if (node.dataType().find('video') != -1):
      if VIDEO_API_EXISTS:
        try:
          md = video.VideoDecoder(node)
	  if event.config.frames == 1:
            img = md.thumbnailAtPercent(event.config.percent, event.config.size)
          else:
            img = QImage(event.config.size * event.config.frames / 2, event.config.size * 2, 4)
	    img.fill(0)
            painter = QPainter(img)
            for y in range(0, 2):
              try:
                for x in range(1, event.config.frames/2 + 1):
	          try:
	            frame = md.thumbnailAtPercent((x + ((event.config.frames/2) * y)) * (100/event.config.frames), event.config.size)
	            painter.drawImage((x - 1) * event.config.size, y * event.config.size , frame)
                  except RuntimeError, e:
	            raise e
              except RuntimeError:
	        break
            painter.end()  
          self.emit(SIGNAL("scaledFinished"), event.config, img)
	  return
        except :
	  pass
      self.emit(SIGNAL("scaledFinished"), event.config, None)  
      return 
    img = QImage()
    load = None
    buff = ""
    if node.dataType().find('jpeg') != -1 and node.size() < self.imageMaximumSize:
      try:
        buff = self.jpegInternalThumbnail(node)
	if (buff):
          load = img.loadFromData(buff, 'jpeg')
	  if load == False:
	   buff = ""
      except IOError:
        buff = ""
    if not len(buff) and node.size() < self.imageMaximumSize:
      try:
        f = node.open()
        buff = f.read()
        f.close()
        load = img.loadFromData(buff)
      except IOError:
        load = False
    if load:
      img = img.scaled(QSize(event.config.size, event.config.size), Qt.KeepAspectRatio, Qt.FastTransformation)
      self.emit(SIGNAL("scaledFinished"), event.config, img)
      return
    self.emit(SIGNAL("scaledFinished"), event.config, None)
    return

  def jpegInternalThumbnail(self, node):
     buff = ""
     if node.size() > 6:
       try:
         file = node.open()
         head = file.find("\xff\xd8\xff", "", 3)
         if head > 0 and head < node.size():
           foot = file.find("\xff\xd9", "", long(head))
           if foot > 0 and foot < node.size():
             file.seek(head)
             buff = file.read(foot + 2 - head)
         file.close()
       except IOError:
         return ""
     return buff


class ScaleConfig(object):
  def __init__(self, node, size = 128, percent = 10, frames = 1):
    self.node = node
    self.size = size
    self.percent = percent
    self.frames = frames

  def __hash__(self):
     return 1

  def __eq__(self, other):
     if self.node.uid() == other.node.uid() and self.size == other.size and self.percent == other.percent and self.frames == other.frames: 
       return True
     else:
       return False

  def __str__(self):
    return str(str(self.node.uid()) + str(self.size) + str(self.percent) + str(self.frames))

class ScaleEvent(QEvent):
 Type = QEvent.Type(QEvent.registerEventType())
 def __init__(self, config):
   QEvent.__init__(self, 11003)
   self.config = config

class ThumbnailManager(object):
  __instance = None
  def __init__(self):
     if ThumbnailManager.__instance is None:
       ThumbnailManager.__instance = ThumbnailManager.__ThumbnailManager()

  def __getattr__(self, attr):
     return getattr(self.__instance, attr)

  class __ThumbnailManager(QObject):
    def __init__(self):
      QObject.__init__(self)
      self.pixmapCache = QPixmapCache()
      self.pixmapCache.setCacheLimit(61440)
      self.thread = QThread()
      self.scaler = Scaler()
      self.scaler.moveToThread(self.thread)
      self.connect(self.scaler, SIGNAL("scaledFinished"), self.finished)
      self.thread.start()
      self.thumbnailers = []
      self.handledRequest = set()
      self.corruptionHandler = CorruptedPictureHandler()
      self.pixmapCorrupted = QPixmap(":file_broken.png")
 
    def register(self, thumbnailer):
      self.thumbnailers.append(thumbnailer)

    def unregister(self, thumbnailer):
      try:
        self.thumbnailers.remove(thumbnailer)
      except:
	 pass

    def generate(self, config):
      pixmap = self.pixmapCache.find(str(config))
      if pixmap:
	return pixmap
      elif self.corruptionHandler.isCorrupted(config.node):
        return self.pixmapCorrupted
      else:
        if config not in self.handledRequest:
          QApplication.postEvent(self.scaler, ScaleEvent(config))
	  self.handledRequest.add(config)

    def finished(self, config, scaledImage):
       if scaledImage:
         pixmap = QPixmap().fromImage(scaledImage)
         self.pixmapCache.insert(str(config), pixmap)
         self.emitUpdate(config, pixmap)
       else:
         self.corruptionHandler.setAttributes(config.node)
	 self.emitUpdate(config, self.pixmapCorrupted)
 
    def emitUpdate(self, config, pixmap):
       for thumbnailer in self.thumbnailers:
	 try:
           if thumbnailer.request(config):
             thumbnailer.emit(SIGNAL("ThumbnailUpdate"), config.node, pixmap)
	     thumbnailer.requestRemove(config)	 
	 except:
	    pass
       try:
         self.handledRequest.remove(config)	
       except KeyError:
	 pass 

class ThumbnailBlockingLoop(QEventLoop):
  def __init__(self):
     QEventLoop.__init__(self)

  def quit(self):
    return

  @pyqtSlot(Node, QPixmap)
  def quit(self, node, pixmap):
     QEventLoop.quit(self)
     return pixmap

class Thumbnailer(QObject):
  compatibleType = re.compile("(JPEG|JPG|jpg|jpeg|GIF|gif|bmp|BMP|png|PNG|pbm|PBM|pgm|PGM|ppm|PPM|xpm|XPM|xbm|XBM|TIFF|tiff|video).*", re.IGNORECASE)
  def __init__(self):
    QObject.__init__(self)
    self.thumbnailManager = ThumbnailManager()
    self.thumbnailManager.register(self)
    self.requests = set() 

  @staticmethod
  def isThumbnailable(node):
     if Thumbnailer.compatibleType.search(node.dataType()) != None:
       return True
     return False

  def generate(self, node, iconSize = 128, percent = 10, frames = 1, blocking = False):
     if blocking:
	self.blockingLoop = QEventLoop()
	self.blockingLoop.connect(self, SIGNAL("ThumbnailUpdate"), self.blockingUpdate)
     config = ScaleConfig(node, iconSize, percent, frames) 
     self.requests.add(config)
     pixmap = self.thumbnailManager.generate(config)
     if pixmap:
       return pixmap
     if blocking:
       self.blockingLoop.exec_()
       return self.pixmap

  def blockingUpdate(self, node, pixmap):
     self.pixmap = pixmap
     self.blockingLoop.quit()     

  def requestRemove(self, config):
    try:
       self.requests.remove(config)
    except:
	pass

  def request(self, config):
     if config in self.requests:
	return True
     else:
        return False

  def unregister(self):
     self.thumbnailManager.unregister(self)
