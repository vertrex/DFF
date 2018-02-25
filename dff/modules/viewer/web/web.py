# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2014 ArxSys
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
#  Jeremy MOUNIER <jmo@digital-forensic.org>

__dff_module_webview_version__ = "1.0.0"
import re
import base64

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtWebKit import *
from PyQt4.QtNetwork import QNetworkAccessManager

from dff.api.vfs import *
from dff.api.module.module import *
from dff.api.module.script import *
from dff.api.types.libtypes import Argument, typeId

class WebView(QWebView):
  def __init__(self, web):
    QWebView.__init__(self)
    self.web = web
    s = self.page().settings()
    s.setAttribute(s.JavascriptEnabled, False)
    s.setAttribute(s.PrivateBrowsingEnabled, True)
    # Work offline
    self.page().networkAccessManager().setNetworkAccessible(QNetworkAccessManager.NotAccessible)
    self.page().setLinkDelegationPolicy(QWebPage.DelegateExternalLinks)

  def changeMode(self):
    self.page().settings().clearMemoryCaches()
    if self.page().networkAccessManager().networkAccessible() == QNetworkAccessManager.NotAccessible:
      self.page().networkAccessManager().setNetworkAccessible(1)
    else:
      self.page().networkAccessManager().setNetworkAccessible(0)
    
  def replaceImageElements(self):
    imgs = self.page().currentFrame().findAllElements("img")
    for img in imgs:
      url = img.attribute("src")
      encodedimg = self.encodeImage(self.getNodeFromURL(url, self.web.node))
      if encodedimg:
        img.setAttribute("src", encodedimg)

  def encodeImage(self, node):
    if node:
      conv = '"data:'
      conv += node.dataType()
      conv += ";base64,"
      buff = ""
      vf = node.open()
      size = 0
      while size < node.size():
        buff += vf.read(1024*1024)
        size += len(buff)
      encoded = base64.encodestring(buff)
      conv += encoded
      conv += '"'
      vf.close()
      return conv
    else:
      return None

  def getNodeFromURL(self, url, relativenode):
    if self.checkURL(url):
      vfspath = relativenode.parent().absolute() + "/" + url
      node = self.web.vfs.getnode(str(vfspath))
      if node:
        return node
      else:
        return None
    else:
      return None

  def checkURL(self, url):
    local = False
    if re.match('^http://', url):
      local = False
    elif re.match('^data:', url):
      local = False
    elif re.match('file://', url):
      local = False
    else:
      local = True
    return local

  def getCSSElements(self):
    elements = []
    frame = self.page().currentFrame()
    styles = frame.findAllElements("style")
    links = frame.findAllElements("link")
    for s in styles:
      if s.attribute("type") == "text/css":
        elements.append(s)        
    for l in links:
      if l.attribute("type") == "text/css":
        elements.append(l)
    return elements

  def replaceCSSElements(self, elements):
    for el in elements:
      if el.tagName() == "LINK":
        cssnode = self.getNodeFromURL(el.attribute("href"), self.web.node)
        if cssnode:
          ne = QWebElement()
          ne.setOuterXml("<style></style>")
          ne.setPlainText(self.readImportCSS(cssnode))
          el.replace(ne)
      elif el.tagName() == "STYLE":
        self.importCSS(el)

  def importCSS(self, style):
    if style:
      if re.match('^@import', style.toPlainText()):
        match = re.search('".*"', style.toPlainText())
        path = style.toPlainText()[match.start() + 1 :match.end() - 1]
        cssnode = self.getNodeFromURL(path, self.web.node)
        if cssnode:
          style.setPlainText(self.readImportCSS(cssnode))

  def readImportCSS(self, cssnode):
    cssfile = cssnode.open()
    ret = ""
    size = 0
    while size < cssnode.size():
      buff = cssfile.read(1024*1024)
      size += len(buff)
      if len(buff) == 0:
	break
      ret += self.detectUrlInCSS(buff, cssnode)
    cssfile.close()
    return QString(QByteArray(ret))

  def detectUrlInCSS(self, buff, cssnode):
    urls = re.finditer('url\(.*\)', buff)
    
    matchs = {}

    ret = buff

    for url in urls:
      line =  buff[url.start():url.end()]
      # 4 for len "url("
      if line[4] in ('"', "'"):
        path = line[5:len(line)-2]
      else:
        path = line[4:len(line)-1]
      imgnode = self.getNodeFromURL(path, cssnode)
      if imgnode:
        encoded = "url("
        encoded += self.encodeImage(imgnode)
        encoded += ")"

        l = line.replace('(', "\(")
        li = l.replace(')', "\)")
        ret = re.sub(li, encoded, ret)

    return ret

class WEB(QWidget, Script):
  def __init__(self):
    Script.__init__(self, "web")
    self.vfs = vfs.vfs()
    self.type = "web"
    self.icon = None
  
  def start(self, args):
    self.args = args
    try:
      self.node = args["file"].value()
    except:
      pass

  def g_display(self):
    QWidget.__init__(self)
    self.vfile = self.node.open()

    self.initShape()
    size = 0
    
    self.html = ""

    while size < self.node.size():
      self.buff = self.vfile.read(1024*1024) 
      size += len(self.buff)
      if len(self.buff) == 0:
	break
      self.html += self.buff
      self.webv.setContent(self.html)

    self.webv.replaceImageElements()
    self.webv.replaceCSSElements(self.webv.getCSSElements())
    self.vfile.close()

  def updateWidget(self):
	pass

  def initShape(self):
    self.vbox = QVBoxLayout()
    
    self.vbox.setContentsMargins(0, 0, 0, 0)
    self.webv = WebView(self)

    self.mode = QComboBox()
    self.mode.addItem(QString("offline mode"))
    self.mode.addItem(QString("online mode"))
    
    self.connect(self.mode, SIGNAL("currentIndexChanged(int)"), self.changeMode)

    self.vbox.addWidget(self.mode)
    self.vbox.addWidget(self.webv)

    self.setLayout(self.vbox)

  def changeMode(self):
    self.webv.changeMode()
    self.webv.setContent(self.html)
    self.webv.replaceImageElements()
    self.webv.replaceCSSElements(self.webv.getCSSElements())


class web(Module):
  """Interprets Web pages"""
  def __init__(self):
    Module.__init__(self, "web", WEB)
    self.conf.addArgument({"name": "file",
                           "description": "Web page",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["HTML"]})
    self.conf.addConstant({"name": "extension-type", 
 	                   "type": typeId.String,
 	                   "description": "compatible extension",
 	                   "values": ["html", "htm"]})
    self.tags = "Viewers"
    self.flags = ["gui"]
    self.icon = ":text"	
