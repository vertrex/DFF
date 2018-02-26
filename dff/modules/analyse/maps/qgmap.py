import json, os

import sys

from PyQt4.QtCore import QUrl, QXmlStreamReader, pyqtSignal, QFileInfo, SIGNAL
from PyQt4.QtGui import QApplication
from PyQt4.QtWebKit import QWebPage, QWebView, QWebSettings
from PyQt4.QtNetwork import QNetworkRequest, QNetworkAccessManager

class _LoggedPage(QWebPage):
  def javaScriptConsoleMessage(self, msg, line, source):
    print ('JS: %s line %d: %s' % (source, line, msg))

class InversedGeoCoder(QNetworkAccessManager):
  def __init__(self):
    QNetworkAccessManager.__init__(self)

  def decode(self, coord):
    url = QUrl("http://nominatim.openstreetmap.org/reverse")
    url.addQueryItem("format", "json")
    url.addQueryItem("lat", str(coord[0]))
    url.addQueryItem("lon", str(coord[1]))
    url.addQueryItem("zoom", "18")
    url.addQueryItem("addressdetails", "1")
    request = QNetworkRequest(url)
    reply = self.get(request)
    while reply.isRunning() :
      QApplication.processEvents()
    reply.deleteLater()
    self.deleteLater()
    return json.loads(unicode(reply.readAll(), 'UTF-8'))

class QGoogleMap(QWebView) :
  def __init__(self, parent, debug=False):
    super(QGoogleMap, self).__init__(parent)
    if debug :
      QWebSettings.globalSettings().setAttribute(QWebSettings.DeveloperExtrasEnabled, True)
      self.setPage(_LoggedPage())

    self.initialized = False
    self.loadFinished.connect(self.onLoadFinished)
    self.page().mainFrame().addToJavaScriptWindowObject("qtWidget", self)
    self.connect(self.page().networkAccessManager(),
                 SIGNAL("sslErrors(QNetworkReply*, const QList<QSslError> & )"),
                 self.__manageSslErrors)
    basePath = os.path.abspath(os.path.dirname(__file__))
    if hasattr(sys, 'frozen'):
      htmlFile = os.path.join(os.path.dirname(sys.executable), "resources", 'maps', 'qgmap.html')
    else:
      htmlFile = os.path.join(basePath, "qgmap.html")
    qurl = QUrl.fromLocalFile(QFileInfo(htmlFile).absoluteFilePath())
    self.load(qurl)

  # On Windows platform, CA root Certificates are very well handled...
  def __manageSslErrors(self, reply, errors):
    reply.ignoreSslErrors()

    
  def onLoadFinished(self, ok) :
    if self.initialized : 
      return
    if not ok :
      print("Error initializing Google Maps")
    self.initialized = True
    self.centerAt(0,0)
    self.setZoom(1)

  def waitUntilReady(self) :
    while not self.initialized :
      QApplication.processEvents()

  def geocode(self, location) :
    return GeoCoder(self).geocode(location)

  def runScript(self, script) :
    return self.page().mainFrame().evaluateJavaScript(script)

  def centerAt(self, latitude, longitude) :
    self.runScript("gmap_setCenter({},{})".format(latitude, longitude))

  def setZoom(self, zoom) :
    self.runScript("gmap_setZoom({})".format(zoom))

  def center(self) :
    center = self.runScript("gmap_getCenter()")
    return center.lat, center.lng

  def centerAtAddress(self, location) :
    try : 
      latitude, longitude = self.geocode(location)
    except GeoCoder.NotFoundError : 
      return None
    self.centerAt(latitude, longitude)
    return latitude, longitude

  def addMarkerAtAddress(self, location, **extra) :
    if 'title' not in extra :
      extra['title'] = location
    try : 
      latitude, longitude = self.geocode(location)
    except GeoCoder.NotFoundError : 
       return None
    return self.addMarker(location, latitude, longitude, **extra)

  def addMarker(self, key, latitude, longitude, **extra) :
    return self.runScript(
      "gmap_addMarker("
      "key={!r}, "
      "latitude={}, "
      "longitude={}, "
      "{}"
      "); ".format( key, latitude, longitude, json.dumps(extra)))

  def setMarkerOptions(self, keys, **extra) :
    return self.runScript(
      "gmap_changeMarker("
      "key={!r}, "
      "{}"
      "); ".format(keys, json.dumps(extra)))

  def deleteMarker(self, key) :
    return self.runScript(
      "gmap_deleteMarker("
      "key={!r} "
      "); ".format( key))

  def refreshMap(self):
    return self.runScript("gmap_refreshMap();")

  markerClicked = pyqtSignal(str)
