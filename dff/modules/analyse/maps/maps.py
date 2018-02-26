# -*- coding: utf-8 -*-
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
 
from dff.api.vfs.vfs import vfs
from dff.api.module.module import Module, Script
from dff.api.filters.libfilters import Filter

from nodesmapwidget import NodesMapWidget

class Maps(NodesMapWidget, Script):
  def __init__(self):
    Script.__init__(self, "Maps")
    self.vfs = vfs()
    self.nodeCoord = {}

  def getCoordinates(self, node):
    try:
      longitude = float(node.attributesByName("GPSLongitudeRef")[0].value())
      latitude = float(node.attributesByName("GPSLatitudeRef")[0].value())
      if latitude and longitude:
        return (latitude,  longitude)
    except:
      pass
    return None

  def start(self, args):
    self.root = self.vfs.getnode("/")
    try:
      #self.status #searching
      filter = Filter("")
      query = '(type in["image/jpeg"])'
      filter.compile(query)
      filter.process(self.root, True)
      nodes = filter.matchedNodes()
      #self.status getting coord for x on x
      for node  in nodes:
        coord = self.getCoordinates(node)
        if coord:
          self.nodeCoord[node] = coord
    except Exception as e:
      print 'Maps module error ',  e

  def g_display(self):
    NodesMapWidget.__init__(self) 
    #show widget with status'
    for node in self.nodeCoord: 
      coord = self.nodeCoord[node] 
      if coord:
        self.addNodeCoord(node, coord)
    self.mapWidget.refreshMap()

  def updateWidget(self):
    pass

class maps(Module):
  """Show exif GPS info on google maps"""
  def __init__(self):
    Module.__init__(self, "Maps", Maps)
    self.depends = ["metaexif"]
    self.icon = ":maps"
    self.flags = ["gui"]
    self.tags = "Analyse"
