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
#  Jeremy MOUNIER < jmo@arxsys.fr>
#

__dff_module_firecache_version__ = "1.0.0"

import re

from dff.api.vfs import *
from dff.api.module.module import *
from dff.api.types.libtypes import Argument, typeId
from dff.api.vfs.libvfs import *

from dff.modules.firefoxcache.cache_map import *
from dff.modules.firefoxcache.commons import *


class FIRECACHE(mfso):
    def __init__(self):
        mfso.__init__(self, "firecache")
        self.name = "firecache"
        self.__disown__()

    def start(self, args):
        try:
            self.node = args['cache_dir'].value()
        except "KeyError":
            return
        children = self.node.children()
        cachenodes = self.getCacheNodes(children)

        if len(cachenodes) != 4:
            print "Missing cache files in cache directory"
        else:
            print "All cache files were found"
            if self.openCacheFiles(cachenodes):
                mapfile = cachenodes[0]
                header = CacheMapHeader(mapfile, 0)
                if header.isValid():
                    self.map = CacheMap(header, cachenodes, self)
                    self.map.mapRecords()

    def openCacheFiles(self, cachenodes):
        try:
            for count, node in cachenodes.iteritems():
                cachenodes[count] = node.open()
            return True
        except:
            print "Error while opening cache nodes"
            return None

    def getCacheNodes(self, children):
        cachenodes = {}
        for count, child in enumerate(children):
            if child.name() == CACHE[0]:
                cachenodes[0] = child
            if child.name() == CACHE[1]:
                cachenodes[1] = child
            if child.name() == CACHE[2]:
                cachenodes[2] = child
            if child.name() == CACHE[3]:
                cachenodes[3] = child
        return cachenodes

    def getRecords(self):
        return self.map.getRecords()


class firefoxcache(Module):
  """This modules permit to virtualy reconstruct windows Microsoft Internet Explorer Cache File."""
  def __init__(self):
    Module.__init__(self, "firefox_cache", FIRECACHE)
    self.conf.addArgument({"name": "cache_dir",
                           "description": "Firefox Cache Directory",
                           "input": Argument.Required|Argument.Single|typeId.Node})
#    self.conf.addConstant({"name": "mime-type",
# 	                   "type": typeId.String,
# 	                   "description": "managed mime type",
# 	                   "values": ["Internet Explorer cache file"]})
    self.tags = "Databases"
    self.icon = ":database"
