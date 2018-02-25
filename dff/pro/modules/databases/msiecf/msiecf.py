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

__dff_module_msiecf_version__ = "1.0.0"
import re

from dff.api.vfs.vfs import vfs
from dff.api.vfs.libvfs import mfso 
from dff.api.module.module import Module 
from dff.api.types.libtypes import Argument, typeId
from dff.api.module.manager import ModuleProcessusManager

from dff.modules.msiecf.msiecf_index import *

from msiecfmanager import MsiecfManager

ModuleProcessusManager().register(MsiecfManager('msiecf'))

class MSIECF(mfso):
    def __init__(self):
        mfso.__init__(self, "msiecf")
        self.vfs = vfs()
        self.name = "msiecf"
        self.__disown__()

    def start(self, args):
        try:
            self.node = args['file'].value()
            if args.has_key("verbose"):
                verbose = True
            else:
                verbose = False
            self.index = MSIEIndex(self.node)
            self.index.mount(self)
        except KeyError:
            pass

    def indexType(self):
        rtype = "TEMP"
        try:
            records = self.index.hashTables.getRecords("VALID")
            if len(records) > 0:
                for typ, pattern in INDEX_TYPE.iteritems():
                    location = records[0].location()
                    if location:
                        if (re.match(pattern, location)):
                            rtype = typ
                    else:
                        return None
                return rtype
            else:
                return None
        except (AttributeError, TypeError):
            return None

    def cacheRecords(self):
        ret = {}
        records = self.index.hashTables.getRecords("VALID")
        rpath = self.node.parent().absolute()
        for rec in records:
            try:
                cachedir = rec.cacheDirectory()
                filename = rec.filename()
                path = rpath
                path += "/" 
                path += cachedir
                path += "/"
                path += filename
                node = self.vfs.getnode(path)
                if node:
                    ret[rec] = node
            except TypeError:
                pass
        return ret
            
    # Access to index records
    def validRecords(self):
        return self.index.hashTables.getRecords("VALID")

    def invalidRecords(self):
        return self.index.hashTables.getRecords("INVALID")

    def unknownRecords(self):
        return self.index.hashTables.getRecords("UNKNWON")

    # Deleted Records
    def validDeletedRecords(self):
        return self.index.validDeletedRecords()

    def redirectDeletedRecords(self):
        return self.index.redirectDeletedRecords()


class msiecf(Module):
  """This modules permit to virtualy reconstruct windows Microsoft Internet Explorer Cache File."""
  def __init__(self):
    Module.__init__(self, "msiecf", MSIECF)
    self.conf.addArgument({"name": "file",
                           "description": "Internet Explorer Cache File",
                           "input": Argument.Required|Argument.Single|typeId.Node})

    self.conf.addArgument({"name": "verbose",
                           "description": "Display module progression",
                           "input": Argument.Empty})

    self.conf.addConstant({"name": "mime-type",
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["windows/ie-cache"]})
    self.tags = "Databases"
    self.flags = ["noscan"]
    self.icon = ":database"
