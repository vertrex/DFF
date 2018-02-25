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
#  Samuel CHEVET <gw4kfu@gmail.com>
#

import volatility.addrspace as addrspace
import volatility.plugins.addrspaces.standard as standard

from dff.api.vfs.vfs import vfs

class dffAdressSpace(standard.FileAddressSpace):
    order = 1
    def __init__(self, base, config, **kwargs):
        addrspace.BaseAddressSpace.__init__(self, base, config, **kwargs)
        self.as_assert(base == None or layered, 'Must be first Address Space')
        self.path = config.LOCATION[7:]
        self.vfs = vfs()
        self.name = self.path
        self.fname = self.path
        self.node = self.vfs.getnode(self.path)
        self.fhandle = self.node.open()
        self.fsize = self.node.size()
        self.offset = 0
