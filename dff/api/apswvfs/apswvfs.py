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
#  Solal Jacob < sja@arxsys.fr>
#

from dff.api.vfs.vfs import vfs
import apsw
import os

class apswVFS(apsw.VFS):
  def __init__(self, vfsname="dff-vfs", basevfs=""):
    self.vfsname = vfsname
    self.basevfs = basevfs
    self.vfs = vfs()
    apsw.VFS.__init__(self, self.vfsname, self.basevfs)

  def xAccess(self, pathname, flags):
    drive, pathname = os.path.splitdrive(pathname)
    pathname = pathname.replace('\\', '/')
    if pathname.rfind('-wal') != -1:
       pathname = pathname[0:pathname.rfind('-wal')]
    if self.vfs.getnode(pathname):
       return True
    else:
       return False

  def xOpen(self, name, flags):
    try:
      if isinstance(name, apsw.URIFilename):
         name = str(name.filename())
    except AttributeError:
      pass
    drive, path = os.path.splitdrive(name)
    name = path.replace('\\', '/')
    if name.rfind('-wal') != -1:
          name = name[0:name.rfind('-wal')]
    return apswVFile(self.basevfs, name, flags)


class apswVFile(apsw.VFSFile):
  def __init__(self, inheritfromvfsname, filename, flags):
    self.filename = filename
    self.vfile = None
    self.vfs = vfs()
    self.node = self.vfs.getnode(filename)
    if self.node: 
      self.vfile = self.node.open()

  def xCheckReservedLock(self):
     return False

  def xRead(self, size, offset):
    if self.vfile:
      if self.vfile.seek(offset) != offset:
        raise Exception("apswVFile : Can't seek to offset " + str(offset) + " on : " + str(self.node.absolute()))
      buff = self.vfile.read(size)
      if not len(buff):
        
        raise Exception("apswVFile : Can't read data of size " + str(size) + " at offset " + str(offset) + " on : " + str(self.node.absolute()))
      return buff
    else:
      raise Exception("apswVFile: no VFile opened on {}".format(self.filename))

  def xWrite(self, buff, size):
    return 0

  def xClose(self):
    if self.vfile:
      self.vfile.close()

  def xSectorSize(self):
    return 512

  def xDeviceCharacteristics(self):
    return 0 

  def xLock(self, level):
    pass

  def xUnlock(self, level):
    pass

  def xSync(self, flags):
    pass

  def xTruncate(self, newsize):
    pass
  
  def xFileSize(self):
    if self.vfile:
      return self.vfile.node().size() 
    else:
      return 0

  def xFileControl(self, op, ptr):
     return False 
