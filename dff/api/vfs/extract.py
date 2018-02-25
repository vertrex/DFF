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
#  Frederic Baguelin <fba@digital-forensic.org>
#

import os, shutil, time, traceback, types, sys
if os.name == "nt":
  import ctypes

from dff.api.vfs.libvfs import Node, VFS
from dff.api.exceptions.libexceptions import vfsError
from dff.api.events.libevents import EventHandler, event
from dff.api.types.libtypes import VList, Variant, RCVariant

class Extract(EventHandler):
  reservednames = ['CON', 'PRN', 'AUX', 'CLOCK$', 'NUL',
                 'COM0', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
                 'LPT0', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
                 '$AttrDef', '$BadClus', '$Bitmap', '$Boot', '$LogFile', '$MFT', '$MFTMirr', 
                 'pagefile.sys', '$Secure', '$UpCase', '$Volume', '$Extend']

  max_depth = 2**31-1

  FileProgress = 0x01
  OverallProgress = 0x02
  FileFailed = 0x04
  FolderFailed = 0x08
  DataFailed = 0x10
  PreserveFailed = 0x20
  RenameOccured = 0x40

  def __init__(self):
    EventHandler.__init__(self)
    self.__fsEncoding = sys.getfilesystemencoding()
    self.__vfsRoot = VFS.Get().root
    self.__extracted = {}
    self.__errors = {}
    self.total_files = 0
    self.total_folders = 0
    self.extracted_files = 0
    self.extracted_folders = 0
    self.files_errors = 0
    self.folders_errors = 0
    self.ommited_files = 0
    self.ommited_folders = 0

  @staticmethod
  def freeSpace(path):
     """Return available free space for the disk containing path"""
     if  os.name == "posix":
        st = os.statvfs(path)
        return st.f_bavail * st.f_frsize
     elif os.name == "nt":
        freeSpace = ctypes.c_ulonglong()
        if isinstance(path, unicode):
           ctypes.windll.kernel32.GetDiskFreeSpaceExW(path, None, None, ctypes.byref(freeSpace))
        else:
           ctypes.windll.kernel32.GetDiskFreeSpaceExA(path, None, None, ctypes.byref(freeSpace))
        return freeSpace.value   
     else:
        raise Exception("Extract.freeSpace is not implemented for this OS")   

  def checkFsCapacity(self):
    #perform more tests (reserved words, chars, links, ...)
    try:
      f1 = tempfile.mkstemp("casesensitive")
      f2 = tempfile.mkstemp("caseSensitive")
      f1.close()
      f2.close()
      self.case_insensitive = True
    except:
      self.case_insensitive = False
      pass

  #
  # Public Interface
  # 


  def extractFile(self, src, dst, preserve=False, overwrite=False):
    if preserve:
      try:
        dst = self.__makePreservedDirs(src, dst)
      except Exception:
        tb = traceback.format_exc()
        self.__notifyFailure(src.path(), Extract.PreserveFailed, tb)
    try:
      absfile, absfolder, renamed = self.__generateAbsolutePath(src, dst)
    except Exception:
      tb = traceback.format_exc()
      self.__notifyFailure(src.absolute(), Extract.FileFailed, tb)
      return None
    if absfile:
      #since requesting file extraction, if node is both file and folder, extract original filename
      if absfolder:
        absfile = absfolder
      self.total_files += 1
      self.__extractFile(src, absfile, overwrite)
      return absfile
    return None


  def extractFolder(self, src, dst, preserve=False, overwrite=False, extract_original=False):
    if preserve:
      try:
        dst = self.__makePreservedDirs(src, dst)
      except Exception:
        tb = traceback.format_exc()
        self.__notifyFailure(src.path(), Extract.PreserveFailed, tb)
        return
    self.__countItems(src, False, 1)
    self.__extractTree(src, dst, overwrite, extract_original, 1)

    
  def extractTree(self, src, dst, preserve=False, overwrite=False, extract_original=False, depth=max_depth):
    if preserve:
      try:
        dst = self.__makePreservedDirs(src, dst)
      except Exception:
        tb = traceback.format_exc()
        self.__notifyFailure(src.path(), Extract.PreserveFailed, tb)
        return
    self.__countItems(src, extract_original, depth)
    self.__extractTree(src, dst, overwrite, extract_original, depth)


  def extractData(self, data, name, dst, overwrite=False):
    try:
      absfile, absfolder, renamed = self.__generateAbsolutePath(name, dst)
      if absfile:
        f = open(absfile)
        f.write(data)
        f.close()
    except Exception as e:
      f.close()
      tb = traceback.format_exc()
      self.__notifyFailure(name, Extract.DataFailed, tb)

  #
  # Private Interface
  # 

  def __encode(self, path):
    apath = ""
    for byte in path:
      if ord(byte) <= 0x1f or byte in "\"*:<>?\/|":
        apath += "0x%0.2x" % ord(byte) 
      else:
        apath += byte
    for reserved in Extract.reservednames:
      if apath.startswith(reserved):
        apath = "_" + apath
        break
    path = apath
    return path

  def __toFSUnicode(self, data):
    if type(data) == types.UnicodeType:
      if self.__fsEncoding in ('mbcs', 'utf-8'):	    
	data = data.decode(data, 'utf-8', 'replace')
      else:
        data = data.encode(data, 'utf-8', 'replace')
    else:
      if self.__fsEncoding in ('mbcs', 'utf-8'):	    
	data = unicode(data, 'utf-8', 'replace')
    data = self.__encode(data)
    return data


  def __countItems(self, node, extract_original, depth):
    if node.size():
      if node.hasChildren():
        if extract_original:
          self.total_files += 1
        self.total_folders += 1
        if depth > 0:
          children = node.children()
          for child in children:
            self.__countItems(child, extract_original, depth-1)
      else:
        self.total_files += 1
    elif node.hasChildren() or node.isDir():
      self.total_folders += 1
      if node.hasChildren() and depth > 0:
        children = node.children()
        for child in children:
          self.__countItems(child, extract_original, depth-1)
    else:
      self.total_files += 1

  def __splitNodeAbsolute(self, node):
    t = []
    while node.this != self.__vfsRoot.this:
        t.append(node)
	node = node.parent()
    t.reverse()
    return t

  def __splitNodePath(self, node):
     return self.__splitNodeAbsolute(node.parent())	  

  def __makePreservedDirs(self, node, dst):
    if node.path() == "/":
      abspath = dst
    else:
      relpath = ""
      for cnode in self.__splitNodePath(node):
        encpath = self.__toFSUnicode(cnode.name())
        relpath = os.path.join(relpath, encpath)
        abspath = os.path.join(dst, relpath)
        if os.path.exists(abspath):
          if os.path.isfile(abspath):
            os.remove(abspath)
            os.mkdir(abspath)
        else:
	  try:	
            os.mkdir(abspath)
	  except Exception as e:
	    raise e
    return abspath


  def __generateAbsolutePath(self, node, dst):
    absfile = ""
    absfolder = ""
    renamed = False
    if node.isDir() or node.hasChildren():
      if node.size():
        absfile = os.path.join(dst, self.__toFSUnicode(node.name() + ".bin"))
      absfolder = os.path.join(dst, self.__toFSUnicode(node.name()))
    else:
      absfile, renamed = self.__generateItemName(dst, node) 
      absfile = os.path.join(dst, absfile)
    if renamed:
      self.__notifyRename(node.absolute(), absfile)
    return (absfile, absfolder, renamed)

  def __extractTree(self, src, dst, overwrite, extract_original, depth):
    try:
      absfile, absfolder, renamed = self.__generateAbsolutePath(src, dst)
    except Exception:
      tb = traceback.format_exc()
      if src.isFile():
        self.__notifyFailure(src.absolute(), Extract.FileFailed, tb)
      else:
        self.__notifyFailure(src.absolute(), Extract.FolderFailed, tb)
      return
    if len(absfolder):
      if len(absfile) and extract_original:
        self.__extractFile(src, absfile, overwrite)
      self.__makeFolder(src, absfolder, extract_original, depth)
      if depth > 0:
        children = src.children()
        for child in children:
          self.__extractTree(child, absfolder, overwrite, extract_original, depth-1)
    elif len(absfile):
      self.__extractFile(src, absfile, overwrite)


  def __extractFile(self, src, dst, overwrite):
    self.__notifyOverallProgress()
    if os.path.exists(dst) and not overwrite:
      if not os.path.isfile(dst):
        os.remove(dst)
      else:	    
        self.extracted_files += 1
        self.__notifyOverallProgress()
        return
    sysfile = None
    vfile = None
    try:
      try:	    
        sysfile = open(dst, 'wb')
      except Exception as e:
         self.__notifyFailure(src.absolute(), Extract.FileFailed, tb)
	 return  
      if src.size() == 0:
        sysfile.close()
        self.extracted_files += 1
        self.__notifyOverallProgress()
        return
      vfile = src.open()
      readsize = 8192
      filesize = src.size()
      update = False
      if filesize > 10*1024*1024:
        update = True
      percent = 0
      totalread = 0 
      readed = 1
      while totalread < filesize and readed > 0:
        toread = filesize - totalread
        if  toread > readsize:
          toread = readsize
        buff = vfile.read(toread)
        readed = len(buff)
        if readed != toread:
          vfile.seek(totalread)
          buff = vfile.read(toread)
          readed = len(buff)
          if readed != toread:
            raise Exception("Can't read whole file " + src.absolute() + "\n (" + str(totalread) + "/" + str(filesize) + ") .")
        totalread += readed
        sysfile.write(buff)
        if update and percent < round(totalread * 100 / filesize):
          percent = round(totalread * 100 / filesize)
          self.__notifyFileProgress(src, percent)
      vfile.close()
      sysfile.close()
      self.extracted_files += 1
    except Exception as e:
      if sysfile:
        sysfile.close()
      if vfile:
        vfile.close()
      self.files_errors += 1
      tb = traceback.format_exc()
      self.__notifyFailure(src.absolute(), Extract.FileFailed, tb)
    self.__notifyOverallProgress()


  def __makeFolder(self, node, syspath, extract_original, depth):
    ret = True
    if not os.path.exists(syspath):
      try:
        os.mkdir(syspath)
        self.extracted_folders += 1
      except Exception:
        tb = traceback.format_exc()
        self.__notifyFailure(node.absolute(), Extract.FolderFailed, tb)
        self.__countOmmited(node, extract_original, depth-1)
        ret = False
    else:
      self.extracted_folders += 1
    self.__notifyOverallProgress()
    return ret

  def __generateItemName(self, abspath, node):
    item = self.__toFSUnicode(node.name())
    renamed = False
    try:
      targets = os.listdir(abspath)
    except OSError:
      return (item, renamed)
    item_base, item_ext = os.path.splitext(item)
    for target in targets:
      if item == target:
        item = item_base + "_" + str(node.uid()) + item_ext
        renamed = True
        break
    return (item, renamed)


  def __notifyRename(self, src, dst):
    e = event()
    e.thisown = False
    e.type = Extract.RenameOccured
    vl = VList()
    vl.append(Variant(src))
    vl.append(Variant(dst))
    e.value = RCVariant(Variant(vl))
    self.notify(e)

  def __notifyFileProgress(self, node, percent):
    e = event()
    e.thisown = False
    e.type = Extract.FileProgress
    vl = VList()
    vl.append(Variant(node))
    vl.append(Variant(int(percent)))
    e.value = RCVariant(Variant(vl))
    self.notify(e)


  def __notifyFailure(self, src, ftype, tb):
    e = event()
    e.thisown = False
    e.type = ftype
    vl = VList()
    vl.append(Variant(src))
    vl.append(Variant(str(tb)))
    e.value = RCVariant(Variant(vl))
    self.notify(e)


  def __notifyOverallProgress(self):
    buff = ""
    if self.total_files > 0:
      percent = (float(self.extracted_files) * 100) / self.total_files
      buff += "extracted file(s):   " + str(self.extracted_files) + "/" + str(self.total_files) + " (" + str(round(percent, 2)) + "%)\n"
    if self.total_folders > 0:
      percent = (float(self.extracted_folders) * 100) / self.total_folders
      buff += "extracted folder(s): " + str(self.extracted_folders) + "/" + str(self.total_folders) + " (" + str(round(percent, 2)) + "%)\n"
    if self.files_errors > 0 and self.total_files > 0:
      percent = (float(self.files_errors) * 100) / self.total_files
      buff += "file(s) error:       " + str(self.files_errors) + "/" + str(self.total_files) + " (" + str(round(percent, 2)) + "%)\n"
    if self.folders_errors > 0 and self.total_folders > 0:
      percent = (float(self.folders_errors) * 100) / self.total_folders
      buff += "folder(s) error:     " + str(self.folders_errors) + "/" + str(self.total_folders) + " (" + str(round(percent, 2)) + "%)\n"
    if self.ommited_files > 0 and self.total_files > 0:
      percent = (float(self.ommited_files) * 100) / self.total_files
      buff += "ommited file(s):     " + str(self.ommited_files) + "/" + str(self.total_files) + " (" + str(round(percent, 2)) + "%)\n"
    if self.ommited_folders > 0 and self.total_folders > 0:
      percent = (float(self.ommited_folders) * 100) / self.total_folders
      buff += "ommited folder(s):   " + str(self.ommited_folders) + "/" + str(self.total_folders) + " (" + str(round(percent, 2)) + "%)\n"
    e = event()
    e.type = Extract.OverallProgress
    e.value = RCVariant(Variant(buff))
    e.thisown = False
    self.notify(e)


  def __countOmmited(self, node, extract_original, depth):
    if node.size():
      if node.hasChildren():
        if extract_original:
          self.ommited_files += 1
        self.ommited_folders += 1
        if depth > 0:
          children = node.children()
          for child in children:
            self.__countOmmited(child, extract_original, depth-1)
      else:
        self.ommited_files += 1
    elif node.hasChildren() or node.isDir():
      self.ommited_folders += 1
      if node.hasChildren() and depth > 0:
        children = node.children()
        for child in children:
          self.__countOmmited(child, extract_original, depth-1)
    else:
      self.ommited_files += 1
