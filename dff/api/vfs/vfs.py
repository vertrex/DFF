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
#  Solal J. <sja@digital-forensic.org>
#


from dff.api.vfs.libvfs import *
import types

class vfs():
    def __init__(self):
        self.libvfs = VFS.Get()


    def walk(self, top, topdown=True, depth=-1):
        if depth == 0:
            return
        if type(top) == types.StringType:
            node = self.getnode(top.replace("//", "/"))
        elif isinstance(top, Node):
            node = top
        else:
            raise ValueError("top must be a string or a Node")
        if node == None:
            return
        children = node.children()
        dirs, files = [], []
        for child in children:
            if type(top) == types.StringType:
                item = child.name()
            elif isinstance(top, Node):
                item = child
            if child.hasChildren() or child.isDir():
                if child.size():
                    files.append(item)
                dirs.append(item)
            else:
                files.append(item)
            #if child.size() > 0:
            #    files.append(item)
        if topdown:
            yield top, dirs, files
        for name in dirs:
            if type(top) == types.StringType:
                newtop = str(top + "/" + name).replace("//", "/")
            elif isinstance(top, Node):
                newtop = name
            for x in self.walk(newtop, topdown, depth-1):
                yield x
        if not topdown:
            yield top, dirs, files


    def getnode(self, path):
        if not path:
            return self.getcwd()
        #if type(path) != type(""):
	   #return path
        if path and path[0] != "/":
            abspath = self.getcwd().absolute()
            path = str(abspath + "/" + path).replace("//", "/")
        # Avoid trailing '/'
        while len(path) > 1 and path[-1:] == "/":
            path = path[:-1]
	if type(path) == unicode:
	   path = str(path)
	node = self.libvfs.GetNode(path)
        if node:
	  return node
        return None

    def open(self, path):
	if type(path) == type(""):
            node = self.getnode(path)
        if node: #and node.is_file:
            return node.open()
        else:
            return

    def gettree(self):
        return self.libvfs.GetTree()

    def getcwd(self):
	return self.libvfs.GetCWD()

    def setcwd(self, path):
	self.libvfs.cd(path)

    def deletenode(self, node):
	return self.libvfs.DeleteNode(node)

       # return a Node's Dictionary with directory of nodeDir
    def listingDirectories(self, nodeDir):
        if nodeDir == False:
            return False
        listing = []
        list = nodeDir.children()
        for i in list:
            if i.hasChildren():# or not i.is_file :
                listing.append(i)
        return listing
    
    # return a Node's Dictionary with files and directory of nodeDir
    def listingDirectoriesAndFiles(self, nodeDir):
        if nodeDir == False:
            return False
        if not nodeDir.hasChildren(): #and nodeDir.is_file:
            return False
        listing = []
        list = nodeDir.children()
        for i in list:
            listing.append(i)
        return listing
    
    def getInfoDirectory(self, nodeDir):
        list = nodeDir.children()
        info = {}
        info['size'] = 0
        info['item'] = 0

        for i in list :
            if i.hasChildren(): #or not i.is_file :
                info_child = self.getInfoDirectory(i)
                info['size'] = info['size'] + info_child['size']
                info['item'] = info['item'] + info_child['item'] + 1
            else :
                info['item'] = info['item'] + 1
                info['size'] = info['size'] + i.size()
        return info

    def link(self, node, dest):
        pass
        #Link(node, dest)
