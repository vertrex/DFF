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
import os, sys

from dff.api.loader.loader import loader

pathset = set()

for moduleDirectory in loader().modulesPaths():
  if moduleDirectory[0] != "/":
    for files in os.listdir(os.getcwd() + "/" + moduleDirectory):
      directory = os.getcwd() + "/" + moduleDirectory + "/" + files
      if os.path.isdir(directory):
        pathset.add(directory[len(os.getcwd()) + 1:]) 
  else:
    for files in os.listdir(moduleDirectory):
      directory = moduleDirectory + "/" + files
      if os.path.isdir(directory):
        pathset.add(directory) 
      
for path in pathset:
  __path__.append(path)
