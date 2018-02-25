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
#  Christophe Malinge <cma@digital-forensic.org>
#  Solal Jacob <sja@digital-forensic.org>
#
from dff.ui.conf import Conf

class history():
  class __history():
    def __init__(self):
      self.conf = Conf()
      self.hist = []
      self.wfile = None
      self.current = 0
      self.load()

    def load(self):
        self.path = self.conf.historyFileFullPath
        if self.wfile:
          self.wfile.close()
        try:
          if not self.conf.noHistoryFile and not self.conf.noFootPrint:
            self.rfile = open(self.path, 'r')
            self.wfile = open(self.path, 'a')
            self.hist = self.rfile.readlines()
            self.rfile.close()
        except IOError:
          if not self.conf.noHistoryFile and not self.conf.noFootPrint:
            self.wfile = open(self.path, 'a')
        self.current = len(self.hist) - 1 if len(self.hist) != 0 else 0
        return


    def getnext(self):
        cmd = None
        if len(self.hist) and self.current != len(self.hist) - 1:
          self.current += 1
          cmd = self.hist[self.current]
          return cmd.strip('\n')
        return cmd


    def getprev(self):
        cmd = None
        pos = self.current
        if len(self.hist) and pos >= 0:
          cmd = self.hist[pos]
          cmd.strip('\n')
          self.current = self.current - 1 if pos != 0 else 0
        return cmd


    def save(self):
        if not self.conf.noHistoryFile and not self.conf.noFootPrint:
          self.wfile.close()


    def add(self, cmd):
        try: 
          self.hist += [ cmd ]
          self.current = len(self.hist) - 1
          if not self.conf.noHistoryFile and not self.conf.noFootPrint:
            self.wfile.write(cmd.encode('utf-8') + "\n")
            self.wfile.flush()
        except IOError:
          print "can't write on history" 
        return 

    def clear(self):
        self.hist = []
        if not self.conf.noHistoryFile and not self.conf.noFootPrint:
          self.wfile.close()
          self.wfile = open(self.path, 'w')

  __instance = None

  def __init__(self):
    if history.__instance is None:
       history.__instance = history.__history()

  def __setattr__(self, attr, value):
    setattr(self.__instance, attr, value)

  def __getattr__(self, attr):
    return getattr(self.__instance, attr)
