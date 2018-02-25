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
# 
import sys
import ConfigParser
from os import access, R_OK
from os.path import exists, expanduser, normpath

from PyQt4.QtCore import QDir


try:
    import api.index
    INDEX_ENABLED = True
except ImportError:
    INDEX_ENABLED = False

class Conf():
    class __Conf():
        def __init__(self, confPath):
            """ Initial configuration

            By default ; no footprint !
            """
            self.initLanguage()
            self.indexEnabled = INDEX_ENABLED
            homeDir = normpath(expanduser('~') + '/')
            
            # Global settings
            self.workingDir = normpath(homeDir + '/.dff_conf/')
            self.noHistoryFile = False

            # DFF < 1.0 history file was saved in ~/.dff_history
            if exists(normpath(homeDir + '/.dff_history')):
                self.historyFileFullPath = normpath(homeDir + '/.dff_history')
            else:
                self.historyFileFullPath = normpath(self.workingDir + '/history')
            self.noFootPrint = True
            
            # Indexes configuration
            if self.indexEnabled:
                self.root_index = normpath(self.workingDir + '/indexes/')
                self.index_name = 'default'
                self.index_path = normpath(self.root_index + '/' + self.index_name)

            # Help
            self.docPath = normpath(sys.modules['dff.ui.gui'].__path__[0] + '/help.qhc')

            # Try reading config file, overwrite default values above if found
            if confPath:
                self.configFile = normpath(confPath)
            else:
                self.configFile = normpath(self.workingDir + '/config.cfg')
            if access(self.configFile, R_OK):
                self.read()


        def initLanguage(self):
            self.language = "en"

        def save(self):
            if self.noFootPrint:
                return
            config = ConfigParser.RawConfigParser()
            config.add_section('Global')
            config.set('Global', 'nofootprint', self.noFootPrint)
            config.set('Global', 'workingdir', self.workingDir)
            config.set('Global', 'nohistoryfile', self.noHistoryFile)
            config.set('Global', 'historyfilefullpath', self.historyFileFullPath)
            config.add_section('Language')
            config.set('Language', 'use', self.language)
            if self.indexEnabled:
                config.add_section('Index')
                config.set('Index', 'rootindex', self.root_index)
                config.set('Index', 'indexname', self.index_name)
                config.set('Index', 'indexpath', self.index_path)
            config.add_section('Help')
            config.set('Help', 'helppath', self.docPath)
            configfile = open(self.configFile, 'wb')
            if configfile:
		config.write(configfile)
		configfile.close()

        def read(self):
            config = ConfigParser.RawConfigParser()
            config.read(self.configFile)
            self.noFootPrint = config.getboolean('Global', 'nofootprint')
            self.workingDir = config.get('Global', 'workingdir')
            self.noHistoryFile = config.getboolean('Global', 'nohistoryfile')
            self.historyFileFullPath = config.get('Global', 'historyfilefullpath')
            self.language = config.get('Language', 'use')
            if self.indexEnabled:
                try:
                    config.items('Index')
                    self.root_index = config.get('Index', 'rootindex')
                    self.index_name = config.get('Index', 'indexname')
                    self.index_path = config.get('Index', 'indexpath')
                except ConfigParser.NoSectionError:
                    self.root_index = ""
                    self.index_name = ""
                    self.index_path = ""
            self.docPath = config.get('Help', 'helppath')

            
    __instance = None
    
    def __init__(self, confPath = ''):
        if Conf.__instance is None:
            Conf.__instance = Conf.__Conf(confPath)

    def __setattr__(self, attr, value):
	setattr(self.__instance, attr, value)
  
    def __getattr__(self, attr):
	return getattr(self.__instance, attr)
    
    def setLanguage(self, lang):
        self.language = lang

    def getLanguage(self):
        return self.language

