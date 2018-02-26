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
#  Jeremy MOUNIER <jmo@digital-forensic.org>
# 

__dff_module_gen_nodes_version__ = "1.0.0"

import collections
from urlparse import urlparse
from datetime import *
import re
import time
import types

from dff.api.vfs import vfs 
from dff.api.loader import loader
from dff.api.module.module import Module
from dff.api.module.script import Script
from dff.api.module.manager import ModuleProcessusManager
from dff.api.types.libtypes import Argument, typeId
from dff.api.taskmanager.taskmanager import TaskManager

from dff.pro.api.report.manager import ReportManager

from dff.modules.browsers.browser import RegUtils
from dff.modules.browsers.firefox import Firefox
from dff.modules.browsers.chrome import Chrome
from dff.modules.browsers.internetexplorer import InternetExplorer, REG_INTERNET_EXPLORER
from dff.modules.browsers.opera import Opera

from dff.modules.analyse.analyse import Translator 

class InternetBrowsers(object):
    FIREFOX = "Firefox"
    CHROME = "Google Chrome"
    OPERA = "Opera"
    IE = "Internet Explorer"
    HISTORY = {"hostname" : 0, 
               "url" : 1, 
               "title": 2, 
               "count" : 3, 
               "username" : 4, 
               "visit_date" : 5, 
               #               "hidden" : 6, 
               #               "typed" : 7, 
               "browser" : 6}

    def __init__(self, root=None):
        self._compatible_browsers = [InternetBrowsers.FIREFOX, 
                                     InternetBrowsers.CHROME, 
                                     InternetBrowsers.OPERA,
                                     InternetBrowsers.IE]
        self.__log = []
	processusManager = ModuleProcessusManager()
        self._registry = processusManager.get('winreg')
        self._browsers = []
        self.__log.append("Trying to find browsers databases")
        self.__firefox = Firefox(None)
        self.__chrome = Chrome(None)
        self.__opera = Opera(None)
        self.__ie = InternetExplorer(None)
        self.__browsersInstalledVersion()
        if self.__firefox.relevantDatabasesFound():
            self.__log.append("\t[OK] Firefox databases found -- installed version: " + self.__firefox.version())
            self._browsers.append(self.__firefox)
        elif self.__firefox.version() != "N/A":
            self.__log.append("\t[NOK] Firefox databases not found but is installed -- version: " + self.__firefox.version())
        if self.__chrome.relevantDatabasesFound():
            self.__log.append("\t[OK] Chrome databases found -- installed version: " + self.__chrome.version())
            self._browsers.append(self.__chrome)
        elif self.__chrome.version() != "N/A":
            self.__log.append("\t[NOK] Chrome databases not found but is installed -- version: " + self.__chrome.version())
        if len(self.__opera.history()):
            self.__log.append("\t[OK] Opera databases found -- installed version: " + self.__opera.version())
            self._browsers.append(self.__opera)
        elif self.__firefox.version() != "N/A":
            self.__log.append("\t[NOK] Opera databases not found but is installed -- version: " + self.__opera.version())
        if len(self.__ie.history()):
            self.__log.append("\t[OK] Internet Explorer databases found -- installed version: " + self.__ie.version())
            self._browsers.append(self.__ie)
        elif self.__firefox.version() != "N/A":
            self.__log.append("\t[NOK] Internet Explorer databases not found but is installed -- version: " + self.__ie.version())



    def log(self):
        return self.__log


    def getMozillaVersion(self):
        v = vfs.vfs()
        root = v.getnode("/")
        version = None
        entries = []
        hku_moz_version = self._registry.getKeys({ 'HKU\Software\Mozilla\Mozilla Firefox' : ['*'] }, root)
        if hku_moz_version:
            entries.append(hku_moz_version)
        hklm_moz_version = self._registry.getKeys({ 'HKLM\Software\Mozilla\Mozilla Firefox' : ['*'] }, root)
        if hklm_moz_version:
            entries.append(hklm_moz_version)
        for entry in entries:
            for key in entry:
                for value in key.values():
                    if value.name == "CurrentVersion":
                        version = value.data()
                        break
        if type(version) == types.UnicodeType:
            return version.encode('utf-8')
        else:
            return version


    # Windows only
    def __browsersInstalledVersion(self):
        # Windows information
        regutils = RegUtils()
        if regutils.hasHives():
            founded = regutils.findInstalledSoftwares(self._compatible_browsers, detailed=True)
            iee = self._registry.getAllKeys(REG_INTERNET_EXPLORER)
            ie = regutils.mergeKey("Internet Explorer", iee)
            founded.update(ie)
            tlog = []
            for browserName, browserInformation in founded.iteritems():
                if browserName.lower().find(InternetBrowsers.FIREFOX.lower()) >= 0:
                    self.__firefox.setConfiguration(browserInformation)
                elif browserName.lower().find(InternetBrowsers.CHROME.lower()) >= 0:
                    self.__chrome.setConfiguration(browserInformation)
                elif browserName.lower().find(InternetBrowsers.OPERA.lower()) >= 0:
                    self.__opera.setConfiguration(browserInformation)
                elif browserName.lower().find(InternetBrowsers.IE.lower()) >= 0:
                    self.__ie.setConfiguration(browserInformation)


    def history(self):
        history = []
        for browser in self._browsers:
            print browser.name(), len(browser.history())


    def historyToDictionnary(self, history, key):
        try:
            rows = history
        except:
            return None
        try:
            k = InternetBrowsers.HISTORY[key]
        except :
            return None
        h = {}
        for hist in rows:
            try:
                h[hist[InternetBrowsers.HISTORY[key]]].append(hist)
            except:
                h[hist[InternetBrowsers.HISTORY[key]]] = []
                h[hist[InternetBrowsers.HISTORY[key]]].append(hist)
        return h


    def browsers(self):
        return self._browsers


class TranslateBrowsers(Translator):
  def translationMap(self):
    return {
        "Web browsers" : unicode(self.tr("Web browsers")),
        "History" : unicode(self.tr("History")),
        "Domain" : unicode(self.tr("Domain")),
        "Title" : unicode(self.tr("Title")),
        "Url" : unicode(self.tr("Url")),
        "Occurrence" : unicode(self.tr("Occurrence")),
        "User" : unicode(self.tr("User")),
        "Date" : unicode(self.tr("Date")),
        "Browser" : unicode(self.tr("Browser")),
        "Browsers history" : unicode(self.tr("Browsers history")),
        }

class BROWSERS(Script):
    def __init__(self):
       Script.__init__(self, "Web Browsers")
       self.name = "Web Browsers"


    def start(self, args):
        try:
          self.root = args["root"].value()
          rmanager = ReportManager()
          self.translator = TranslateBrowsers()
          historique = rmanager.createPage(self.translator.translate("Web browsers"), self.translator.translate("History"))
          ieb = InternetBrowsers()
          allhistory = []
          for browser in ieb.browsers():
              h = browser.history()
              allhistory.extend(h)
          thead = self.translator.translate(["Domain", "Title", "Url", "Occurence", "User", "Date", "Browser"])
          historique.addTable(self.translator.translate("Browsers history"), thead, allhistory)
          rmanager.addPage(historique)
          logs = ieb.log()
          logpage = rmanager.createPage(self.translator.translate("Web browsers"), "Logs")
          if len(logs) <= 1:
              logpage.addText("Logs", "No browsers databases found")                  
          else:
              logpage.addText("Logs", logs[0])
              for log in logs[1:]:
                  logpage.addText("", log)
          rmanager.addPage(logpage)
        except Exception as e:
            print "Browsers.start ", e
            import traceback
            traceback.print_exc()


class browsers(Module):
  """Retrieve all navigation information from Internet explorer, Firefox, Chrome and Opera browsers"""
  def __init__(self):
      Module.__init__(self, "WebBrowsers", BROWSERS)
      self.conf.addArgument({"name": "root",
			   "description" : "Root from where the analysis will start",
			   "input" : Argument.Required|Argument.Single|typeId.Node})
      self.icon = ":firefox"
      self.depends = ["File systems", "partition", "winreg", "sqlitedb", "msiecf"]
      self.tags = "Analyse"
