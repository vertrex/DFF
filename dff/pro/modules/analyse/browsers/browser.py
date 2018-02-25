# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2014 ArxSys
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

#import re
#from urlparse import urlparse, urljoin
from dff.api.module.manager import ModuleProcessusManager
from dff.modules.browsers.dtime import DTime
# TODO : Decode urls with Faup could add valuable description
# https://github.com/stricaud/faup
# try:
#     from pyfaup.faup import Faup
# except ImportError:
#     pass

REG_UNINSTALL = { 
    "HKLM\Software\Microsoft\Windows\Currentversion\Uninstall\*" : 
    { "values" : '*',
      "description" : "Uninstallable software list"
      },
    "HKU\Software\Microsoft\Windows\Currentversion\Uninstall\*" : 
    { "values" : '*',
      "description" : "Uninstallable software list from users"
      },
    "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" :
        { "values" : '*',
          "description" : "Uninstallable software list from 64bit systems"
          }
    }


class RegUtils(object):
    def __init__(self):
	processusManager = ModuleProcessusManager()
        self._registry = processusManager.get('winreg')

    def hasHives(self):
        if len(self._registry.registry) > 0:
            return True
        return False

    def findInstalledSoftwares(self, softwaresName, detailed=False):
        if not softwaresName:
            return None
        inst = self._registry.getAllKeys(REG_UNINSTALL)
        installed = self.mergeValues(inst)
        if not detailed:
            installed = " ".join(installed.keys())
            founded = []
            for software in softwaresName:
                if installed.lower().find(software.lower()) >= 0:
                    founded.append(software)
            return founded
        else:
            founded = {}
            for software in softwaresName:
                for soft in installed.keys():
                    if soft.lower().find(software.lower()) >= 0:
                        founded[soft] = installed[soft]
            return founded

    def mergeValues(self, results):
        # pour un meme nom de cle, merge les valeurs
        allkeys = {}
        for result in results:
            #query = result["query"]
            #description = result["description"]
            keys = result["keys"]
            for keyname, values in keys.iteritems():
                try:
                    kv = allkeys[keyname]
                    allkeys[keyname] = dict(kv.items() + values.items())
                except:
                    allkeys[keyname] = values
#            allkeys.update(result["keys"])
        return allkeys

    def mergeKey(self, name, results):
        # merge les valeurs de l'ensemble des cles trouvees
        res = {}
        res[name] = {}
        for result in results:
            #query = result["query"]
            #description = result["description"]
            keys = result["keys"]
            for keyname, values in keys.iteritems():
                kv = res[name]
                res[name] = dict(kv.items() + values.items())
        return res
        

class Profile(object):
    def __init__(self, directory):
        pass


class Browser(object):
    def __init__(self, config={}):
        processusManager = ModuleProcessusManager()
        self._registry = processusManager.get('winreg')
        self._sqlite = processusManager.get('SqliteDB')
        self._msiecf = processusManager.get('msiecf')
        self._config = config
        self._name = ""
        self.__log = ""


    def setConfiguration(self, config):
        self._config = config


    def __findItems(self, database, items):
        for item in items:
            if item not in database:
                return False
        return True
            

    def databasesBySchema(self, schema):
        matched = []
        for db, node in self._sqlite.databases.iteritems():
            try:
                cursor = db.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [str(table[0]) for table in cursor.fetchall()]
                if self.__findItems(tables, schema.keys()):
                    found = 0
                    for table in schema.iterkeys():
                        cursor = db.execute('PRAGMA table_info({})'.format(str(table)))
                        columns = [str(column[1]) for column in cursor.fetchall()]
                        if self.__findItems(columns, schema[table]):
                            found += 1
                    if found == len(schema):
                        matched.append((db, node))
                else:
                    continue
            except:
                continue
        return matched


    def log(self):
        return self.__log


    def version(self):
        # Version || DisplayVersion in registry conf
        if not self._config:
            return "N/A"
        try:
            return self._config["Version"]
        except KeyError:
            pass
        try:
            return self._config["DisplayVersion"]
        except KeyError:
            return "N/A"

    def installDate(self):
        if not self._config:
            return "N/A"
        try:
            # From Registry creation key
            ts = self._config["KeyModifiedTime"]
            dt = DTime(ts)
            return dt.toNT64()
        except KeyError:
            return "N/A"


    def name(self):
        return self._name


    def history(self):
        return []


    def typed(self):
        return []


    def usernameFromPath(self, path):
        spath = path.split('/')
        if "NTFS" in spath:
            try:
                idx = spath.index("Documents and Settings")
                return spath[idx + 1]
            except ValueError:
                pass
            try:
                idx = spath.index("Users")
                return spath[idx + 1]
            except ValueError:
                return "N/A"
        elif "extfs" in path.lower():
            try:
                idx = spath.index("home")
                return spath[idx + 1]
            except:
                return "N/A"
        elif path.lower().find("hfs"):
            try:
                idx = spath.index("Users")
                return spath[idx + 1]
            except:
                return "N/A"            
        return "N/A"


    def cutURL(self, url):
        splitedURL = ""
        maxSize = 30
        for x in range((len(url)/maxSize)+1):
           splitedURL += url[x*maxSize:(x*maxSize)+maxSize] + "<wbr>" #XXX rajoute un - encore pire :) 
        return splitedURL
