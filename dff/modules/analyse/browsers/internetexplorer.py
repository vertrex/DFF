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

import re
from .browser import Browser

from dff.modules.msiecf.hash_records import Url, Redr, Leak
from dff.modules.msiecf.msiecf_index import INDEX_TYPE

from urlparse import urlparse, urljoin

from dff.modules.browsers.dtime import DTime

HTTP = "http://"
HTTPS = "https://"
FTP = "ftp://"
FILE = "file://"
HOST = "Host: "
MSHELP = "mshelp://"
IEDOMAINCK = [HTTP, FILE, HOST, MSHELP, HTTPS, FTP]

REG_INTERNET_EXPLORER = {
    "HKLM\Software\Microsoft\Internet Explorer" : 
    {"values" : ["Build", "Version"],
     "description" : "Internet Explorer main configuration"
     },
    "HKU\Software\Microsoft\Internet Explorer\Main" : 
    {"values" : "*",
     "description" : "Internet Explorer main configuration"
     },
    "HKU\Software\Microsoft\Internet Explorer\TypedURLs" : 
    {"values" : "*",
     "description" : "Typed URLs"
     },
    "HKU\Software\Microsoft\Internet Explorer" : 
    {"values" : ["Download Directory"],
     "description" : "Download Directory"
     }
    }

class InternetExplorer(Browser):
    def __init__(self, config):
        Browser.__init__(self, config)
        self._name = "Internet Explorer"
        

    def readURL(self, entry):
        if entry.location():
            domain = self.domain(url)
            
    def cookies(self):
        cookies = self._msiecf.getAllRecords("COOKIE", "VALID")
        for i in cookies:
            if len(i["data"]):
                print i["index"].absolute()
                print i["index"].path()
                for e in i["data"]:
                    self.readURL(e)

 
    def history(self):
        history = []
        indexes = self._msiecf.getAllRecords("HISTORY", "VALID")
        itypes = INDEX_TYPE.keys()
        for idx in indexes:
            for entry in idx["data"]:
                if isinstance(entry, Url):
                    username = self.usernameFromPath(idx["index"].absolute())
                    url = entry.location()
#                    print entry.dataEntries(), entry.dataOffset
#                    print entry.data()
                    hits = str(entry.hits)
#                    prim_ft = DTime(entry.primFiletime).toNT64()
#                    sec_ft = DTime(entry.secFiletime).toNT64()
                    last_visited = DTime(entry.lastCheckedDatetime).toFAT()
                    if url:
                        try:
                            h = []
                            domain = self.domain(url)
                            curl = self.cutURL(domain["url"])
                            h.append(domain["domain"])
                            h.append(unicode(curl, 'utf-8', 'replace'))
                            h.append(unicode(curl, 'utf-8', 'replace'))
                            h.append(hits)
                            h.append(username)
                            h.append(last_visited)
                            h.append("Internet Explorer")
                            history.append(h)
                        except Exception as e:
                            #print "internetexplorer.history ", e
                            pass
                else:
                    pass
        return history

    def domain(self, location):
        """ Return record domain if exists"""
        res = {}
        if location:
            for dck in IEDOMAINCK:
                se = re.search(dck, location)
                if se:
                    if dck in [FILE, MSHELP]:
                        res["domain"] = "localhost"
                        res["url"] = location[se.span()[0]:]
                    elif dck == HOST:
                        netloc = location[se.span()[1]:]
                        snet = netloc.split('.')
                        if len(snet) >= 2:
                            res["domain"] = netloc
                            res["url"] = res["domain"]
                        else:
                            res["domain"] = "localhost"
                            res["url"] = netloc
                    else:
                        stri = location[se.span()[0]:]
                        url = urlparse(stri)
                        res["domain"] = url.netloc
                        res["url"] = stri
                    return res
            return None    
        else:
            return None
