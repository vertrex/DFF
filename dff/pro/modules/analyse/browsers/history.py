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
from collections import namedtuple

from dff.modules.msiecf.hash_records import Url, Redr, Leak

from dff.modules.browsers.dtime import DTime

HISTORY_HEADER = ["browser",
          "url",
          "hits",
          "last_visited",
          "page_title", 
          "prim_ft",
          "sec_ft",
          "typed",
          "hidden",
          "frecency"
          ]

FOXHISTORY = namedtuple('FOXHISTORY', 'url, title, rev_host, visit_count, hidden, typed, frecency, last_visit_date')

class History():
    def __init__(self, header=HISTORY_HEADER):
        self.header = header
        self.initAttr()

    def initAttr(self):
        for head in HISTORY_HEADER:
            setattr(self, head, None)

    def setIE(self, obj):
        if isinstance(obj, Url):
            self.browser = "Internet Explorer"
            self.url = obj.location()
            self.hits = str(obj.hits)
            self.prim_ft = DTime(obj.primFiletime).toNT64()
            self.sec_ft = DTime(obj.secFiletime).toNT64()
            self.last_visited = DTime(obj.lastCheckedDatetime).toFAT()
        elif isinstance(obj, Redr):
            self.browser = "Internet Explorer"
            self.url = obj.location()
        else:
            return False
        return True

    def setFirefox(self, obj):
        if hasattr(obj, "_fields"):
            self.initAttr()
            self.browser = "Firefox"
            self.url = obj.url
            self.page_title = obj.title
            self.last_visited = DTime(obj.last_visit_date).toPosix()
            self.hits = str(obj.visit_count)
            if obj.typed == 1:
                self.typed = "Oui"
            else:
                self.typed = "Non"
            if obj.hidden == 1:
                self.hidden = "Oui"
            else:
                self.hidden = "None"
            self.frecency = str(obj.frecency)
            setattr(self, "revhost", obj.rev_host )
        else:
            return False
        return True

    def __str__(self):
        return self.url

    def __unicode__(self):
        return self.url

