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

from urlparse import urlparse, urljoin
from dff.modules.browsers.browser import Browser

import re

class Chrome(Browser):
    def __init__(self, config):
        Browser.__init__(self, config)
        self._name = "Chrome"
        self.qhistory = "SELECT datetime(urls.last_visit_time/1000000-11644473600,\'unixepoch\'),urls.url, urls.title, urls.visit_count, urls.hidden FROM urls"
        self.qcookies = "SELECT datetime(creation_utc/100000-11644473600, \
        \'unixepoch\'), datetime(expires_utc/1000000-11644473600,\
        \'unixepoch\'), host_key, name, value, path, secure FROM \
        cookies ORDER BY cookies.expires_utc DESC"
        self.__historyDatabases = self.databasesBySchema({"urls": ['url'],
                                                          "downloads": ['opened'], 
                                                          "visits": ["visit_duration"], 
                                                          "visit_source": ["source"]})


    def relevantDatabasesFound(self):
        return len(self.__historyDatabases) > 0      


    def history(self):
#       history["thead"] = ["hostname", "url", "title", "count", "username", "visit_date", "hidden", "typed", "browser"]
        h = []
        for db, node in self.__historyDatabases:
            try:
                cursor = db.execute(self.qhistory).fetchall()
                username = self.usernameFromPath(node.absolute())
                for row in cursor:
                    history = []
                    (visit_date, url, title, count, hidden) = row
                    history.append(urlparse(url).netloc)
                    history.append(self.cutURL(title))
                    history.append(self.cutURL(url))
                    history.append(count)
                    history.append(username)
                    history.append(visit_date)
                    history.append("Chrome")
                    if not hidden:
                        h.append(history)
            except:
                pass
        return h        
