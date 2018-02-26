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
from dff.modules.browsers.dtime import DTime

from dff.api.filters.libfilters import Filter
from dff.api.vfs import vfs

import re

class Opera(Browser):
    def __init__(self, config):
        Browser.__init__(self, config)
        self._name = "Opera"
        self.__historyDatabases = self.databasesBySchema({"urls": ['url', 'title', 'visit_count', 'last_visit_time']})
        self.qhistory = "SELECT datetime(urls.last_visit_time/1000000-11644473600,\'unixepoch\'),urls.url, urls.title, urls.visit_count FROM urls"
        


    def history(self):
        nodes = self.findNodes('name matches /^global_history.dat/')
        history = []
        for node in nodes:
            history.extend(self._globalHistory(node))
        history.extend(self._sqliteHistory())
        return history


    def _sqliteHistory(self):
        h = []
        for base, node in self._sqlite.databases.iteritems():
            try:
                cursors = base.execute(self.qhistory).fetchall()
                isme = re.search(self._name, node.absolute(),  flags=re.IGNORECASE)
                if not isme:
                    continue
                username = self.usernameFromPath(node.absolute())
                for cursor in cursors:
                    history = []
                    (visit_date, url, title, count) = cursor                    
                    history.append(urlparse(url).netloc)
                    history.append(self.cutURL(title))
                    history.append(self.cutURL(url))
                    history.append(count)
                    history.append(self.usernameFromPath(node.absolute()))
                    history.append(visit_date)
                    history.append("Opera")
                    if not hidden:
                        h.append(history)
            except:
                pass
        return h        

    def _globalHistory(self, node):
        vfile = node.open()
        buff = vfile.read()
        sbuff = buff.split('\n')
        cp = 0
        history = []
        while cp < len(sbuff):
            try:
                hist = []
                h = sbuff[cp:cp+4]
                title = h[0]
                url = h[1]
                visited = DTime(int(h[2])).toEpoch()
                count = h[3]
                username = self.usernameFromPath(node.absolute())
                hist.append(urlparse(url).netloc)
                hist.append(self.cutURL(title))
                hist.append(self.cutURL(url))
                hist.append(count)
                hist.append(username)
                hist.append(visited)
                hist.append("Opera")
                cp += 4
                history.append(hist)
            except:
                break
        vfile.close()
        return history

    def findNodes(self, query):
        v = vfs.vfs()
        rootnode = v.getnode("/")
        filters = Filter("")
#        query = 'name matches re("^global_history.dat")'
        filters.compile(query)
        filters.process(rootnode, True)
        result = filters.matchedNodes()
        return result

