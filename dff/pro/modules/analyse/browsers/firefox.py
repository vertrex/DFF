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
from dff.api.filters.libfilters import Filter
from dff.api.vfs import vfs

from dff.modules.browsers.browser import Browser
from dff.modules.browsers.dtime import DTime
from dff.modules.browsers.mork import Mork
from dff.modules.browsers.config import FX_PLACES

class Firefox(Browser):
#    https://support.mozilla.org/en-US/kb/Recovering%20important%20data%20from%20an%20old%20profile#w_passwords
    def __init__(self, config):
        Browser.__init__(self, config)
        self._name = "Firefox"
        self.__historyDatabases = self.databasesBySchema({"moz_places": ['url', 'title', 'visit_count'],
                                                          "moz_historyvisits": ['visit_date']})


    def relevantDatabasesFound(self):
        return len(self.__historyDatabases) > 0


    def getProfile(self, node):
        try:
            profile =  node.parent().parent().name()
        except:
            pass


    def history(self):
        history = []
        history.extend(self._sqliteHistory())
        nodes = self.findMorkFiles()
        for node in nodes:
            history.extend(self._morkHistory(node))
        return history


    def _sqliteHistory(self):
        h = []
        for db, node in self.__historyDatabases:
            try:
                cursor = db.execute(FX_PLACES).fetchall()
                cursor2 = db.execute("select moz_places.url, moz_places.title, moz_places.rev_host, moz_places.visit_count, moz_places.hidden, moz_places.typed, moz_places.frecency from moz_places;").fetchall()
                if len(cursor) <  len(cursor2):
                    cursor = cursor2
                username = self.usernameFromPath(node.absolute())
                for row in cursor:
                 try:
                    history = []
                    if len(row) == 7:
                        (url, title, rev_host, visit_count, hidden, typed, frecency) = row
                        visit_date = None
                    else:
                        (url, title, rev_host, visit_count, hidden, typed, frecency, visit_date) = row
                    if rev_host is not None:
                        history.append(rev_host[::-1])
                    else:
                        history.append("N/A")
                    history.append(self.cutURL(title))
                    history.append(self.cutURL(url))
                    if visit_count is not None:
                        history.append(visit_count)
                    else:
                        history.append("N/A")
                    history.append(username)
                    if visit_date is not None:
                        history.append(DTime(visit_date).toPosix())
                    else:
                        history.append("N/A")
#                    history.append(hidden)
#                    history.append(typed)
                    history.append("Firefox")
                    h.append(history)
                 except Exception as e:
                    pass
                    #print "firefox._sqliteHistory iter row ", e
            except Exception as e:
                pass
                #print "firefox._sqliteHistory ", e
        return h

    def _morkHistory(self, node):
        vfile = node.open()
        data = vfile.read()
        vfile.close()
        mork = Mork()
        db = mork.digest(data)
        d = mork.json(db)
        username = self.usernameFromPath(node.absolute())
        history = []
        for j in d:
            h = []
            try:
                h.append(j["Hostname"])
            except:
                h.append(None)
            try:
                h.append(unicode(j["Name"].replace('\x00', '')))
            except:
                h.append(None)
            try:
                h.append(self.cutURL(j["Url"]))
            except:
                if h[0]:
                    h.append(j["Hostname"])
                else:
                    h.append(None)
            try:
                h.append(j["VisitCount"])
            except:
                h.append(None)
            h.append(username)
            try:
                h.append(DTime(long(j["LastVisitDate"])).toPosix())
            except:
                h.append(None)
            # try:
            #     h.append(j["Typed"])
            # except:
            #     h.append(None)
            h.append("Firefox")
            if not h in history and h[0]:

                try:
                    hidden = j["Hidden"]
                except:
                    hidden = None
                if not hidden:
                    history.append(h)
        return history
    
    def findMorkFiles(self):
        # For Firefox < version 3
        filesname = ["formhistory.dat", "history.dat"]
        v = vfs.vfs()
        rootnode = v.getnode("/")
        filters = Filter("")
        query = 'type == "database/mork"'
        filters.compile(query)
        filters.process(rootnode, True)
        result = filters.matchedNodes()
        return result
