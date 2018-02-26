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

from datetime import *
import time

class DTime:
    def __init__(self, timestamp):
        self._ts = timestamp
        self._datetime = None

    def toDatetime(self):
        if self._ts:
            self._datetime = datetime.fromtimestamp(self._ts)
            return self._datetime.isoformat()
        else:
            return None

    def toPosix(self):
        if self._ts:
            self._datetime = datetime.fromtimestamp(self._ts/1000000)
            return self._datetime.isoformat()
        else:
            return None

    def toNT64(self):
        if self._ts:
            epoch = 116444736000000000L
            sec = (self._ts - epoch) / 10000000
            self._datetime = datetime.fromtimestamp(sec)
            return self._datetime.isoformat()
        else:
            return None

    def toFAT(self):
        if self._ts:
            dos_time = (self._ts >> 16) & 0xffff
            dos_date = self._ts & 0xffff 
            day = dos_date & 31
            month = (dos_date >> 5) & 15
            year = (dos_date >> 9) + 1980
            if dos_time != 0:
                sec = (dos_time & 31) * 2
                minute = (dos_time >> 5) & 63
                hour = dos_time >> 11
            else:
                sec = minute = hour = 0
            self._datetime = datetime(year, month, day, hour, minute, sec)
            return self._datetime.isoformat()
        else:
            return None

    def __unicode__(self):
        if self._datetime:
            return self._datetime.isoformat()
        else:
            return None

    def __str__(self):
        if self._datetime:
            return self._datetime.isoformat()
        else:
            return None

