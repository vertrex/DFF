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

from dff.modules.winreg.registrymanager import RegValue

IE = "Internet Explorer"
FIREFOX = "Firefox"
CHROME = "Chrome"
UFO = "N\A"

INPUT_HEADER = [
    "browser",
    "input",
    "source",
    "times_used",
    "first_used",
    "last_used"
    ]

FOXINPUT = namedtuple('FOXINPUT', 'fieldname, value')


class Input:
    def __init__(self, header=INPUT_HEADER):
        self.header = header
        self.initAttr()

    def initAttr(self):
        for head in INPUT_HEADER:
            setattr(self, head, None)

    def setIE(self, obj):
        self.browser = IE
        self.input = obj.data()
        return True

    def setFirefox(self, obj):
        if hasattr(obj, "_fields"):
            self.browser = FIREFOX
            self.source = obj.fieldname
            self.input = obj.value
        else:
            return False
        return True

    def __str__(self):
        return self.input

    def __unicode__(self):
        return self.input

