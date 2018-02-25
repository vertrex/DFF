#!/usr/bin/python
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
#  Solal Jacob <sja@digital-forensic.org>
#

"""@package dff
Digital-forensic framework launcher
"""
import os, sys, subprocess

if os.name == "nt":
    sys.path.append(os.path.abspath("third-party"))
    os.environ['PATH'] = os.path.abspath(os.path.join("third-party", "bin")) + ";" + os.environ['PATH']

from dff.api.manager.manager import ApiManager

from dff.ui.console.console import Console
from dff.pro.ui.gui.gui import GUIPro as GUI
from dff.ui.ui import parseArguments

MODULES_PATHS = ["dff/modules", "dff/pro/modules"]

def fg():
    """Launch shell loop"""
    ui.launch()

if __name__ == "__main__":
    """You can place some script command here for testing purpose"""
    arguments = parseArguments()
    clamProcessus = None
    if os.name == "nt":
        try:
            sinfo = subprocess.STARTUPINFO()
            sinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            clamProcessus = subprocess.Popen("third-party/clamd/clamd.exe",
                                             cwd="third-party/clamd", startupinfo=sinfo)
        except:
            sys.stderr.write("Unable to start clamd antivirus daemon")
    if not arguments.graphical or arguments.batch:
       ui = console = Console(arguments=arguments)
       console.loadModules(MODULES_PATHS)
       if arguments.batch:
         console.onecmd("batch " + arguments.batch, False)
    if arguments.graphical:
        ui = gui = GUI(arguments)
    try:
        ui.launch(MODULES_PATHS)
    except Exception as e:
        print str(e)
        if clamProcessus is not None:
            clamProcessus.terminate()
