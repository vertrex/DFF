#!/usr/bin/python2 
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
import os, sys, getopt

from dff.api.manager.manager import ApiManager

from dff.ui.gui.gui import GUI
from dff.ui.console.console import Console
from dff.ui.ui import parseArguments

MODULES_PATHS = ["dff/modules"]

def fg():
    """Launch shell loop"""
    ui.launch()

if __name__ == "__main__":
    """You can place some script command here for testing purpose"""
    arguments = parseArguments()
    if not arguments.graphical or arguments.batch:
       ui = console = Console(arguments=arguments)
       console.loadModules(MODULES_PATHS)
       if arguments.batch:
         console.onecmd("batch " + arguments.batch, False)
    if arguments.graphical:
        ui = gui = GUI(arguments)
    ui.launch(MODULES_PATHS)
