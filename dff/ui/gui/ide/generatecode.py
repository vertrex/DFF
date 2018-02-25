# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
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
#  Jeremy Mounier <jmo@digital-forensic.org>
# 
import sys

class GenerateCode():
    def __init__(self):
        pass
    
    def set_header(self, fname, lname, mail):
        self.fname = fname
        self.lname = lname
        self.mail = mail

    def setTag(self, tag):
        self.tag = tag

    def setDescription(self, desc):
        self.description = desc

    def generate_header(self):
        buff="# DFF -- An Open Source Digital Forensics Framework\n\
#\n\
# This program is free software, distributed under the terms of\n\
# the GNU General Public License Version 2. See the LICENSE file\n\
# at the top of the source tree.\n\
# \n\
# See http://www.digital-forensic.org for more information about this\n\
# project. Please do not directly contact any of the maintainers of\n\
# DFF for assistance; the project provides a web site, mailing lists\n\
# and IRC channels for your use.\n\
# \n\
# Author(s):\n\
#  " + self.fname + " "+ self.lname +" < " + self.mail + ">\n\
#\n\
\n"
        return buff

    def generate_script(self,  scriptname):
        buff = self.generate_header()
        buff += "import sys\n\
from api.module.script import Script\n\
from api.module.module import Module\n\
from api.types.libtypes import Argument, typeId\n\
\n\
from PyQt4.QtCore import QSize, SIGNAL\n\
from PyQt4.QtGui import QWidget\n\
from ui.gui.utils.utils import Utils\n\
\n\
class " + scriptname.upper() + "(Script):\n\
    def __init__(self):\n\
	#Module initialization goes here\n\
	Script.__init__(self, \"" + scriptname + "\")\n\
\n\
    def c_display(self):\n\
	# You can add console display function here\n\
	# such as ncurses func or others display functions.\n\
	#ex: print \"something\"\n\
	pass\n\
\n\
    def start(self, args):\n\
       # get your arguments here.\n\
       # Do something.\n\
       try:\n\
          self.parent = args[\"file\"].value()\n\
          print \"Hello World\"\n\
       except IndexError:\n\
          print \"Could not get \'file\' argument.\"\n\
\n\
\n\
class " + scriptname + "(Module):\n\
  def __init__(self):\n\
    Module.__init__(self, \"" + scriptname + "\", " + scriptname.upper() + ")\n\
\n\
    # Add your argument and tags here\n\
    self.conf.addArgument({\"input\": Argument.Required|Argument.Single|typeId.Node,\n\
                           \"name\": \"file\",\n\
                           \"description\": \"Description of your module\"})\n\
    self.tags = \"" + self.tag + "\" \n"
        return buff

    def generate_script_gui(self,  scriptname):
        buff = self.generate_header()
	buff += "import sys\n\
from api.module.script import Script\n\
from api.module.module import Module\n\
from api.types.libtypes import Argument, typeId\n\
\n\
from PyQt4.QtCore import QSize, SIGNAL\n\
from PyQt4.QtGui import QTextEdit\n\
from ui.gui.utils.utils import Utils\n\
\n\
class " + scriptname.upper() + "(Script, QTextEdit):\n\
    def __init__(self):\n\
	#Module initialization goes here\n\
	Script.__init__(self, \"" + scriptname + "\")\n\
\n\
    def c_display(self):\n\
	# You can add console display function here\n\
	# such as ncurses func or others display functions.\n\
	#ex: print \"something\"\n\
	pass\n\
\n\
    def g_display(self):\n\
	#This function must init a QWidget\n\
	QTextEdit.__init__(self, None)\n\
\n\
    def updateWidget(self):\n\
	#you can put your refresh on resize func here\n\
	pass\n\
\n\
    def start(self, args):\n\
       # get your arguments here.\n\
       # Do soemthing.\n\
       try:\n\
          self.parent = args[\"file\"].value()\n\
          print \"Hello World\"\n\
       except IndexError:\n\
          print \"Could not get \'parent\' argument.\"\n\
\n\
class " + scriptname + "(Module):\n\
  def __init__(self):\n\
    Module.__init__(self, \"" + scriptname + "\", " + scriptname.upper() + ")\n\
\n\
    # Add your argument and tags here\n\
    self.conf.addArgument({\"input\": Argument.Required|Argument.Single|typeId.Node,\n\
                           \"name\": \"file\",\n\
                           \"description\": \"Description of your module\"})\n\
    self.tags = \"" + self.tag + "\" \n"

        return buff	

    def generate_drivers(self,  drivername):
        buff = self.generate_header()
        buff += "from struct import unpack\n\
from api.vfs import * \n\
from api.module.module import *\n\
from api.vfs.libvfs import *\n\
from modules.fs.spare import SpareNode\n\
\n\
from api.types.libtypes import Variant, VMap, Parameter, Argument, typeId\n\
from api.vfs.libvfs import AttributesHandler\n\
from api.vfs.vfs import vfs\n\
\n\
class " + drivername + "(Module):\n\
   \"\"\"\n   " + self.description + "\n   \"\"\"\n\
   def __init__(self):\n\
      Module.__init__(self, \"" + drivername + "\", " + drivername.capitalize() +")\n\
      self.conf.addArgument({\"input\": Argument.Optional|Argument.Single|typeId.Node,\n\
                            \"name\": \"parent\", \n\
                            \"description\": \"files or folders will be added as child(ren) of this node or as the root node by default\",\n\
                            \"parameters\": {\"type\": Parameter.Editable}\n\
                            })\n\
\n\
      # you can add some arguments for your module here by using the self.conf.addArgument method\n\
      self.tags = \"" + self.tag + "\" \n\
\n\
\n\
class " + drivername.capitalize() + "(mfso):\n\
   def __init__(self):\n\
      # initialization of the driver\n\
      mfso.__init__(self, \"" + drivername + "\")\n\
\n\
      # get the VFS\n\
      self.vfs = VFS.Get()\n\
      self.name = \"" + drivername + "\"\n\
      self.__disown__()\n\
\n\
   def start(self, args):\n\
      # get the parent Node\n\
      print \"Running module...\"\n\
      try:\n\
         self.parent = args[\"parent\"].value()\n\
         print \"Hello World\"\n\
      except IndexError:\n\
         print \"Could not get \'parent\' argument.\"\n\
\n\
class " + drivername.capitalize() + "Node(Node):\n\
   \"\"\"\n\
   The type of node your driver will generate.\n\
   \"\"\"\n\n\
   def __init__(self, name, size, parent, fso): # you might need more parameters\n\
      Node.__init__(self, name, size, parent, fso)\n\
      self.__disown__()\n\
"
        return buff
