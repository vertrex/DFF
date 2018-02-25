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
#  Christophe Malinge <cma@digital-forensic.org>
#  Frederic Baguelin <fba@digital-forensic.org>
#
import sys,string, os, traceback, types, completion, signal
import line_to_arguments
import threading
import re

from cmd import Cmd

from dff.api.manager.manager import ApiManager
from dff.api.types.libtypes import ConfigManager

from dff.ui.ui import UI
from dff.ui.console.complete_raw_input import complete_raw_input
from dff.ui.history import history

PROMPT = "dff / > "
INTRO = "\nWelcome to the Digital Forensic Framework\n"
IDENTCHARS = string.ascii_letters + string.digits + '\ _='

class Console(Cmd, UI):
    def __init__(self, completekey='tab', stdin=None, stdout=None, sigstp=True, arguments=None):
        Cmd.__init__(self, completekey, stdin, stdout)
        UI.__init__(self, arguments)
        self.arguments = arguments
        self.cm = ConfigManager.Get()
        self.history = history()
        self.api = ApiManager()
        self.vfs = self.api.vfs()
        self.taskmanager = self.api.TaskManager()
	self.line_to_arguments = line_to_arguments.Line_to_arguments()
        self.old_completer = ""
        self.prompt = "dff / > "
        self.intro = "\n##########################################\n\
# Welcome on Digital Forensics Framework #\n\
##########################################\n"
	self.stdin = self
	self.completekey = '\t'
	self.comp_raw = complete_raw_input(self)
        if self.arguments:
            print arguments.verbosity
            self.completion = completion.Completion(self.comp_raw, arguments.debug, arguments.verbosity)
        else:
            self.completion = completion.Completion(self.comp_raw, False, 0)
	self.proc = None
	if os.name == 'posix' and sigstp:
  	  signal.signal(signal.SIGTSTP, self.bg)



    def launch(self, modulesPaths = None, defaultConfig = None):
       if modulesPaths or defaultConfig:
         self.loadModules(modulesPaths, defaultConfig=defaultConfig)
       self.cmdloop()


    def bg(self, signum, trace):
	if self.proc:
	   proc = self.proc
	   proc.event.set()
  	   proc.exec_flags += ["thread"]
	   print "\n\n[" + str(proc.pid) + "]" + " background " + proc.name
	   return None


    def precmd(self, line):
        return line

    def postcmd(self, stop, line):
        self.prompt = "dff " + self.vfs.getcwd().absolute() + " > "
        return stop

    def preloop(self):
	return 
 
    def postloop(self):
        print "Exiting..."

    def onecmd(self, line, wait=False):
        try:
	    if line == 'exit' or line == 'quit':
	      return 'stop'
            if len(line.strip()) == 0:
                return self.emptyline()
            iterator = re.finditer('(?<!\\\)\&&', line)
            prevpos = 0
            commands = []
            itcount = 0
            for match in iterator:
                commands.append(line[prevpos:match.span()[0]].strip())
                prevpos = match.span()[1]
            if prevpos != len(line):
                commands.append(line[prevpos:])
            noerror = True
            for command in commands:
                cmds = self.completion.lp.makeCommands(command)
                for cmd in cmds:
                    if len(cmd[3]):
                        noerror = False
                        print cmd[3]
                    else:
                        exec_type = ["console"]
                        cname = cmd[0]
                        config = self.cm.configByName(cname)
                        try:
                            args = config.generate(cmd[1])
                            if cmd[2]:
                                exec_type.append("thread")
                            self.proc = self.taskmanager.add(cname, args, exec_type)
                            if self.proc and not cmd[2]:
                                if wait:
                                    self.proc.event.wait()
                                else:
                                    while not self.proc.event.isSet():
                                        self.comp_raw.get_char(1)
                        except RuntimeError, error:
                            noerror = False
                            print "module " + cmd[0]
                            print "\t" + str(error)
                    self.proc = None
            if noerror:
                self.history.add(line.strip())
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_exception(exc_type, exc_value, exc_traceback, None, sys.stdout)


    def emptyline(self):
        pass


    def default(self, line):
        try:
            exec(line) in self._locals, self._globals
        except Exception, e:
            print e.__class__, ":", e


    def cmdloop(self, intro=None):
        self.preloop()
        if self.intro:
          print self.intro
	  self.intro = None
	else:
	  print ''
        stop = None
        while not stop:
           if self.cmdqueue:
               line = self.cmdqueue.pop(0)
           else:
	       line = self.comp_raw.raw_input()
           line = self.precmd(line)
           stop = self.onecmd(line)
           stop = self.postcmd(stop, line)
        self.postloop()

    def complete(self, line, begidx):
	line = unicode(line, 'utf-8', 'replace').strip('\n') if type(line) == types.StringType else line
        self.completion_matches = self.completion.complete(line, begidx)
        try:
            return self.completion_matches
        except IndexError:
            return None

