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
#  Solal J. <sja@digital-forensic.org>
#

import os, sys
import imp
import re
import traceback
from distutils.version import StrictVersion
from stat import *

from dff.api.module.module import *
from dff.api.types.libtypes import ConfigManager
from dff.api.vfs.libvfs import VFS, fso, mfso

__module_prepend__ = '__dff_module_'
__module_append__ = '_version__'
# Depencies are in this form : __api_env_minversion__ = '1.0.0'
__api_components__ = ['devices', 'env', 'exceptions', 'gui', 'loader', 'magic', 'manager', 'module', 'search', 'taskmanager', 'tree', 'type', 'variant', 'vfs']
__api_version_prepend__ = '__api_'
__api_version_append__ = '_minversion__'

class loader():
    class __loader():
        def pprint(self, args):
             print args

        def LoadFile(self, module_path):
            filename = module_path[module_path.rfind("/")+1:]
            path = module_path[:module_path.rfind("/")+1]
# Strict .py check ; avoid .pyc, for example
            if filename.endswith(".py"):
#            if filename.rfind(".py") != -1:
                if path not in sys.path:
# Append to sys.path only once
                    sys.path.append(path)
                self.ModuleImport(module_path, filename[:filename.rfind(".py")])

        def LoadDir(self, module_path):
            files = os.listdir(module_path)
            if module_path[len(module_path) - 1] != "/":
                module_path += "/"
            for filename in files:
                if not filename.startswith(".") and not filename.startswith("__") and not filename.startswith("#"):
                    try:
                        mode = os.stat(module_path+filename)[ST_MODE]
                    except:
                        print "Can't access " + str(module_path+filename)
			return     
                    if mode:
                        if S_ISDIR(mode):
                            self.LoadDir(module_path+filename)
                        else:
                            self.LoadFile(module_path+filename)

        def Load(self, args):
            module_path = args
            mode = None
            self.loadingErrors = ""
            try:
	      self.pprint("loading modules in " + module_path)
              mode = os.stat(module_path)[ST_MODE]
            except:
              print "File doesn't exist"
            if mode:
              if S_ISDIR(mode):
                self.LoadDir(module_path)
              elif S_ISREG(mode):
                self.LoadFile(module_path)
              else:
               print "unsupported stat type"
            if len(self.loadingErrors):
                print "\n" + self.loadingErrors
                print "\n" + "If you really need theses modules, please consider either"
                print "\n   - to install dependencies by yourself"
                print "\n   - or to have a look at our professional support -- http://www.arxsys.fr/support"
 

        def _versionFromLine(self, line):
            ''' 

            '''
            if line.startswith(__module_prepend__) and line.find(__module_append__) != -1:
                m = re.search('^' + __module_prepend__ + '([a-zA-Z0-9_]+)' + __module_append__ + '\s*=\s*[\'\"]([ab0-9\.]+)[\'\"]\s*$', line)
                if m and len(m.groups()) == 2:
                    return (__module_prepend__, [m.group(1), m.group(2)])
            if not line.startswith(__api_version_prepend__):
                return None
            for oneComponent in __api_components__:
                if line.startswith(__api_version_prepend__ + oneComponent + __api_version_append__):
                    m = re.search('^' + __api_version_prepend__ + oneComponent + __api_version_append__ + '\s*=\s*[\'\"]([ab0-9\.]+)[\'\"]\s*$', line)
                    if m and len(m.groups()) == 1:
                        return (oneComponent, m.group(1))
            return None
            # future : must return api component name in order to warn about missing component
                    
            
        def _validateDFFModule(self, module_path):
            ''' Return a version dict if file path given is a valid DFF module.

            A valid DFF module has variable __dff_module_NAME_version__ sets
            right after header.
            Header is :
             - Each line starting with a sharp character
             - Text block delimited by three quote characters
             - Text block delimited by three double quote characters
            '''
            vDict = dict()
            f = open(module_path, 'r')
	    if f:
                b = f.read(4096)
                start = -1
                headerT1, headerT2 = False, False
                rest = ''
                while len(b):
                    b = b + rest
                    end = b.find('\n', start + 1)
                    while end != -1:
                        line = b[start + 1:end]
                        # Skip header line starting with #
                        if line.startswith('#'):
                            pass
                        # Skip header block with ''' as delimiter
                        elif not headerT1 and line.find('\'\'\'') != -1:
                            headerT1 = True
                        elif headerT1 and line.find('\'\'\'') != -1:
                            headerT1 = False
                        elif headerT1:
                            pass
                        # Skip header block with """ as delimiter
                        elif not headerT2 and line.find('\'\'\'') != -1:
                            headerT2 = True
                        elif headerT2 and line.find('\'\'\'') != -1:
                            headerT2 = False
                        elif headerT2:
                            pass
                        # Skip whitespaces-only or empty lines
                        elif not len(line) or line.isspace():
                            pass
                        
                        # Search for __dff_module_version__ or
                        #  __api_*_minversion__
                        elif line.startswith('__'):
                            vFound = self._versionFromLine(line)
                            if vFound:
                                vDict[vFound[0]] = vFound[1]
                            
                        start = b.find('\n', start + 1)
                        end = b.find('\n', start + 1)
                    if start > 0:
                        rest = b[start - 1:]
                        start = 0
                    else:
                        rest = b
                    b = f.read(4096)
            if f:
		f.close()
	    return vDict

            
        def ModuleImport(self, module_path, modname):
            start = False
            init = False
            type = False
            status = ''
            warnwithoutload = False
            
	    if modname == "loader":
		return

            vDict = self._validateDFFModule(module_path)
            
            if vDict and __module_prepend__ in vDict:
                if __module_prepend__ in vDict:
                    if len(vDict) < 2:
                        status += 'v' + vDict[__module_prepend__][1]
                    else:
                        status += 'v' + vDict[__module_prepend__][1] + ', requires'
                        for k, v in vDict.iteritems():
                            if k != __module_prepend__:
                                status += ' ' + k + ' v' + vDict[k]
                                if hasattr(sys.modules['api.' + k], '__version__'):
                                    # Component version >= required version
                                    if StrictVersion(sys.modules['api.' + k].__version__) >= StrictVersion(vDict[k]):
                                        status += ' (<= v' + sys.modules['api.' + k].__version__ + ')'
                                    else:
                                        status += ' (> v' + sys.modules['api.' + k].__version__ + ' !!)'
                                        warnwithoutload = True
            else:
                # About to be deprecated ; read all module content to find "(Module)"
                status += 'using old style module check'
                flag = False
                f = open(module_path, 'r')
		if f:
                    for line in f:
                        if line.find("(Module)") != -1:
                            flag = True
                            break
                if f:
		    f.close()
		if not flag:
                    return

            if warnwithoutload:
                self.pprint('[WARN]\tnot loading ' + status + ': API required version greather than actual API component version')
                return
            usedmodules = self.vfs.fsobjs()
            if modname in sys.modules:
                module = sys.modules[modname]
                cl = getattr(module, modname)
                tmod = cl()
                rmodname = tmod.name
                removable = True
                if removable:
                    self.cm.unregisterConf(rmodname)
                    del tmod
                    del module
                    self.__load(module_path, modname, status, False)
                else:
                    print "module", modname, "cannot be deleted because it is already in use"  
            else:
                self.__load(module_path, modname, status, True)

        
        def __load(self, module_path, modname, status, first=True):
            file, pathname, description = imp.find_module(modname, [os.path.dirname(module_path)])
            try:
                module = imp.load_module(modname, file, pathname, description)
                cl = getattr(module, modname)
                mod = cl()
                self.modules[mod.name] = mod
		try :
	           self.tags[mod.tags].append(mod.name)
		except KeyError:
		   self.tags[mod.tags] = [mod.name]
                sys.modules[modname] = module
                self.cm.registerConf(mod.conf)
                self.pprint('[OK]\tloading ' + modname + ' ' + status) 
	    except :
		err_type, err_value, err_traceback = sys.exc_info()
	        for l in  traceback.format_exception_only(err_type, err_value):
		  print l
	        for l in  traceback.format_tb(err_traceback):
		   print l

        def __init__(self):
            self.cm = ConfigManager.Get()
            self.vfs = VFS.Get()
            self.cmodules = {}
            self.scripts = {}
            self.builtins = {}
	    self.modules = {}
	    self.tags = {}
            self.loadedPaths = []
            self.__modulesPaths = []       
 
    __instance = None
 
    def __init__(self):
        if loader.__instance is None:
            loader.__instance = loader.__loader()

    def __setattr__(self, attr, value):
        setattr(self.__instance, attr, value)

    def __getattr__(self, attr):
        return getattr(self.__instance, attr)

    def get_modules(self, modules=None):
         if modules:
           try:
            mod = self.modules[modules]
            return mod.name
           except KeyError:
		return None
         else:
           lmod = [] 
           for name, mod in self.modules.iteritems():
	     lmod += [name]
	   return lmod

    def is_modules(self, mod):
         try:
           mod = self.__instance.modules[mod]
         except KeyError:
           return False
         return True

    def get_conf(self, mod):
         try:
           mod = self.__instance.modules[mod]
         except KeyError:
           return None
         return mod.conf 

    def get_tags(self, modu):
         try:
           mod = self.__instance.modules[modu]
         except KeyError:
           return None
         return mod.tags

    def modulesPaths(self):
        return self.__modulesPaths

    def do_load(self, args, pprint = None, reload = False):
        for arg in args:
           self.__modulesPaths.append(arg)
        if type(args) != list:
          args = [args]
        for arg in args:
          path = arg
	  if os.name == "nt":
	    if arg[1] != ":":
              path = os.getcwd() + "/" + arg
    	  else:	
            if arg[0] != "/":
              path = os.getcwd() + "/" + arg
          if pprint:
            self.__instance.pprint = pprint
          if not path in self.loadedPaths or reload:
            self.__instance.Load(path)
            self.loadedPaths.append(path)

    def help_load(self):
        print "load [path/[file]]"
    
    def do_lsmod(self, args):
        """List loaded modules"""
        return []
