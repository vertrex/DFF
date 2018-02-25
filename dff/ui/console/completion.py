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
#  Frederic Baguelin <fba@digital-forensic.org>
#  Christophe Malinge <cma@digital-forensic.org>
#
import sys, os, dircache, utils, re, types, fnmatch, posixpath

from dff.api.loader.loader import loader
from dff.api.vfs.vfs import vfs
from dff.api.types.libtypes import typeId, Argument, Parameter, ConfigManager
from dff.ui.console.utils import ColumnView, unistr, ConsoleAttributes

SPECIAL_CHARS = '<>!&;|}\*?[] '

def normpath(ipath, sep):
    lsep = 0
    ret = u""
    for c in ipath:
        if c == sep:
            if not lsep:
                 lsep = 1
                 ret += c
            else:
                 continue
        else:
            lsep = 0
            ret += c
    return ret


def unicodeChild(child, _type):
    child = child if _type == typeId.Path else child.name()
    return child if type(child) == types.UnicodeType else unicode(child, 'utf-8', 'replace')


def toPosixPath(path):
    path = os.path.expanduser(path)
    if os.name == "nt":
       if path == "\\":
          return path
       backslash = 0
       result = u""
       for c in path:
          if backslash:
             backslash = 0
             if c in SPECIAL_CHARS:
                result += "\\" + c
             else:
                result += "/" + c
          else:
             if c == "\\":
                backslash = 1
                continue
             else:
                result += c
       if path[-1] == "\\":
          result += "\\"
       return result
    else:
        return path


def splitPath(ipath, ctype):
    if ipath == "":
        if ctype != typeId.Node:
            ipath = toPosixPath(os.path.abspath(""))
            ipath = unicode(ipath, 'utf-8', 'replace') if type(ipath) != types.UnicodeType else ipath
            return ipath, u""
        else:
            return unicode(vfs().getcwd().absolute(), 'utf-8', 'replace'), u""
    if ctype == typeId.Node:
        ipath = posixpath.join(vfs().getcwd().absolute(), ipath) if ipath[0] != "/" else ipath
    else:
        ipath = toPosixPath(ipath)
        if os.name == "nt":
            if ipath[0] != "/" and os.path.splitdrive(ipath)[0] == "":
                ipath = posixpath.join(toPosixPath(os.path.abspath("")), ipath)
        elif not posixpath.isabs(ipath):
            ipath = posixpath.join(posixpath.abspath(""), ipath)
    rpath, supplied = posixpath.split(ipath)
    if rpath != "/":
        rpath = posixpath.normpath(removeEscape(rpath)) + "/"
    return rpath, supplied


def isGlobed(supplied):
    special = 0
    globbed = False
    if supplied:
        backslash = 0
        for char in supplied:
            if backslash:
                backslash = 0
            else:
                if char == "\\":
                    backslash = 1
                    continue
                elif char in "*[?":
                    globbed = True
    return globbed


def removeEscape(supplied):
    special = 0
    result = u""
    if supplied:
        backslash = 0
        for char in supplied:
            if backslash:
                backslash = 0
                if char in SPECIAL_CHARS:
                    result += char
                else:
                    result += "\\" + char
            else:
                if char == "\\":
                    backslash = 1
                    continue
                else:
                    result += char
    return result


def addEscape(supplied):
    result = u""
    for char in supplied:
        if char in SPECIAL_CHARS:
            result += "\\" + char
        else:
            result += char
    return result


class Context():
    def __init__(self, DEBUG = False, VERBOSITY = 0):
        self.DEBUG = DEBUG
        self.VERBOSITY = VERBOSITY
        self.confmanager = ConfigManager.Get()
        self.config = None
        self.keylessarg = None
        self.currentArgument = None
        self.parsedArgument = None
        self.providedArguments = {}
        self.remainingArguments = []
        self.threaded = False
        self.currentStr = ""
        self.vfs = vfs()
        self.currentStrScope = 0
        self.paramsplit = re.compile('(?<!\\\)\,')
        self.badargs = []
        self.tokens = []


    def debug(self, dbg):
        if self.DEBUG and self.VERBOSITY > 0:
            print dbg

    def __makeParameter(self, argument, parameter):
        lret = []
        ctype = argument.type()
        if ctype == typeId.Node:
            path, supplied = splitPath(parameter, ctype)
            if isGlobed(supplied):
                root = self.vfs.getnode(unistr(path))
                if root:
                    children = root.children()
                else:
                    raise ValueError("Base node for globing " + unistr(parameter)  + " provided to argument < " + unistr(argument.name()) + " > does not exist")
                for child in children:
                    if fnmatch.fnmatch(addEscape(child.name()), supplied):
                        lret.append(child)
                if len(lret) == 0:
                    raise ValueError("Globing nodes with " + unistr(parameter)  + " provided to argument < " + unistr(argument.name()) + " > gives no results")
            else:
                parameter = unistr(removeEscape(parameter))
                n = self.vfs.getnode(parameter)
                if n:
                    lret.append(n)
                else:
                    raise ValueError("Node " + parameter  + " provided to argument < " + unistr(argument.name()) + " > does not exist")    
        elif ctype == typeId.Path:
            rpath, supplied = splitPath(parameter, ctype)
            if os.name == "nt":
                if rpath.startswith("/"):
                    rpath = os.path.join("C:", rpath)
                rpath = os.path.normpath(rpath)
            if isGlobed(supplied):
                try:
                    children = dircache.listdir(rpath)
                except:
                    raise ValueError("Base path for globing " + unistr(parameter)  + " provided to argument < " + unistr(argument.name()) + " > does not exist")
                for child in children:
                    if fnmatch.fnmatch(addEscape(child), supplied):
                        lret.append(unistr(os.path.join(rpath, child)))
                if len(lret) == 0:
                    raise ValueError("Globing paths with " + unistr(parameter)  + " provided to argument < " + unistr(argument.name()) + " > gives no results")
            else:
                abspath = os.path.join(rpath, removeEscape(supplied))
                if os.path.exists(abspath):
                    lret.append(unistr(abspath))
                else:
                    raise ValueError("Path " + unistr(parameter)  + " provided to argument < " + unistr(argument.name()) + " > does not exist")
        elif ctype == typeId.String:
            lret.append(unistr(removeEscape(parameter)))
        else:
            lret.append(parameter)
        return lret


    def makeArguments(self):
        command = {}
        dbg = "\n ==== Context.makeCommand() ===="
        if len(self.badargs) > 0:
            raise KeyError("cannot generate config for module < " + self.config.origin() + " > The following arguments do not exist: " + unistr(self.badargs)) 
        for argname in self.providedArguments.keys():
            argument = self.config.argumentByName(argname)
            parameters = self.providedArguments[argname]
            if argument.inputType() == Argument.List:
                l = []
                iterator = self.paramsplit.finditer(parameters)
                itcount = 0
                previdx = 0
                for match in iterator:
                    itcount += 1
                    pos = match.span()
                    parameter = parameters[previdx:pos[0]]
                    previdx = pos[1]
                    dbg += "\n    adding parameter: < " + unistr(parameter) + " > to list"
                    try:
                        realparam = self.__makeParameter(argument, parameter)
                        l.extend(realparam)
                    except:
                        raise
                if itcount == 0 or previdx != len(parameters):
                    dbg += "\n    adding parameter: < " + unistr(parameters[previdx:]) + " > to list"
                    try:
                        parameter = parameters[previdx:]
                        realparam = self.__makeParameter(argument, parameter)
                        l.extend(realparam)
                    except:
                        raise
                command[argname] = [arg for arg in l]
            else:
                ret = unistr(parameters)
                dbg += "\n    adding parameter: < " + unistr(parameters)
                try:
                    realparam = self.__makeParameter(argument, parameters)[0]
                    command[argname] = realparam
                except:
                    raise
        if self.DEBUG and self.VERBOSITY > 0:
            dbg += "\n    resulting command arguments:"
            for argname in command.keys():
                dbg += "\n      " + argname + " --> " + unistr(command[argname])
        self.debug(dbg)
        return command


    def dump(self):
        buff = "\n ==== Context.dump() ===="
        buff += "\n    associated config: "
        if self.config != None:
            buff += self.config.origin()
            lparg = len(self.providedArguments)
            buff += "\n    provided arguments: " + unistr(lparg)
            if lparg != 0:
                for argname in self.providedArguments.keys():
                    ret = unistr(self.providedArguments[argname])
                    buff += "\n      " + argname + " --> " + ret
            lrarg = len(self.remainingArguments)
            buff += "\n    remaining arguments: " + unistr(lrarg)
            if lrarg != 0:
                for argname in self.remainingArguments:
                    buff += "\n      " + argname
            buff += "\n    threaded: " + unistr(self.threaded)
        else:
            buff += " None"
        buff += "\n    currentArgumentScope: "
        if self.currentArgument != None:
            buff += unistr(self.currentArgument.name())
        else:
            buff += "None"
        buff += "\n    currentStr: " + unistr(self.currentStr)
        buff += "\n    currentStrScope: " + unistr(self.currentStrScope)
        return buff
        

    def disambiguator(self):
        requirednodes = self.config.argumentsByFlags(typeId.Node|Argument.Required)
        optionalnodes = self.config.argumentsByFlags(typeId.Node|Argument.Optional)
        requiredpathes = self.config.argumentsByFlags(typeId.Path|Argument.Required)
        optionalpathes = self.config.argumentsByFlags(typeId.Path|Argument.Optional)
        rnodes = len(requirednodes)
        onodes = len(optionalnodes)
        rpathes = len(requiredpathes)
        opathes = len(optionalpathes)

        dbg = "\n ==== Context.disambiguator() ===="
        if rnodes == 1 and rpathes == 0:
            self.keylessarg = requirednodes[0]
        if onodes == 1 and opathes == 0 and rnodes == 0 and rpathes == 0:
            self.keylessarg = optionalnodes[0]
        if rpathes == 1 and rnodes == 0:
            self.keylessarg = requiredpathes[0]
        if opathes == 1 and onodes == 0 and rnodes == 0 and rpathes == 0:
            self.keylessarg = optionalpathes[0]
        if self.keylessarg != None:
            dbg += "\n    keylessarg exists and has been setted to < " + unistr(self.keylessarg.name()) + " >"
        else:
            dbg += "\n    keylessarg does not exist"
        self.debug(dbg)


    def setCurrent(self, token, pos):
        dbg = "\n ==== Context.setCurrent() ===="
        dbg += "\n    token: " + token
        dbg += "\n    pos: " + unistr(pos)
        dbg += "\n    currentstrscope: " + token[:pos]
        if len(token.split()) != 0:
            self.currentStr = token
            self.currentStrScope = pos
        else:
            self.currentStrScope = 0
            self.currentStr = ""
        if self.parsedArgument != None:
            dbg += "\n    parsedArgument != None"
            if self.providedArguments[self.parsedArgument.name()] in [token, None]:
                dbg += "\n    currentArgument = self.parsedArgument --> " + unistr(self.parsedArgument.name())
                self.currentArgument = self.parsedArgument
            else:
                dbg += "\n    currentArgument = None"
                self.currentArgument = None
        self.debug(dbg)



    def parameterToken(self, token):
        dbg = "\n ==== Context.parameterToken() ===="
        if self.parsedArgument == None:
            dbg += "\n    parsedArgument == None"
            if self.keylessarg != None and self.keylessarg.name() in self.remainingArguments:
                dbg += "\n    keylessarg exists and not setted yet. " + str(self.keylessarg.name()) + " --> " + token
                self.providedArguments[self.keylessarg.name()] = token
                self.remainingArguments.remove(self.keylessarg.name())
                self.parsedArgument = self.keylessarg
        elif self.providedArguments[self.parsedArgument.name()] == None:
            dbg += "\n    parsedArgument exists and not setted yet. " + unistr(self.parsedArgument.name()) + " --> " + token
            self.providedArguments[self.parsedArgument.name()] = token
            self.remainingArguments.remove(self.parsedArgument.name())
        else:
            dbg += "\n    parsedArgument already setted"
            self.parsedArgument = None
        self.debug(dbg)


    def __argumentToken(self, token):
        dbg = "\n ==== Context.__argumentToken() ===="
        argument = self.config.argumentByName(unistr(token[2:]))
        if argument != None:
            argname = argument.name()
            dbg += "\n      argument found: " + argname
            if argname in self.remainingArguments:
                if argument.inputType() == Argument.Empty:
                    self.providedArguments[argname] = True
                    self.remainingArguments.remove(argname)
                    self.parsedArgument = None
                else:
                    self.providedArguments[argname] = None
                    self.parsedArgument = argument
            else:
                dbg += "\n      argument < " + argname + " > already provided"
        else:
            self.badargs.append(token)
            dbg += "\n      argument not found"
            self.parsedArgument = None
        self.debug(dbg)


    def argumentToken(self, token):
        dbg = "\n ==== Context.argumentToken() ===="
        if self.parsedArgument != None:
            if self.parsedArgument.inputType() != Argument.Empty:
                dbg += "\n    token starts with -- and parsedArgument != None and is not a switch"
                argname = self.parsedArgument.name()
                if self.providedArguments[argname] == None:
                    if token[2:] not in self.remainingArguments:
                        dbg += "\n    currentArgument exists and not setted yet. " + unistr(argname) + " --> " + token
                        self.remainingArguments.remove(argname)
                        self.providedArguments[argname] = token
                    else:
                        self.__argumentToken(token)
                else:
                    self.__argumentToken(token)
            else:
                self.remainingArguments.remove(argname)
                self.providedArguments[argname] = None
                self.parsedArgument = None
        else:
            self.__argumentToken(token)
        self.debug(dbg)


    def configToken(self, token):
        self.config = self.confmanager.configByName(unistr(token))
        if self.config != None:
            self.disambiguator()
            argsname = self.config.argumentsName()
            for argname in argsname:
                self.remainingArguments.append(argname)


    def addToken(self, token, curpos = -1):
        dbg = "\n ==== Context.addToken() ===="
        dbg += "\n    token: " + token
        dbg += "\n    curpos: " + unistr(curpos)
        self.tokens.append(token)
        self.debug(dbg)
        if self.config == None:
            if curpos != -1:
                self.setCurrent(token, curpos)
                self.configToken(token[:curpos])
            else:
                self.configToken(token)
        else:
            if token.startswith("--"):
                if curpos != -1:
                    self.setCurrent(token, curpos)
                    self.argumentToken(token[:curpos])
                else:
                    self.argumentToken(token)
            else:
                self.parameterToken(token)
                if curpos != -1:
                    self.setCurrent(token, curpos)



class LineParser():
    def __init__(self, DEBUG = False, VERBOSITY = 0):
        self.DEBUG = DEBUG
        self.VERBOSITY = VERBOSITY
        self.ctxs = []
        self.shellKeys = [";", "&"]


    def debug(self, msg):
        if self.DEBUG and self.VERBOSITY:
            print "  ", msg


    def currentContext(self):
        if self.scopeCtx >= 0:
            return self.contexts[self.scopeCtx]
        return None


    def manageShellKeys(self, key, startidx, endidx):
        dbg = "\n ==== LineParser.manageShellKeys() ===="
        if key == "&":
            dbg += "\n    & found"
            dbg += "\n    begidx: " + unistr(self.begidx)
            dbg += "\n    endidx: " + unistr(endidx)
            self.contexts[self.ctxpos].threaded = True
            dbg += "\n    incrementing ctxpos"
            ctx = Context(self.DEBUG, self.VERBOSITY - 1)
            self.contexts.append(ctx)
            self.ctxpos += 1
            if self.begidx > endidx: #and endidx != len(self.line):
                self.scopeCtx = self.ctxpos
        elif key == "&&":
            self.contexts.append(Context(self.DEBUG, self.VERBOSITY - 1))
            self.ctxpos += 1
            if self.begidx == startidx + 1:
                self.scopeCtx = self.ctxpos
                self.contexts.append(Context(self.DEBUG, self.VERBOSITY - 1))
                self.ctxpos += 1
                dbg += "\n    key found and begidx in the middle of " + key
        self.debug(dbg)


    def makeCommands(self, line):
        line = line.rstrip()
        begidx = len(line)
        self.makeContexts(line, begidx)
        commands = []
        dbg = "\n ==== LineParser.makeCommands() ===="
        for context in self.contexts:
            if context.config != None:
                try:
                    commands.append((context.config.origin(), context.makeArguments(), context.threaded, ""))
                except KeyError, error:
                    commands.append((context.config.origin(), None, context.threaded, "module < " + context.config.origin() + " >\n" + unistr(error)))
                except ValueError, error:
		    commands.append((context.config.origin(), None, context.threaded, "module < " + context.config.origin() + " >\n" + unistr(error)))
            elif len(context.tokens) != 0:
                commands.append((None, None, None, str("module < "+ unistr(context.tokens[0]) + " > does not exist")))
        if self.DEBUG and self.VERBOSITY:
            dbg += "\n    stacked commands:"
            for command in commands:
                dbg += "\n      command name: " + unistr(command[0]) if command[0] else ""
                dbg += "\n      arguments: " + unistr(command[1]) if command[1] else ""
                dbg += "\n      to thread: " + unistr(command[2]) if command[2] else "" + "\n"
        self.debug(dbg)
        return commands


    def makeContexts(self, line, begidx = -1):
        self.begidx = begidx
        self.contexts = []
        self.scopeCtx = -1
        self.line = line
        self.ctxpos = 0
        startidx = 0
        i = 0
        token = ""

        dbg = "\n ==== LineParser.makeContext() ===="
        dbg += "\n    line: |" + line + "|"
        dbg += "\n    begidx: " + unistr(begidx)
        if len(line) != 0:
            ctx = Context(self.DEBUG, self.VERBOSITY - 1)
            self.contexts.append(ctx)
            while i < len(line):
                if line[i] == " " and (line[i-1] != "\\") and len(token.split()) != 0:
                    if self.begidx >= startidx and self.begidx <= i:
                        self.scopeCtx = self.ctxpos
                        self.contexts[self.ctxpos].addToken(token, self.begidx-startidx)
                    else:
                        self.contexts[self.ctxpos].addToken(token)
                    token = ""
                    startidx = i
                elif line[i] in self.shellKeys and (line[i-1] != "\\"):
                    if len (token.split()) != 0:
                        if self.begidx >= startidx and self.begidx <= i:
                            self.contexts[self.ctxpos].addToken(token, self.begidx-startidx)
                            self.scopeCtx = self.ctxpos
                        else:
                            self.contexts[self.ctxpos].addToken(token)
                    token = ""
                    startidx = i
                    key = ""
                    while i < len(line) and line[i] in self.shellKeys:
                        key += line[i]
                        i += 1
                    self.manageShellKeys(key, startidx, i)
                    startidx = i
                    if i < len(line):
                        token = line[i]
                    else:
                        token = ""
                    startidx = i
                elif len(token.split()) == 0:
                    startidx = i
                    token = line[i]
                else:
                    token = token + line[i]
                i += 1

            if len(token.split()) != 0:
                if self.begidx >= startidx and self.begidx <= i:
                    self.contexts[self.ctxpos].addToken(token, self.begidx-startidx)
                    self.scopeCtx = self.ctxpos
                else:
                    self.contexts[self.ctxpos].addToken(token)
            elif self.begidx == len(line):
                self.contexts[self.ctxpos].addToken(token, self.begidx-startidx)
                self.scopeCtx = self.ctxpos


            if self.DEBUG and self.VERBOSITY > 0:
                dbg += "\n    current context: "
                if self.contexts[self.scopeCtx].config:
                    dbg += unistr(self.contexts[self.scopeCtx].config.origin())
                else:
                    dbg += "None"
                dbg += "\n    scopeCtx: " + unistr(self.scopeCtx)
                dbg += "\n    ctxpox: " + unistr(self.ctxpos)
                print dbg
                for ctx in self.contexts:
                    print ctx.dump()
                print 


class Completion():
    def __init__(self, console, DEBUG = False, VERBOSITY = 0):
        self.DEBUG = DEBUG
        self.VERBOSITY = VERBOSITY
	self.console = console
        self.lp = LineParser(self.DEBUG, self.VERBOSITY - 1)
        self.confmanager = ConfigManager.Get()
        self.loader = loader()
        self.vfs = vfs()
        self.colview = ColumnView()


    def currentParameter(self):
        dbg = "\n ==== currentParameter() ===="
        dbg += "\n    current str to process: |" + self.context.currentStr + "|"
        resstr = ""
        if len(self.context.currentStr) in  [0, 1] or self.context.currentArgument.inputType() == Argument.Single:
            resstr = self.context.currentStr[:self.context.currentStrScope]
        else:
            endidx = self.context.currentStrScope
            dbg += "\n    cursor pos in current string " + unistr(endidx)
            iterator = re.finditer('(?<!\\\)\,', self.context.currentStr)
            startidx = 0
            for match in iterator:
                pos = match.span()
                dbg += "\n    " + unistr(pos)
                dbg += "\n    " + unistr(endidx)
                if pos[1] <= endidx:
                    startidx = pos[1]
            dbg += "\n    startidx: " + unistr(startidx)
            dbg += "\n    endidx: " + unistr(endidx)
            resstr = self.context.currentStr[startidx:endidx]
        dbg += "\n    resulting str: " + resstr
        self.debug(dbg)
        return resstr


    def setPathContext(self, ctype):
        rpath = ""
        supplied = ""
        children = None
        sep = os.path.sep
        path = self.currentParameter()
        rpath, supplied = splitPath(path, ctype)
        if ctype == typeId.Node:
            node = self.vfs.getnode(unistr(rpath))
            if node:
                if node.hasChildren():
                    children = node.children()
                elif node.isDir():
                    children = []
        elif os.path.exists(rpath):
            if os.path.isdir(rpath):
                try:
                    children = dircache.listdir(unistr(rpath))
                except:
                    children = []
        return (path, rpath, supplied, children)


    def completePathes(self):
        out = {"type": "path",
               "matches": [],
               "length": 1,
               "supplied": "",
               "matched": 0}

        ctype = self.context.currentArgument.type()
        itype = self.context.currentArgument.inputType()
        path, rpath, supplied, children = self.setPathContext(ctype)
        out["supplied"] = supplied
        sep = "/"
        dbg = "\n ==== completePathes() ===="
        if children == None:
            dbg += "\n    cannot complete with provided path"
            self.debug(dbg)
            return ""
        dbg += "\n    path: " + path
        dbg += "\n    relative path: " + rpath
        dbg += "\n    supplied str: " + supplied
        if ctype == typeId.Node:
            dbg += "\n    children: " + unistr([child.name() for child in children])
        else:
            dbg += "\n    children: " + unistr(children)
        if len(children) == 0:
            if rpath[-1] != sep:
                out["matches"].append(sep)
            else:
                out["matches"].append("")
            out["matched"] += 1
        else:
            glob = isGlobed(supplied)
            match = False
            for child in children:
                name = unicodeChild(child, ctype)
                if glob:
                    if fnmatch.fnmatch(addEscape(name), supplied):
                        match = True
                elif len(supplied) == 0:
                    match = True
                elif len(supplied) == 1 and supplied[0] == "\\":
                    if name[0] in SPECIAL_CHARS:
                        match = True
                elif name.startswith(removeEscape(supplied)):
                    match = True
                if match:
                    match = False
                    if (ctype == typeId.Node and child.hasChildren()) or (ctype == typeId.Path and os.path.isdir(os.path.join(rpath, name))):
                        if len(name + sep) > out["length"]:
                            out["length"] = len(name + sep)
                        out["matches"].append(name + sep)
                    else:
                        if len(name) > out["length"]:
                            out["length"] = len(name)
                        out["matches"].append(name)
                    out["matched"] += 1
        self.debug(dbg)
        return out
        

    def completePredefined(self):
        parameter = self.currentParameter()
        out = {"type": "predefined",
               "matches": [],
               "matched": 0,
               "supplied": parameter,
               "length": 1}
        predefs = self.context.currentArgument.parameters()
        for predef in predefs:
            val = unistr(predef.value())
            if parameter == "" or val.startswith(parameter):
                if len(val) > out["length"]:
                    out["length"] = len(val)
                out["matches"].append(val)
                out["matched"] += 1
        return out


    def completeModules(self):
        out = {"type": "module",
               "matches": {},
               "length": {"tag": 1, "module": 1},
               "matched": 0}
        longest_tag = 1
        longest_modname = 1

        modnames = self.confmanager.configsName()
        for modname in modnames:
            if (self.context == None) or modname.startswith(self.context.currentStr[:self.context.currentStrScope]) or self.context.currentStr[:self.context.currentStrScope] == "":
                if longest_modname < len(modname):
                    longest_modname = len(modname)
                tag = self.modules[modname].tags
                if longest_tag < len(tag):
                    longest_tag = len(tag)
                if tag not in out["matches"]:
                    out["matches"][tag] = []
                out["matches"][tag].append(modname)
                out["matched"] += 1

        out["length"]["tag"] = longest_tag
        out["length"]["module"] = longest_modname

        if out["matched"] == 1:
            out = [out["matches"][i][0] for i in out["matches"].iterkeys()]
        elif out["matched"] == 0:
            out = ""
        return out


    def completeArguments(self):
        out = {"type": "key",
               "required": [],
               "optional": [],
               "length": 1,
               "matched": 0}

        for argname in self.context.remainingArguments:
            argument = self.context.config.argumentByName(argname)
            if self.context.currentStr[:self.context.currentStrScope] in ["", "-"]:
                match = True
            elif self.context.currentStr.startswith("--") and argname.startswith(self.context.currentStr[2:self.context.currentStrScope]):
                match = True
            else:
                match = False
            if match:
                out["matched"] += 1
                if len(argname) > out["length"]:
                    out["length"] = len(argname)
                if argument.requirementType() in [Argument.Empty, Argument.Optional]:
                    out["optional"].append(argname)
                else:
                    out["required"].append(argname)
        if out["matched"] == 0:
            out = ""
        elif out["matched"] == 1:
            if len(out["required"]) == 0:
                out = out["optional"][0]
            else:
                out = out["required"][0]
            out = "--" + out
        return out


    def debug(self, msg):
        if self.DEBUG and self.VERBOSITY > 0:
            print "  ", msg


    def dispatch(self):
        matches = ""
        dbg = "\n ==== dispatch() ===="
        compfunc = None
        if self.context.currentArgument != None:
            parg = self.context.providedArguments[self.context.currentArgument.name()]
            dbg += "\n    currentArgument exists: " + unistr(self.context.currentArgument.name())
            dbg += "\n    associated parameter: " + unistr(parg)
            if parg == None or parg == self.context.currentStr:
                dbg += "\n    completing parameters for argument: " + unistr(self.context.currentArgument.name())
                if self.context.currentArgument.type() in [typeId.Node, typeId.Path]:
                    compfunc = getattr(self, "completePathes")
                else:
                    compfunc = getattr(self, "completePredefined")
            else:
                dbg += "\n    completing argument for currentStr: " + unistr(self.context.currentStr)
                compfunc = getattr(self, "completeArguments")
        else:
            dbg += "\n    no current argument to complete"
            if len(self.context.remainingArguments) > 0:
                dbg += "\n      remaining arguments exist --> total: " + unistr(len(self.context.remainingArguments))
                if self.context.keylessarg != None and self.context.keylessarg.name() in self.context.remainingArguments:
                    req = 0
                    dbg += "\n      keylessarg != None and has not been provided yet"
                    if not self.context.currentStr.startswith("--"):
                        dbg += "\n      keylessarg < " + unistr(self.context.keylessarg.name()) + " > can be used as default"
                        self.context.currentArgument = self.context.keylessarg
                        if self.context.currentArgument.type() in [typeId.Node, typeId.Path]: 
                            compfunc = getattr(self, "completePathes")
                        else:
                            compfunc = getattr(self, "completePredefined")
                    else:
                        dbg += "\n      keylessarg can not be used as default, complete with remaining arguments"
                        compfunc = getattr(self, "completeArguments")
                else:
                    dbg += "\n      either keylessarg is None or keylessarg already used"
                    compfunc = getattr(self, "completeArguments")
            else:
                dbg += "\n    nothing to complete"
        #self.debug(dbg)
        if compfunc != None:
            matches = compfunc()
            dbg += "\n    matches:" + unistr(matches)
        self.debug(dbg)
        return matches


    def complete(self, line, begidx):
        if type(line) == types.StringType:
            line = unicode(line, 'utf-8', 'replace')
        self.modules = self.loader.modules
        self.lp.makeContexts(line, begidx)
        self.context = self.lp.currentContext()
        matches = ""
        if self.context == None:
            matches = self.completeModules()
        elif self.context.config == None:
            matches = self.completeModules()
            if len(matches) == 0:
                print "\nmodule < " + self.context.currentStr + " > does not exist"
        else:
            if self.context.currentStr != self.context.config.origin():
                matches = self.dispatch()

        if type(matches) == types.ListType and len(matches) == 1:
            return matches[0]
        else:
            return matches


    def strdiff(self, str1, str2):
     i = len(str1)
     j = 0
     while j < len(str1) and j < len(str2) and str1[j] == str2[j]:
       j += 1
       i -= 1
     return len(str1) - i


    def find_longest(self, list):
     max = 0
     for str in list:
       if len(str) > max:
         max = len(str)
     return max


    def get_max_col(self, start, max):
     displaywidth = ConsoleAttributes().terminalSize() - start
     col = (displaywidth - (displaywidth / 6)) / max
     return col

    def insert_predefined_comp(self, text, matches):
     max_predef = matches["length"]
     col = self.get_max_col(13, max_predef)
     x = 0

     if matches["matched"] == 1:
         idx = self.strdiff(matches["supplied"], matches["matches"][0])
         return matches["matches"][0][idx:]

     sys.stdout.write("predefined: ")
     for item in matches["matches"]:
       if x == col:
         sys.stdout.write("\n" + " " * 13)
         x = 0
       predef_arg = item + " " * (max_predef + 2 - len(item))
       x += 1
       sys.stdout.write(predef_arg)


    def insert_module_comp(self, text, matches):     
     max_tag = matches["length"]["tag"]
     max_mod = matches["length"]["module"]
     col = self.get_max_col(max_tag + 4, max_mod)
     max_ident = 0
     prev_mod = ""
     cur_mod = text
     res = ""
     idx = 0

     if matches["matched"] == 1:
       if len(matches["matches"]["required"]) == 1:
         return self.get_str(text, matches["matches"]["required"][0])
       else:
         return self.get_str(text, matches["matches"]["optional"][0])

     for tag in matches["matches"].iterkeys():
       if len(matches["matches"][tag]) > 0:
         tag_arg = tag + " " * (max_tag + 2 - len(tag)) + ": "
         sys.stdout.write(tag_arg)
         x = 0
         for item in matches["matches"][tag]:
           if cur_mod != "":
             if prev_mod != "":
               _len = self.strdiff(prev_mod, item)
               if max_ident > _len:
                 max_ident = _len
             else:
               max_ident = len(item)
             prev_mod = item[:max_ident]
           if x == col:
             sys.stdout.write("\n" + " " * (max_tag + 4))
             x = 0
           mod_arg = item + " " * (max_mod + 2 - len(item))
           x += 1
           sys.stdout.write(mod_arg)
         idx += 1
         if idx < len(matches["matches"]):
           sys.stdout.write("\n")

     if max_ident > 0:
       return prev_mod[len(text):max_ident]


    def insert_path_comp(self, text, matches):
     supplied = matches["supplied"]
     if matches["matched"] == 1:
       if isGlobed(supplied):
           sys.stdout.write(matches["matches"][0])
       else:
           res = self.strdiff(supplied, addEscape(matches["matches"][0]))
           comp = addEscape(matches["matches"][0])[res:]
           return comp
     else:
       items = [addEscape(item) for item in matches["matches"]]
       common = posixpath.commonprefix(items)
       crow = 0
       for row in self.colview.iterRows(matches["matches"]):
           crow += 1
           if crow < self.colview.rows:
               print row
           else:
               sys.stdout.write(row)
     if supplied != "":
         if not isGlobed(supplied):
             comp = common[len(supplied):]
             return comp
     elif common != "":
         return common


    def get_str(self, text, matches):
     start = len(text)
     if start > 0:
       return matches[start:]
     else:
       return matches


    def longestCommonStr(self, str1, str2):
        minstr = (len("+" + str1) > len("+" + str2) and ("+" + str2) or ("+" + str1))[1:]
        maxstr = (len(str1) > len(str2) and str1 or str2)
        if minstr == maxstr:
            res = maxstr
        else:
            comp = map(lambda x: minstr.startswith(maxstr[:x]), xrange(1, len(maxstr) + 1))
            idx = comp.index(False)
            res = maxstr[:idx]
        return res


    def insert_key_comp(self, text, matches):
     max_key = matches["length"]
     col = self.get_max_col(10, max_key)
     idx = 0
     filled = 0
     prev_key = text
     same = 0

     common = ""
     for requirement in ["required", "optional"]:
         if len(matches[requirement]) > 0:
             filled += 1
             sys.stdout.write(requirement + ": ")
             x = 0
             count = 0
             for key in matches[requirement]:
                 if x == col:
                     sys.stdout.write("\n" + (" " * 10))
                     x = 0
                 key_arg = key + " " * (max_key + 2 - len(key))
                 if count == 0:
                     common = self.longestCommonStr(key_arg, key_arg)
                 else:
                     common = self.longestCommonStr(common, key_arg)
                 sys.stdout.write(key_arg)
                 x += 1
                 count += 1
         idx += 1
         if idx < filled:
           sys.stdout.write("\n")
     if text == "":
         return "--" + common
     elif text == "-":
         return "-" + common
     elif "--" + common == text:
         return ""
     else:
         return common[len(text)-2:]
