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
#
import re
import utils
import dircache
import os.path, os

from dff.api.manager.manager import ApiManager

class Line_to_arguments():
    def __init__(self):
        self.api = ApiManager()
        self.loader = self.api.loader()
        self.vfs = self.api.vfs()

    def generate(self, line):
        self.args, bopt = utils.split_line(line)
        cmds = []
        cmd = []
        generated_arguments = []
        #generated_args
        for a in self.args:
            if a in [";", "<", ">", "&", "|", "&&"]:
		pass
            else:
                cmd.append(a)
        cmds.append(cmd)
        for cmd in cmds:
            gen_arg = self.argument("input")
            if (self.string_to_arguments(cmd, gen_arg) != -1):
                exc = {}
                exc[cmd[0]] = gen_arg
                generated_arguments.append(exc)
            else:
                pass

        return generated_arguments



    def node_to_argument(self, key, value, gen_arg):
        res = 0

        if value == None:
            node = self.vfs.getnode(value)
        else:
	    value = value.replace("\ ", " ")
            node = self.vfs.getnode(value)
        if node != None:
            gen_arg.add_node(key, node)
        else:
            print "Value error: node <", value, "> doesn't exist"
            res = -1
        return res


    def path_to_argument(self, key, value, gen_arg):
        res = 0

        if value == None:
            abs_path = os.getcwd()
        else:
            value = value.replace("\ ", " ")
            abs_path = utils.get_absolute_path(value)
        if os.path.exists(abs_path):   
             gen_arg.add_path(key, str(abs_path))
        else:
            print "Value error: local path <", value, "> doesn't exist"
            res = -1
        return res


    def bool_to_argument(self, key, value, gen_arg):
        if value == None:
            gen_arg.add_bool(key, int(0))
        else:
            gen_arg.add_bool(key, int(1))
        return 0


    def string_to_argument(self, key, value, gen_arg):
        if value == None:
            gen_arg.add_string(key, str(""))
        else:
            gen_arg.add_string(key, str(value))
        return 0


    def int_to_argument(self, key, value, gen_arg):
        res = 0

        if value == None:
            gen_arg.add_int(key, int(-1))
        else:
            if utils.is_hex(value):
                gen_arg.add_int(key, int(value, 16))
            elif utils.is_int(value):
                gen_arg.add_int(key, int(value))
            else:
                print "Value error: value <", value, "> cannot be converted to int"
                res = -1
        return res


    def get_func_generator(self, cdl):
        func_name = cdl.type + "_to_argument"
        func = None
        if hasattr(self, func_name):
            func = getattr(self, func_name)
        else:
            print "Type error: type <", cdl.type, "> associated to argument <", cdl.name, "> doesn't exist"
        return func
        

    def several_argument(self, cdl, args, gen_arg):
        res = 0

        i = 0
        needs_no_key = utils.needs_no_key(cdl)
        priority = utils.keyPriority(cdl)
        arg_with_no_key = utils.get_arg_with_no_key(args)
        while i != (len(cdl)) and res == 0:
            func = self.get_func_generator(cdl[i])
            if func != None:
                key = "--" + cdl[i].name
                if key not in args:
                    if cdl[i].optional == False:
                        if needs_no_key != None and arg_with_no_key != -1:
                            value = args[arg_with_no_key]
                            res = func(cdl[i].name, value, gen_arg)
                            arg_with_no_key = -1
                        else:
                            print "Argument error: the argument <", cdl[i].name, "> is required by command: <", args[0], ">"
                            res = -1
                    else:
                        if arg_with_no_key != -1 and len(priority[0]) == 0 and len(priority[1]) == 1:
                            if cdl[i].name == priority[1][0].name:
                                value = args[arg_with_no_key]
                                res = func(cdl[i].name, value, gen_arg)
                            else:
                                res = func(cdl[i].name, None, gen_arg)
                        else:
                            res = func(cdl[i].name, None, gen_arg)
                else:
                    key_idx = args.index(key)
                    if cdl[i].type == "bool":
                        res = func(cdl[i].name, "", gen_arg)
                    else:
                        if (key_idx) == len(args) - 1:
                            print "Key error: the argument <", key, "> needs a value"
                            res = -1
                        else:
                            value = args[key_idx + 1]
                            res = func(cdl[i].name, value, gen_arg)
            else:
                res = -1
            
            i += 1

        return res

    def string_to_arguments(self, args, gen_arg):
	try:
          if not self.loader.is_modules(args[0])  :
            print "dff:" +  args[0] + ": command not found"
        except IndexError: 
            return -1
        conf = self.loader.get_conf(args[0]) 
        if conf != None:
            cdl = conf.descr_l
            if cdl == None:
                return gen_arg
            res = self.several_argument(cdl, args, gen_arg)
            if res == -1:
                return -1
            else:
                return gen_arg
        else:
            return -1
