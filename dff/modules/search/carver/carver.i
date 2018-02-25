/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http://www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Frederic B. <fba@digital-forensic.org>
 */

#include "pyrun.swg"

%module CARVER

%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "windows.i"

%{
#include "vfs.hpp"
#include "exceptions.hpp"
#include "carver.hpp"
#include "rootnode.hpp"
#include "tags.hpp"
#include "../../../api/search/pattern.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%typemap(in) unsigned char *
{
if (!PyString_Check($input)) 
   {
      	 PyErr_SetString(PyExc_ValueError,"Expected a string");
   	 return NULL;
   }
else
   {
	$1 = (unsigned char*)PyString_AsString($input);
   }
}

%typemap(in) unsigned char
{
if (!PyString_Check($input))
   {
      	 PyErr_SetString(PyExc_ValueError,"Expected a string");
   	 return NULL;
   }
else
   {
	if (PyString_Size($input) == 1)
	   {
		$1 = (unsigned char)PyString_AsString($input)[0];
   	   }
        else
	  {
		$1 = (unsigned char)PyString_AsString($input)[0];
	  }
   }
}

%include "carver.hpp"

namespace std
{
  %template(listDescr)     list<description*>;
};

%pythoncode
%{

__dff_module_carver_version__ = "1.0.0"

from dff.api.module.module import Module
from dff.api.types.libtypes import Argument, typeId, Variant

class CARVER(Module):
    """Search for header and footer of a selected mime-type in a node and create the corresponding file.
    You can use this modules for finding deleted data or data in slack space or in an unknown file system."""
    def __init__(self):
        Module.__init__(self, 'carver', Carver)

        self.conf.addArgument({"name": "file",
                               "description": "file used by carver",
                               "input": Argument.Required|Argument.Single|typeId.Node})
        needle = Argument("needle", Argument.Required|Argument.Single|typeId.String, "represents the needle to search in the haystack")
        needle.thisown = False

        wildcard = Argument("wildcard", Argument.Required|Argument.Single|typeId.Char, "represents wildcard character used to match anything")
        wildcard.thisown = False

        size = Argument("size", Argument.Required|Argument.Single|typeId.UInt32, "size of the needle. Needed in order to take into account \0")
        size.thisown = False

        header = Argument("header", Argument.Required|Argument.Single|typeId.Argument, "represents the header, generally corresponding to the starting magic value")
        header.addSubArgument(needle)
        header.addSubArgument(wildcard)
        header.addSubArgument(size)
        header.thisown = False

        needle = Argument("needle", Argument.Required|Argument.Single|typeId.String, "represents the needle to search in the haystack")
        needle.thisown = False

        wildcard = Argument("wildcard", Argument.Required|Argument.Single|typeId.Char, "represents wildcard character used to match anything")
        wildcard.thisown = False

        size = Argument("size", Argument.Required|Argument.Single|typeId.UInt32, "size of the needle. Needed in order to take into account \0")
        size.thisown = False

        footer = Argument("footer", Argument.Optional|Argument.Single|typeId.Argument, "represents the footer, generally corresponding to the ending magic value")
        footer.addSubArgument(needle)
        footer.addSubArgument(wildcard)
        footer.addSubArgument(size)
        footer.thisown = False

        filetype = Argument("filetype", Argument.Required|Argument.Single|typeId.String, "name of the filetype corresponding to the current pattern automaton")
        filetype.thisown = False

        window = Argument("window", Argument.Required|Argument.Single|typeId.UInt32, "maximum size to associate when no footers found or not defined")
        window.thisown = False

        aligned = Argument("aligned", Argument.Empty, "defines if headers have to be aligned to sectors")
        aligned.thisown = False

        base64 = Argument("b64", Argument.Empty, "defines if matching base64 encoded files")
        base64.thisown = False

        blksize = Argument("blksize", Argument.Optional|Argument.Single|typeId.UInt32)
        blksize.thisown = False

        pattern = Argument("pattern", Argument.Required|Argument.Single|typeId.Argument, "defines a matching context for carving files. Associate a header and a footer")
        pattern.addSubArgument(filetype)
        pattern.addSubArgument(header)
        pattern.addSubArgument(footer)
        pattern.addSubArgument(window)
        pattern.addSubArgument(aligned)
        pattern.addSubArgument(base64)
        pattern.addSubArgument(blksize)
        pattern.thisown = False

        patterns = Argument("patterns", Argument.Required|Argument.List|typeId.Argument, "defines a matching context for carving files")
        patterns.thisown = False
        patterns.addSubArgument(pattern)

        self.conf.addArgument(patterns)
        self.conf.addArgument({"name": "start-offset",
                               "input": Argument.Single|Argument.Optional|typeId.UInt64,
                               "description": "offset where to start carving"})
        self.tags = "builtins"
%}
