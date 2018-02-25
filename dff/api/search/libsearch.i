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

%module(package="dff.api.search") libsearch

 /*%module(package="dff.api.vfs",docstring="searching...", directors="1") libsearch */
%feature("autodoc", 1); //1 = generate type for func proto, no work for typemap
%feature("docstring");

/* %feature("docstring") Search */
/* " */
/* This class is used to search patterns. */
/* " */

/* %feature("docstring") algorithm */
/* " */
/* This class is an interface which must be extended. It allows users to develope */
/* custom search algorithms. */
/* " */

%feature("director") SearchAlgorithm;
%feature("director") FastSearch;

#ifndef WIN32
%include "stdint.i"
#else
%include "wstdint.i"
#endif

%include "std_string.i"
%include "std_list.i"
%include "windows.i"

%typemap(in) (unsigned char* haystack, uint32_t hslen)
{
  if (!PyString_Check($input)) 
    {
      PyErr_SetString(PyExc_ValueError, "Expecting a string");
      return NULL;
    }
  $1 = (unsigned char *) PyString_AsString($input);
  $2 = (uint32_t) PyString_Size($input);
}

%apply (unsigned char* haystack, uint32_t hslen)
{
  (unsigned char* needle, uint32_t ndlen)
};

%{
#include "../include/export.hpp"
#include "../include/search.hpp"
%}

%import "../include/export.hpp"
%include "../include/search.hpp"
