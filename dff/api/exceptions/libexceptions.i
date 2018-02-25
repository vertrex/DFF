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
 *  Solal J. <sja@digital-forensic.org>
 */

#include "pyrun.swg"

%module(package="dff.api.exceptions", directors="1") libexceptions


%{
#include "exceptions.hpp"
%}

%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "std_vector.i"
%include "std_except.i"
#ifndef WIN32
%include "stdint.i"
#else
%include "wstdint.i"
#endif
%include "windows.i"


/* %exception start */
/* { */
/*   try */
/*     { */
/*    //   SWIG_PYTHON_THREAD_BEGIN_ALLOW; */
/*       $action */
/*      // SWIG_PYTHON_THREAD_END_ALLOW; */
/*     } */
/*   catch (vfsError &e) */
/*     { */
/*       SWIG_exception(SWIG_IOError, e.error.c_str()); */
/*     } */
/*   catch (envError &e) */
/*     { */
/*       SWIG_PYTHON_THREAD_BEGIN_BLOCK; */
/*       PyErr_SetString(PyExc_KeyError, e.error.c_str()); */
/*       SWIG_PYTHON_THREAD_END_BLOCK; */
/*       return NULL; */
/*     } */
/*   catch (std::string e) */
/*     { */
/*       SWIG_exception(SWIG_RuntimeError, e.c_str()); */
/*     } */
/*   catch (char const* cstr) */
/*     { */
/*       SWIG_exception(SWIG_RuntimeError, cstr); */
/*     } */
/*   catch (Swig::DirectorException e) */
/*     { */
/*       SWIG_PYTHON_THREAD_BEGIN_BLOCK; */
/*       SWIG_fail; */
/*       SWIG_PYTHON_THREAD_END_BLOCK; */
/*     } */
/* } */

/* %exception notify */
/* { */
/*   try */
/*     { */
/*       $action */
/*     } */
/*   catch (vfsError &e) */
/*     { */
/*       SWIG_exception(SWIG_IOError, e.error.c_str()); */
/*     } */
/*   catch (envError &e) */
/*     { */
/*       SWIG_PYTHON_THREAD_BEGIN_BLOCK; */
/*       PyErr_SetString(PyExc_KeyError, e.error.c_str()); */
/*       SWIG_PYTHON_THREAD_END_BLOCK; */
/*       return NULL; */
/*     } */
/*   catch (std::string e) */
/*     { */
/*       SWIG_exception(SWIG_RuntimeError, e.c_str()); */
/*     } */
/*   catch (char const* cstr) */
/*     { */
/*       SWIG_exception(SWIG_RuntimeError, cstr); */
/*     } */
/*   catch (Swig::DirectorException e) */
/*     { */
/*       SWIG_PYTHON_THREAD_BEGIN_BLOCK; */
/*       SWIG_fail; */
/*       SWIG_PYTHON_THREAD_END_BLOCK; */
/*     } */
/* } */

%exception
{
  try
    {
      $action;
    }
  catch (DFF::vfsError &e)
    {
      SWIG_exception(SWIG_IOError, e.error.c_str());
    }
  catch (DFF::envError &e)
    {
      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
      PyErr_SetString(PyExc_KeyError, e.error.c_str());
      SWIG_PYTHON_THREAD_END_BLOCK;
      return NULL;
    }
  catch (std::string e)
    {
      SWIG_exception(SWIG_RuntimeError, e.c_str());
    }
  catch (char const* cstr)
    {
      SWIG_exception(SWIG_RuntimeError, cstr);
    }
  catch (Swig::DirectorException e)
    {
      SWIG_exception(SWIG_RuntimeError, "Unknown Exception");
    }
}

%feature("director:except")
{
    if ($error != NULL)
    {
      throw DFF::vfsError("Exception caught");
    }
}


%include "../include/export.hpp"
%include "../include/exceptions.hpp"
