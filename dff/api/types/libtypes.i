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
 *  Frederic Baguelin <fba@digital-forensic.org>
 *  Solal J. <sja@digital-forensic.org>
 */

#include "pyrun.swg"

%module(package="dff.api.types") libtypes
%feature("autodoc", 1); //1 = generate type for func proto, no work for typemap
%feature("docstring");

%{

#include <sys/stat.h>
#include <datetime.h>
#include "export.hpp"
#include "exceptions.hpp"

#include "rc.hpp"
#include "variant.hpp"
#include "constant.hpp"
#include "argument.hpp"
#include "config.hpp"
#include "confmanager.hpp"
#include "path.hpp"
#include "datetime.hpp"
  
#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif
%}

#ifndef WIN32
%include "stdint.i"
#elif _MSC_VER >= 1600
	%include "stdint.i"
#else
%include "wstdint.i"
#endif
%include "std_string.i"
%include "std_list.i"
%include "std_map.i"
%include "windows.i"
%include "std_except.i"

%import "../exceptions/libexceptions.i"

%inline %{   
 static bool std_list_Sl_DFF_RCPtr_Sl_DFF_Variant_Sg__Sg__operator_Se__Se_(std::list< Variant_p > *self,PyObject *obj);
  static bool std_map_Sl_std_string_Sc_DFF_RCPtr_Sl_DFF_Variant_Sg__Sg__operator_Se__Se_(std::map< std::string, Variant_p > *self,PyObject *obj);
  static int SWIG_AsVal_std_string(PyObject*, std::string*);
  %}

%ignore DFF::Variant::operator==(T val);
%ignore DFF::Variant::operator!=(T val);
%ignore DFF::Variant::operator>(T val);
%ignore DFF::Variant::operator>=(T val);
%ignore DFF::Variant::operator<(T val);
%ignore DFF::Variant::operator<=(T val);

/* let SWIG handle reference counting for all RCObj derived classes */
%refobject  DFF::RCObj "$this->addref();"
%unrefobject DFF::RCObj "$this->delref();"


%include "../include/rc.hpp"
%include "../include/variant.hpp"
%include "../include/argument.hpp"
%include "../include/constant.hpp"
%include "../include/export.hpp"
%include "../include/config.hpp"
%include "../include/path.hpp"
%include "../include/datetime.hpp"
%include "../include/confmanager.hpp"

%extend_smart_pointer( Variant_p );
%template(RCVariant) Variant_p;

namespace std
{
  %template(MapString)       std::map<string, string>;
  %template(ListString)      std::list<std::string>;
  %template(ArgumentList)    std::list<DFF::Argument*>;
  %template(ConfigList)      std::list<DFF::Config*>;
  %template(ConstantList)    std::list<DFF::Constant*>;
  %template(VList)	     std::list< Variant_p >;
  %template(VMap)	     std::map<std::string, Variant_p >;
  %template(MapDateTime)     std::map<std::string, DFF::DateTime*>;
  %template(MapConstant)     std::map<std::string, DFF::Constant*>;
  %template(MapArgument)     std::map<std::string, DFF::Argument*>;
  %template(MapInt)          std::map<string, unsigned int>;
};



/* %typemap(in) (std::map< std::string,Variant * >::key_type const &, Variant*) */
/* { */
/*   if ((SWIG_ConvertPtr($input, (void **) &$3, $3_descriptor, 0)) == -1)  */
/*     return NULL; */
/*   $3->addref(); */
/* } */

namespace DFF
{

%traits_swigtype(DFF::DateTime);
%fragment(SWIG_Traits_frag(DFF::DateTime));

%template(__Char) Variant::value<char>;
%template(__Int16) Variant::value<int16_t>;
%template(__UInt16) Variant::value<uint16_t>;
%template(__Int32) Variant::value<int32_t>;
%template(__UInt32) Variant::value<uint32_t>;
%template(__Int64) Variant::value<int64_t>;
%template(__UInt64) Variant::value<uint64_t>;
%template(__Bool) Variant::value<bool>;
%template(__CArray) Variant::value<char *>;
%template(__Node) Variant::value<DFF::Node*>;
%template(__Path) Variant::value<DFF::Path*>;
%template(__DateTime) Variant::value<DFF::DateTime*>;
%template(__VLink) Variant::value<DFF::VLink*>;
%template(__String) Variant::value<std::string>;
%template(__VList) Variant::value< std::list< Variant_p > >;
%template(__VMap) Variant::value< std::map<std::string, Variant_p > >;


%extend Constant
{
  void  addValues(PyObject* obj) throw (std::string)
  {
    std::string err;
    Py_ssize_t  lsize;
    Py_ssize_t  i;
    PyObject*   item;
    std::list< Variant_p > vlist;
    DFF::Variant*            v;
    uint8_t             itype;

    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    itype = self->type();
    if (PyList_Check(obj))
      {
        if ((lsize = PyList_Size(obj)) == 0)
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("Constant < " + self->name() + " > provided list of values is empty"));
        }
        else
        {
            i = 0;
    
            while ((i != lsize) && err.empty())
              {
                item = PyList_GetItem(obj, i);
                if ((v = new_DFF_Variant__SWIG_20(item, itype)) == NULL)
                  err = "Constant < " + self->name() + "  >\n provided list of values must be of type < " + DFF::typeId::Get()->typeToName(itype) + " >";
                else
                  vlist.push_back( Variant_p(v) );
                i++;
              }
        }
      }
    else
      err = "Constant < " + self->name() + " > values must be a list";
    if (err.empty())
      self->addValues(vlist);
    else
      {
        vlist.clear();
        SWIG_PYTHON_THREAD_END_BLOCK;
        throw(err);
      }
    SWIG_PYTHON_THREAD_END_BLOCK;
  }
};

%extend Argument
{
  PyObject*     validateParams(PyObject* obj, uint16_t* ptype, int32_t* min, int32_t* max) throw(std::string)
  {
    PyObject*   ptype_obj = NULL;
    PyObject*   min_obj = NULL;
    PyObject*   max_obj = NULL;
    PyObject*   predef_obj = NULL;
    Py_ssize_t  lsize;
    int         ecode = 0;

    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    if ((ptype_obj = PyDict_GetItemString(obj, "type")) == NULL)
    {
      SWIG_PYTHON_THREAD_END_BLOCK;
      throw(std::string("No field < type > defined for provided parameters"));
    }
    ecode = SWIG_AsVal_unsigned_SS_short(ptype_obj, ptype);
    if (!SWIG_IsOK(ecode))
    {
      SWIG_PYTHON_THREAD_END_BLOCK;
      throw(std::string("invalid type for field < type >"));
    }
    if ((min_obj = PyDict_GetItemString(obj, "minimum")) != NULL)
      {
        if (self->inputType() != DFF::Argument::List)
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("minimum must not be defined when argument does not need list of parameters"));
        }
        if (PyInt_Check(min_obj))
          {
            ecode = SWIG_AsVal_int(min_obj, min);
            if (!SWIG_IsOK(ecode))
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              throw(std::string("invalid type for field < minimum >"));
            }
            if (*min < 0)
            {      
              SWIG_PYTHON_THREAD_END_BLOCK;
              throw(std::string("minimum must be >= 0"));
            }
          }
        else
          {
           SWIG_PYTHON_THREAD_END_BLOCK;
           throw(std::string("invalid type for field < minimum >"));
         }
      }
    else
      *min = -1;

    if ((max_obj = PyDict_GetItemString(obj, "maximum")) != NULL)
      {
        if (self->inputType() != DFF::Argument::List)
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("maximum must not be defined when argument does not need list of parameters"));
        }
        if (PyInt_Check(max_obj))
          {
            ecode = SWIG_AsVal_int(max_obj, max);
            if (!SWIG_IsOK(ecode))
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              throw(std::string("invalid type for field < maximum >"));
            }
            if (*max <= 0)
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              throw(std::string("maximum must be >= 1"));
            }
            if (*min >= *max)
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              throw(std::string("maximum must be greater than minimum"));
            }
          }
        else
          {
            SWIG_PYTHON_THREAD_END_BLOCK;
            throw(std::string("invalid type for field < maximum >"));
          }
      }
    else
      *max = -1;

    predef_obj = PyDict_GetItemString(obj, "predefined");    
    if (predef_obj == NULL)
      {
        if (*ptype == DFF::Parameter::NotEditable)
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("not editable parameters must have < predefined > field"));
        }
      }
    else
      {
        if (!PyList_Check(predef_obj))
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("< predefined > field of parameters must be a list"));
        }
        if (*ptype == DFF::Parameter::NotEditable)
          {
            lsize = PyList_Size(predef_obj);
            if (*min > lsize)
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              throw(std::string("minimum cannot be greater than length of predefined not editable parameters"));
            }
            else if (*min == -1)
              *min = 1;
            if (*max > lsize)
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              throw(std::string("maximum cannot be greater than length of predefined not editable parameters"));
            }
            else if (*max == -1)
              *max = lsize;
          }
        else if (*min == -1)
          *min = 1;
      }
    SWIG_PYTHON_THREAD_END_BLOCK;
    return predef_obj;
  }

  void  addParameters(PyObject* obj) throw(std::string)
  {
    PyObject*   predef_obj;
    uint16_t    ptype;
    int32_t     min;
    int32_t     max;
    uint16_t    itype;
    PyObject*   item;
    Py_ssize_t  lsize;
    Py_ssize_t  i;
    DFF::Variant*    v;
    std::string err;
    std::list< Variant_p  > vlist;

    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    try
      {
       predef_obj = DFF_Argument_validateParams(self, obj, &ptype, &min, &max);
        if (predef_obj != NULL)
        {
            itype = self->type();
            lsize = PyList_Size(predef_obj);
            i = 0;
            while ((i != lsize) && err.empty())
            {
                item = PyList_GetItem(predef_obj, i);
                //Maybe change this call with _wrap_new_Variant to not depend on swig overload method generation (at the moment it s SWIG_18 but could change if new DFF::Variant ctor implemented...). Then use Swig_ConvertPtr to get Variant from the returned PyObject.
                if ((v = new_DFF_Variant__SWIG_20(item, itype)) == NULL)
                  err = "Argument < " + self->name() + "  >\n predefined parameters must be of type < " + DFF::typeId::Get()->typeToName(self->type()) + " >";
                else
                  vlist.push_back( Variant_p(v) );
                i++;
            }
          }
      }
    catch (std::string e)
      {
        err = "Argument < " + self->name() + " >\n" + e;
      }
    if (!err.empty())
      {
        vlist.erase(vlist.begin(), vlist.end());
        SWIG_PYTHON_THREAD_END_BLOCK;
        throw(std::string(err));
      }
    else
      {
        self->addParameters(vlist, ptype, min, max);
      }
     SWIG_PYTHON_THREAD_END_BLOCK;
  }
};

%extend Config
{

  bool  matchNotEditable(std::list< Variant_p > params, PyObject* obj)
  {
    std::list< Variant_p >::iterator       it;
    bool                                found;

    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    found = false;
    for (it = params.begin(); it != params.end(); it++)
      {
        if (DFF_Variant_operator_Se__Se___SWIG_1(it->get(), obj))
          {
            found = true;
            break;
          }
      }
    SWIG_PYTHON_THREAD_END_BLOCK;
    return found;
  }

  DFF::Variant*      generateSingleInput(PyObject* obj, DFF::Argument* arg) throw (std::string)
  {
    DFF::Variant*    v = NULL;
    
    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    if ((arg != NULL) && (obj != NULL))
      {
        if ((arg->parametersType() == DFF::Parameter::NotEditable) && (!DFF_Config_matchNotEditable(self, arg->parameters(), obj)))
	  {
	    SWIG_PYTHON_THREAD_END_BLOCK;
	    throw(std::string("Argument < " + arg->name() + " >\npredefined parameters are immutable and those provided do not correspond to available ones"));
	  }
        if ((v = new_DFF_Variant__SWIG_20(obj, arg->type())) == NULL)
          {
	    SWIG_PYTHON_THREAD_END_BLOCK;
	    throw(std::string("Argument < " + arg->name() + " >\nparameter is not compatible"));
	  }
	if ((v->type() == DFF::typeId::String) && (v->toString().empty()))
	  {
	    delete v;
	    SWIG_PYTHON_THREAD_END_BLOCK;
	    throw(std::string("Argument < " + arg->name() + " >\nprovided string cannot be empty"));    
	  }
      }
    else
      {
	SWIG_PYTHON_THREAD_END_BLOCK;
	throw(std::string("values provided to generateSingleInput are not valid"));
      }
    SWIG_PYTHON_THREAD_END_BLOCK;
    return v;
  }

  DFF::Variant*      generateListInput(PyObject* obj, DFF::Argument* arg) throw (std::string)
  {
    std::list< Variant_p > vlist;
    DFF::Variant*       v = NULL;
    Py_ssize_t          lsize;
    Py_ssize_t          i;
    PyObject*           item;
    std::string         err = "";
    int32_t             min;
    int32_t             max;

    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    if ((arg != NULL) && (obj != NULL))
      {
        if (PyList_Check(obj))
          {
            i = 0;
            min = arg->minimumParameters();
            max = arg->maximumParameters();
            lsize = PyList_Size(obj);
            if (lsize == 0)
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              throw(std::string("Argument < " + arg->name() + " >\nlist of parameters is empty"));
            }
            if ((min != -1) && (lsize < min))
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              throw(std::string("Argument < " + arg->name() + " >\nnot enough parameters provided"));
            }
            if ((max != -1) && (lsize > max))
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              throw (std::string("Argument < " + arg->name() + " >\ntoo many parameters provided"));
            }
            try
              {
                while ((i != lsize) && err.empty())
                  {
                    item = PyList_GetItem(obj, i);
                    v = DFF_Config_generateSingleInput(self, item, arg);
                    vlist.push_back( Variant_p(v) );
                    i++;
                  }
             }
             catch(std::string e)
             {
                err = e;
             }
          }
        else
          {
            try
              {
                v = DFF_Config_generateSingleInput(self, obj, arg);
                vlist.push_back( Variant_p(v) );
              }
            catch(std::string e)
              {
                err = e;
              }
          }
      }
    else
      err = "values provided to generateListInput are not valid";
    if (!err.empty())
      {
        vlist.clear();
        SWIG_PYTHON_THREAD_END_BLOCK;
        throw(err);
      }
    v = new DFF::Variant(vlist);
    SWIG_PYTHON_THREAD_END_BLOCK;
    return v;
  }
    
//XXX
std::map<std::string, Variant_p >       generate(PyObject* obj) throw (std::string)
    {
      std::map<std::string, Variant_p >   res;
      std::list<DFF::Argument*>              args;
      std::list<DFF::Argument*>::iterator    argit;
     
      PyObject*                         itemval;
      std::string                       argname;
      uint16_t                          itype;
      uint16_t                          rtype;
      int                               ecode;
      std::string                       err;
    
      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
      ecode = PyDict_Check(obj);
      if (ecode)
        {
          args = self->arguments();
          argit = args.begin();
          while ((argit != args.end()) && err.empty())
            {
              argname = (*argit)->name();
              itype = (*argit)->inputType();
              rtype = (*argit)->requirementType();
              itemval = PyDict_GetItemString(obj, argname.c_str());
              if (itemval == NULL)
                {
                  if (rtype == DFF::Argument::Required)
                    err = "Argument < " + argname + " >\n this argument is required";
                }
              else
                {
                  //std::cout << "current argument: " <<  argname << " argument type " << (*argit)->type() << " -- provided parameter type " << obj->ob_type->tp_name << std::endl;
                  try
                    {
                      DFF::Variant * v = NULL;
                      if (itype == DFF::Argument::Empty)
                        v = new_DFF_Variant__SWIG_20(itemval, DFF::typeId::Bool);
                      else if (itype == DFF::Argument::Single)
                        v = DFF_Config_generateSingleInput(self, itemval, *argit);
                      else if (itype == DFF::Argument::List)
                        v = DFF_Config_generateListInput(self, itemval, *argit);
                      if (v != NULL)
                        res[argname] = Variant_p(v);
                      else
                        err = "Argument < " + argname + " >\n" + "parameter provided is not valid (wrong type)";
                    }
                  catch (std::string e)
                    {
                        err = "Argument < " + argname + " >\n" + "parameter provided is not valid\ndetails:\n" + e;
                    }
                }
              argit++;
            }
        }
      else
        err = "generating configuration failed because provided value is not of type dict";
      if (!err.empty())
        {
          res.clear();
          throw(err);
        }
      SWIG_PYTHON_THREAD_END_BLOCK;
      return res;
    }

  void  addConstant(PyObject* obj) throw(std::string)
  {
    uint32_t    pydictsize;
    DFF::Constant*   constant;
    PyObject*   name_obj = 0;
    PyObject*   type_obj = 0;
    PyObject*   values_obj = 0;
    PyObject*   descr_obj = 0;
    int         ecode = 0;
    std::string name;
    uint8_t     type;
    std::string description;

    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    if (PyDict_Check(obj))
      {
        pydictsize = PyDict_Size(obj);
        if ((name_obj = PyDict_GetItemString(obj, "name")) == NULL)
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("No field < name > defined for current constant"));
        }
        ecode = SWIG_AsVal_std_string(name_obj, &name);
        if (!SWIG_IsOK(ecode))
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("invalid type for field < name >"));
        }
        if (self->constantByName(name) != NULL)
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("Constant < " + name + " > already added"));
        }
        if ((type_obj = PyDict_GetItemString(obj, "type")) == NULL)
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("Constant < " + name + ">\nfield < type > must be defined"));
        }
        ecode = SWIG_AsVal_unsigned_SS_char(type_obj, &type);
        if (!SWIG_IsOK(ecode))
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("Constant < " + name + ">\ninvalid type for field < type >"));
        }
        if ((descr_obj = PyDict_GetItemString(obj, "description")) == NULL)
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("Constant < " + name + " >\nfield < description > must be defined"));
        }
        ecode = SWIG_AsVal_std_string(descr_obj, &description);
        if (!SWIG_IsOK(ecode))
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("Constant < " + name + " >\ninvalid type for field < description >"));
        }
        if ((values_obj = PyDict_GetItemString(obj, "values")) == NULL)
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("Constant < " + name + ">\nfield < values > must be defined"));
        }
        try
          {
            constant = new DFF::Constant(name, type, description);
            DFF_Constant_addValues__SWIG_1(constant, values_obj);
            self->addConstant(constant);
          }
        catch (std::string e)
          {
            delete constant;
            SWIG_PYTHON_THREAD_END_BLOCK;
            throw("Constant < " + name + " >\n error while processing argument\ndetails:\n" + e);
          }
      }
    SWIG_PYTHON_THREAD_END_BLOCK;
  }


  void  addArgument(PyObject* obj) throw(std::string)
  {
    uint32_t    pydictsize;
    DFF::Argument*   arg;
    PyObject*   name_obj = 0;
    PyObject*   input_obj = 0;
    PyObject*   param_obj = 0;
    PyObject*   descr_obj = 0;

    uint16_t    input;
    std::string name;
    std::string description;
    std::list<std::string>      names;

    int         ecode = 0;

    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    if (PyDict_Check(obj))
    {
        pydictsize = PyDict_Size(obj);
        if ((name_obj = PyDict_GetItemString(obj, "name")) == NULL)
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("No field < name > defined for current argument"));
        }
        ecode = SWIG_AsVal_std_string(name_obj, &name);
        if (!SWIG_IsOK(ecode))
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("invalid type for field < name >"));
        }
        if (self->argumentByName(name) != NULL)
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("Argument < " + name + " > already added"));
        }
        if ((input_obj = PyDict_GetItemString(obj, "input")) == NULL)
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("Argument < " + name + ">\nfield < input > must be defined"));
        }
        ecode = SWIG_AsVal_unsigned_SS_short(input_obj, &input);
        if (!SWIG_IsOK(ecode))
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("Argument < " + name + ">\ninvalid type for field < input >"));
        }
        if ((descr_obj = PyDict_GetItemString(obj, "description")) == NULL)
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("Argument < " + name + " >\nfield < description > must be defined"));
        }
        ecode = SWIG_AsVal_std_string(descr_obj, &description);
        if (!SWIG_IsOK(ecode))
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("Argument < " + name + " >\ninvalid type for field < description >"));
        }
        param_obj = PyDict_GetItemString(obj, "parameters");
        
        if (input == DFF::Argument::Empty)
          {
            if (param_obj != NULL)
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              throw(std::string("Argument < " + name + ">\nfield < predefined > forbidden"));
            }
            else
              {
                arg = new DFF::Argument(name, input, description);
                self->addArgument(arg);
              }
          }
        else if ((
                  ((input & 0x0300) == DFF::Argument::List) || ((input & 0x0300) == DFF::Argument::Single))
                 && (((input & 0x0c00) == DFF::Argument::Optional) || ((input & 0x0c00) == DFF::Argument::Required)))
          {
            arg = new DFF::Argument(name, input, description);
            if (param_obj != NULL)
              {
                if (!PyDict_Check(param_obj))
                  {
                    delete arg;
                    SWIG_PYTHON_THREAD_END_BLOCK;
                    throw(std::string("Argument < " + name + ">\nparameters field is not of type dict"));
                  }
                else
                  {
                    try
                      {
                        DFF_Argument_addParameters__SWIG_3(arg, param_obj);
                        self->addArgument(arg);
                      }
                    catch (std::string e)
                      {
                        delete arg;
                        SWIG_PYTHON_THREAD_END_BLOCK;
                        throw("Argument < " + name + " >\n error while processing argument\ndetails:\n" + e);
                      }
                  }
              }
            else
              self->addArgument(arg);
          }
        else
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("Argument < " + name + ">\nflags provided to field < input > are not valid"));
        }
    }
    SWIG_PYTHON_THREAD_END_BLOCK;
  }
};

%extend Variant
{

/*   Variant(PyObject* obj) throw (std::string) */
/*     {  */
/*       Variant*  v = NULL; */
/*       std::string      err = ""; */

/*       if (obj == NULL) */
/*         throw(std::string("Provided PyObject is NULL")); */

/*       if (obj == Py_None) */
/*         throw(std::string("Provided PyObject cannot be None")); */

/*       SWIG_PYTHON_THREAD_BEGIN_BLOCK; */
/*       if (PyLong_Check(obj) || PyInt_Check(obj)) */
/*       {         */
/* 	int16_t		s; */
/* 	uint16_t	us; */
/* 	int32_t		i; */
/* 	uint32_t	ui; */
/* 	int64_t		ll; */
/* 	uint64_t	ull; */

/* 	if (SWIG_IsOK(SWIG_AsVal_short(obj, &s))) */
/* 	  v = new DFF::Variant(s);	 */
/* 	else if (SWIG_IsOK(SWIG_AsVal_unsigned_SS_short(obj, &us))) */
/* 	  v = new DFF::Variant(us); */
/* 	else if (SWIG_IsOK(SWIG_AsVal_int(obj, &i))) */
/* 	  v = new DFF::Variant(i); */
/* 	else if (SWIG_IsOK(SWIG_AsVal_unsigned_SS_int(obj, &ui))) */
/* 	  v = new DFF::Variant(ui); */
/* #ifdef SWIGWORDSIZE64 */
/* 	else if (SWIG_IsOK(SWIG_AsVal_long(obj, &ll))) */
/* #else */
/* 	else if (SWIG_IsOK(SWIG_AsVal_long_SS_long(obj, &ll))) */
/* #endif */
/* 	  v = new DFF::Variant(ll); */
/* #ifdef SWIGWORDSIZE64 */
/* 	else if (SWIG_IsOK(SWIG_AsVal_unsigned_SS_long(obj, &ull))) */
/* #else */
/* 	else if (SWIG_IsOK(SWIG_AsVal_unsigned_SS_long_SS_long(obj, &ull))) */
/* #endif */
/* 	  v = new DFF::Variant(ull); */
/* 	else */
/* 	  err = "error while converting integer"; */
/*       } */
/*       else if (PyBool_Check(obj)) */
/*         { */
/*           bool  b; */
/*           if (SWIG_IsOK(SWIG_AsVal_bool(obj, &b))) */
/* 	    v = new DFF::Variant(b); */
/* 	  else */
/* 	    err = "Error while converting boolean"; */
/*         } */
/*       else if (PyString_Check(obj)) */
/*         { */
/*           std::string   str; */

/*           if (SWIG_IsOK(SWIG_AsVal_std_string(obj, &str))) */
/* 	    v = new DFF::Variant(str); */
/* 	  else */
/* 	    err = "Error while converting string"; */
/*         } */
/*       else if (strncmp("Node", obj->ob_type->tp_name, 4) == 0) */
/*         { */
/* 	  void*	vptr; */
/* 	  Node*	node; */
	  
/* 	  if (SWIG_IsOK(SWIG_ConvertPtr(obj, &vptr, SWIGTYPE_p_Node, 0))) */
/* 	    { */
/* 	      node = reinterpret_cast< Node * >(vptr); */
/* 	      v = new DFF::Variant(node); */
/* 	    } */
/* 	  else */
/* 	    err = "Error while converting Node"; */
/*         } */
/*       else if (strncmp("VLink", obj->ob_type->tp_name, 5) == 0) */
/*         { */
/* 	  void*	vptr; */
/* 	  VLink*	node;	   */
/* 	  if (SWIG_IsOK(SWIG_ConvertPtr(obj, &vptr, SWIGTYPE_p_VLink, 0))) */
/* 	    { */
/* 	      node = reinterpret_cast< VLink * >(vptr); */
/* 	      v = new DFF::Variant((Node*)node); */
/* 	    } */
/* 	  else */
/* 	    err = "Error while converting VLink"; */
/*         } */
/*       else if (strncmp("Path", obj->ob_type->tp_name, 4) == 0) */
/*         { */
/* 	  void*     vptr; */
/* 	  Path*     path; */
	  
/* 	  if (SWIG_IsOK(SWIG_ConvertPtr(obj, &vptr, SWIGTYPE_p_Path, 0))) */
/* 	    { */
/* 	      path = reinterpret_cast< Path * >(vptr); */
/* 	      v = new DFF::Variant(path); */
/* 	    } */
/* 	  else */
/* 	    err = "Error while converting Path"; */
/*         } */
/*       else if (PyList_Check(obj)) */
/*         { */
/*           Py_ssize_t            size = PyList_Size(obj); */
/*           Py_ssize_t            it; */
/*           PyObject*             item = NULL; */
/*           std::list<Variant_p > vlist; */
/*           Variant*              vitem = NULL; */

/*           for (it = 0; it != size; it++) */
/*             { */
/*               item = PyList_GetItem(obj, it); */
/* 	      try */
/* 		{ */
/* 		  vitem = new_Variant__SWIG_19(item); */
/* 		  vlist.push_back(Variant_p(vitem)); */
/* 		} */
/* 	      catch (std::string e) */
/* 		{ */
/* 		  err = e; */
/* 		  break; */
/* 		} */
/* 	    } */
/*           if (!err.empty()) */
/*             vlist.erase(vlist.begin(), vlist.end()); */
/*           else */
/* 	    v = new DFF::Variant(vlist); */
/*         } */
/*       else if (PyDict_Check(obj)) */
/*         { */
/*           std::map<std::string, Variant_p >  vmap; */
/*           Variant*              vitem = NULL; */
/* 	  std::string		strkey; */
/* 	  PyObject *key, *value; */
/* 	  Py_ssize_t pos = 0; */

/* 	  while (PyDict_Next(obj, &pos, &key, &value))  */
/* 	    { */
/* 	      if (!PyString_Check(key)) */
/* 		{ */
/* 		  err = "Keys must be of type string"; */
/* 		  break; */
/* 		} */
/* 	      else if (SWIG_IsOK(SWIG_AsVal_std_string(key, &strkey))) */
/* 		{ */
/* 		  try */
/* 		    { */
/* 		      vitem = new_Variant__SWIG_19(value);		  */
/* 		      vmap[strkey] = Variant_p(vitem); */
/* 		    } */
/* 		  catch (std::string e) */
/* 		    { */
/* 		      err = e; */
/* 		      break; */
/* 		    } */
/* 		} */
/* 	      else */
/* 		{ */
/* 		  err = "Error while converting string"; */
/* 		  break; */
/* 		} */
/* 	    } */
/* 	  if (!err.empty()) */
/* 	    vmap.clear(); */
/* 	  else */
/* 	    v = new DFF::Variant(vmap); */
/*         } */
/*       SWIG_PYTHON_THREAD_END_BLOCK; */
/*       if (!err.empty()) */
/* 	throw(std::string(err)); */
/*       return v; */
/*     } */

    Variant(PyObject* obj, uint8_t type) throw(std::string)
    {
      DFF::Variant*  v = NULL;
      bool      err = true;
      int       ecode;

      if (obj == NULL)
        throw(std::string("Provided PyObject is NULL"));

      if (obj == Py_None)
        throw(std::string("Provided PyObject cannot be None"));

      //std::cout << "Variant::Variant(PyObject*, uint8_t) -- PyObject type " << obj->ob_type->tp_name << std::endl;

      SWIG_PYTHON_THREAD_BEGIN_BLOCK;
      if (PyLong_Check(obj) || PyInt_Check(obj))
      {
          if (type == uint8_t(DFF::typeId::Bool))
          {
              bool      b;
              int ecode = SWIG_AsVal_bool(obj, &b);
              if (SWIG_IsOK(ecode))
                {
                  v = new DFF::Variant(b);
                  err = false;
                }
            }
          else if (type == uint8_t(DFF::typeId::Int16))
            {
              int16_t   s;
              ecode = SWIG_AsVal_short(obj, &s);
              if (SWIG_IsOK(ecode))
                {
                  v = new DFF::Variant(s);
                  err = false;
                }
            }
          else if (type == uint8_t(DFF::typeId::UInt16))
            {
              uint16_t  us;
              int ecode = SWIG_AsVal_unsigned_SS_short(obj, &us);
              if (SWIG_IsOK(ecode))
                {
                  v = new DFF::Variant(us);
                  err = false;
                }
            }
          else if (type == uint8_t(DFF::typeId::Int32))
            {
              int32_t   i;
              int ecode = SWIG_AsVal_int(obj, &i);
              if (SWIG_IsOK(ecode))
                {
                  v = new DFF::Variant(i);
                  err = false;
                }
            }
          else if (type == uint8_t(DFF::typeId::UInt32))
            {
              uint32_t ui;
              int ecode = SWIG_AsVal_unsigned_SS_int(obj, &ui);
              if (SWIG_IsOK(ecode))
                {
                  v = new DFF::Variant(ui);
                  err = false;
                }
            }
          else if (type == uint8_t(DFF::typeId::Int64))
            {
              int64_t   ll;
#ifdef SWIGWORDSIZE64
              int ecode = SWIG_AsVal_long(obj, &ll);
#else
              int ecode = SWIG_AsVal_long_SS_long(obj, &ll);
#endif
              if (SWIG_IsOK(ecode))
                {
                  v = new DFF::Variant(ll);
                  err = false;
                }
            }
          else if (type == uint8_t(DFF::typeId::UInt64))
            {
              uint64_t  ull;
#ifdef SWIGWORDSIZE64
              int ecode = SWIG_AsVal_unsigned_SS_long(obj, &ull);
#else
              int ecode = SWIG_AsVal_unsigned_SS_long_SS_long(obj, &ull);
#endif
              if (SWIG_IsOK(ecode))
                {
                  v = new DFF::Variant(ull);
                  err = false;
                }
            }
        }
      else if (PyBool_Check(obj))
        {
          bool  b;
          int ecode = SWIG_AsVal_bool(obj, &b);
          if (SWIG_IsOK(ecode))
            {
              v = new DFF::Variant(b);
              err = false;
            }
        }
      else if (PyString_Check(obj))
        {
          std::string   str;

          ecode = SWIG_AsVal_std_string(obj, &str);
          if (SWIG_IsOK(ecode))
            {
              if (type == DFF::typeId::String)
                {
                  v = new DFF::Variant(str);
                  err = false;
                }
              else if (type == DFF::typeId::CArray)
                {
                  v = new DFF::Variant((char*)str.c_str());
                  err = false;
                }
              else if (type == DFF::typeId::Char)
                {
                  char  c;
                  if ((str.size() == 1) || (str.size() == 0))
                    {
                      c = *(str.c_str());
                      v = new DFF::Variant(c);
                      err = false;
                    }
                }
              else if (type == DFF::typeId::Path)
                {
                  DFF::Path*           p;
                  p = new DFF::Path(str);
                  v = new DFF::Variant(p);
                  err = false;
                }
              else if (type == DFF::typeId::Int16)
                {
                  int16_t               s;
                  std::istringstream    conv(str);
                  if (conv >> s)
                    {
                      v = new DFF::Variant(s);
                      err = false;
                    }
                }
              else if (type == DFF::typeId::UInt16)
                {
                  uint16_t              us;
                  std::istringstream    conv(str);
                  if (conv >> us)
                    {
                      v = new DFF::Variant(us);
                      err = false;
                    }
                }
              else if (type == DFF::typeId::Int32)
                {
                  int32_t               i;
                  std::istringstream    conv(str);
                  if (conv >> i)
                    {
                      v = new DFF::Variant(i);
                      err = false;
                    }
                }
              else if (type == DFF::typeId::UInt32)
                {
                  int32_t               ui;
                  std::istringstream    conv(str);
                  if (conv >> ui)
                    {
                      v = new DFF::Variant(ui);
                      err = false;
                    }
                }
              else if (type == DFF::typeId::Int64)
                {
                  int64_t               ll;
                  std::istringstream    conv(str);
                  if (conv >> ll)
                    {
                v = new DFF::Variant(ll);
                      err = false;
                    }
                }
              else if (type == DFF::typeId::UInt64)
                {
                  uint64_t              ull;
                  std::istringstream    conv(str);
                  if (conv >> ull)
                    {
                      v = new DFF::Variant(ull);
                      err = false;
                    }
                }
            }
        }
      else if (strncmp("Node", obj->ob_type->tp_name, 4) == 0)
        {
          if (type == DFF::typeId::Node)
	    {
	      void*	vptr;
	      DFF::Node*	node;
	      int res = SWIG_ConvertPtr(obj, &vptr, SWIGTYPE_p_DFF__Node, 0);
	      if (SWIG_IsOK(res))
		{
		  node = reinterpret_cast< DFF::Node * >(vptr);
		  v = new DFF::Variant(node);
		  err = false;
		}
            }
        }
      else if (strncmp("VLink", obj->ob_type->tp_name, 5) == 0)
        {
          if (type == DFF::typeId::Node)
	    {
	      void*	vptr;
	      DFF::VLink*	node;
	      int res = SWIG_ConvertPtr(obj, &vptr, SWIGTYPE_p_DFF__VLink, 0);
	      if (SWIG_IsOK(res))
		{
		  node = reinterpret_cast< DFF::VLink * >(vptr);
		  v = new DFF::Variant(node);
		  err = false;
		}
            }
        }
      else if (strncmp("Path", obj->ob_type->tp_name, 4) == 0)
        {
          if (type == DFF::typeId::Path)
            {
              void*     vptr;
              DFF::Path*     path;
              int res = SWIG_ConvertPtr(obj, &vptr, SWIGTYPE_p_DFF__Path, 0);
              if (SWIG_IsOK(res))
                {
                  path = reinterpret_cast< DFF::Path * >(vptr);
                  v = new DFF::Variant(path);
                  err = false;
                }
            }
        }
      else if (PyList_Check(obj) && type == DFF::typeId::List)
        {
          Py_ssize_t            size = PyList_Size(obj);
          Py_ssize_t            it;
          PyObject*             item = NULL;
          std::list< Variant_p >  vlist;
          DFF::Variant*              vitem = NULL;
          bool                  lbreak = false;

          for (it = 0; it != size; it++)
            {
              item = PyList_GetItem(obj, it);
              if ((vitem = new_DFF_Variant__SWIG_20(item, type)) == NULL)
              {
                 lbreak = true;
                 break;
              }
              vlist.push_back(Variant_p(vitem));
            }
          if (lbreak)
            vlist.erase(vlist.begin(), vlist.end());
          else
            {
              v = new DFF::Variant(vlist);
              err = false;
            }
        }
      /* else if (PyDict_Check(obj) && type == DFF::typeId::Map) */
      /*   { */
      /*     PyObject*             item = NULL; */
      /*     std::map<std::string, Variant *>  vmap; */
      /*     Variant*              vitem = NULL; */
      /*     bool                  lbreak = false; */
      /* 	  char*			strkey; */

      /* 	  PyObject *key, *value; */
      /* 	  Py_ssize_t pos = 0; */

      /* 	  while (PyDict_Next(obj, &pos, &key, &value))  */
      /* 	    { */
      /* 	      if (!PyString_Check(key)) */
      /* 		err  */
      /* 	      strkey */
      /* 	      Py_DECREF(o); */
      /* 	    } */
      /*   } */
      if (err)
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          throw(std::string("Cannot create Variant, Provided PyObject and requested type are not compatible"));
        }
      SWIG_PYTHON_THREAD_END_BLOCK;
      return v;
    }

  bool  operator==(PyObject* obj)
  {
    DFF::Variant*    v = NULL;
    uint8_t     type;

    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    type = self->type();

    if (obj == NULL)
      {
        //printf("    !!! obj is NULL !!!\n");
        SWIG_PYTHON_THREAD_END_BLOCK;
        return false;
      }    
    if (obj->ob_type == NULL)
      {
        //printf("    !!! obj->ob_type is NULL !!!\n");
        SWIG_PYTHON_THREAD_END_BLOCK;
        return false;
      }
    if (obj->ob_type->tp_name == NULL)
      {
        //printf("    !!! obj->ob_type->tp_name is NULL !!!\n");
        SWIG_PYTHON_THREAD_END_BLOCK;
        return false;
      } 
    if (strncmp("Variant", obj->ob_type->tp_name, 7) == 0)
      {
        //printf("Variant::operator==(PyObject* obj) ---> obj == Variant\n");
        void* argp1 = 0;
        DFF::Variant *arg1 = (DFF::Variant *) 0 ;
        int res1 = SWIG_ConvertPtr(obj, &argp1, SWIGTYPE_p_DFF__Variant, 0 | 0);
        if (SWIG_IsOK(res1))
        {
            arg1 = reinterpret_cast< DFF::Variant * >(argp1);
            SWIG_PYTHON_THREAD_END_BLOCK;
            return self->operator==(arg1);
        }
        else
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          return false;
        }
      }
    else if (((strncmp("VList", obj->ob_type->tp_name, 5) == 0) || PyList_Check(obj)) && (type == DFF::typeId::List))
      {
        //printf("Variant::operator==(PyObject* obj) ---> obj == VList\n");
        std::list< Variant_p > selflist;
        selflist = self->value<std::list< Variant_p > >();
        SWIG_PYTHON_THREAD_END_BLOCK;
	return std_list_Sl_DFF_RCPtr_Sl_DFF_Variant_Sg__Sg__operator_Se__Se_(&selflist, obj);
      }
    else if (((strncmp("VMap", obj->ob_type->tp_name, 4) == 0) || PyDict_Check(obj)) && (type == DFF::typeId::Map))
      {
        //printf("Variant::operator==(PyObject* obj) ---> obj == VMap\n");
        std::map<std::string, Variant_p > selfmap;
        selfmap = self->value<std::map<std::string, Variant_p > >();
        SWIG_PYTHON_THREAD_END_BLOCK;
	return std_map_Sl_std_string_Sc_DFF_RCPtr_Sl_DFF_Variant_Sg__Sg__operator_Se__Se_(&selfmap, obj);
      }
    else if (PyLong_Check(obj) || PyInt_Check(obj))
      {
        //printf("Variant::operator==(PyObject* obj) ---> obj == PyLong_Check || PyInt_Check provided\n");
        if (type == uint8_t(DFF::typeId::Int16))
          {
            int16_t     v;
            int ecode = SWIG_AsVal_short(obj, &v);
            if (SWIG_IsOK(ecode))
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              return self->operator==<int16_t>(v);
            }
            else
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              return false;
            }
          }
        else if (type == uint8_t(DFF::typeId::UInt16))
          {
            uint16_t    v;
            int ecode = SWIG_AsVal_unsigned_SS_short(obj, &v);
            if (SWIG_IsOK(ecode))
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              return self->operator==<uint16_t>(v); 
            }
            else
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              return false;
            }
          }
        else if (type == uint8_t(DFF::typeId::Int32))
          {
            int32_t     v;
            int ecode = SWIG_AsVal_int(obj, &v);
            if (SWIG_IsOK(ecode))
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              return self->operator==<int32_t>(v); 
            }
            else
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              return false;
            }
          }
        else if (type == uint8_t(DFF::typeId::UInt32))
          {
            uint32_t	v;
            int ecode = SWIG_AsVal_unsigned_SS_int(obj, &v);
            if (SWIG_IsOK(ecode))
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              return self->operator==<uint32_t>(v);
            }
            else
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              return false;
            }
          }
        else if (type == uint8_t(DFF::typeId::Int64))
          {
            int64_t	v;
#ifdef SWIGWORDSIZE64
            int ecode = SWIG_AsVal_long(obj, &v);
#else
            int ecode = SWIG_AsVal_long_SS_long(obj, &v);
#endif
            if (SWIG_IsOK(ecode))
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              return self->operator==<int64_t>(v);
            } 
            else
            {    
              SWIG_PYTHON_THREAD_END_BLOCK;
              return false;
            }
          }
        else if (type == uint8_t(DFF::typeId::UInt64))
          {
            uint64_t    v;
#ifdef SWIGWORDSIZE64
            int ecode = SWIG_AsVal_unsigned_SS_long(obj, &v);
#else
            int ecode = SWIG_AsVal_unsigned_SS_long_SS_long(obj, &v);
#endif
            if (SWIG_IsOK(ecode))
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              return self->operator==<uint64_t>(v);
            }
            else
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              return false;
            }
          }
        else
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          return false;
        }
      }
    else if (PyBool_Check(obj) && (type == DFF::typeId::Bool))
      {
          bool  b;
          int ecode = SWIG_AsVal_bool(obj, &b);
          if (SWIG_IsOK(ecode))
          {
            SWIG_PYTHON_THREAD_END_BLOCK;
            return self->operator==<bool>(v);
          }
          else
          {
            SWIG_PYTHON_THREAD_END_BLOCK;
            return false;
          }
      }
    else if ((PyString_Check(obj)) && (type == DFF::typeId::String))
      {
        char*           cstr;
        
        if ((cstr = PyString_AsString(obj)) != NULL)
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          return self->operator==<std::string>(cstr);
        }
        else
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          return false;
        }
      }
    else
    {    
      SWIG_PYTHON_THREAD_END_BLOCK;
      return false;
    }
  }


  bool  operator!=(PyObject* obj)
  {
    return (!DFF_Variant_operator_Se__Se___SWIG_1(self, obj));
  }

  bool  operator>(PyObject* obj)
  {
    uint8_t     type;

    type = self->type();

    if (obj == NULL)
      {
        //printf("    !!! obj is NULL !!!\n");
        return false;
      }    
    if (obj->ob_type == NULL)
      {
        //printf("    !!! obj->ob_type is NULL !!!\n");
        return false;
      }
    if (obj->ob_type->tp_name == NULL)
      {
        //printf("    !!! obj->ob_type->tp_name is NULL !!!\n");
        return false;
      }
    if (strncmp("Variant", obj->ob_type->tp_name, 7) == 0)
      {
        //printf("Variant::operator>(PyObject* obj) ---> obj == Variant\n");
        void* argp1 = 0;
        DFF::Variant *arg1 = (DFF::Variant *) 0 ;
        int res1 = SWIG_ConvertPtr(obj, &argp1, SWIGTYPE_p_DFF__Variant, 0 | 0);
        if (SWIG_IsOK(res1))
          {
            arg1 = reinterpret_cast< DFF::Variant * >(argp1);
            return self->operator>(arg1);
          }
        else
          return false;
      }
    else if (PyLong_Check(obj) || PyInt_Check(obj))
      {
        //printf("Variant::operator>(PyObject* obj) ---> obj == PyLong_Check || PyInt_Check provided\n");
        if (type == uint8_t(DFF::typeId::Int16))
          {
            int16_t     v;
            int ecode = SWIG_AsVal_short(obj, &v);
            if (SWIG_IsOK(ecode))
              return self->operator><int16_t>(v);
            else
              return false;
          }
        else if (type == uint8_t(DFF::typeId::UInt16))
          {
            uint16_t    v;
            int ecode = SWIG_AsVal_unsigned_SS_short(obj, &v);
            if (SWIG_IsOK(ecode))
              return self->operator><uint16_t>(v); 
            else
              return false;
          }
        else if (type == uint8_t(DFF::typeId::Int32))
          {
            int32_t     v;
            int ecode = SWIG_AsVal_int(obj, &v);
            if (SWIG_IsOK(ecode))
              return self->operator><int32_t>(v); 
            else
              return false;
          }
        else if (type == uint8_t(DFF::typeId::UInt32))
          {
            uint32_t    v;
            int ecode = SWIG_AsVal_unsigned_SS_int(obj, &v);
            if (SWIG_IsOK(ecode))
              return self->operator><uint32_t>(v);
            else
              return false;
          }
        else if (type == uint8_t(DFF::typeId::Int64))
          {
            int64_t     v;
#ifdef SWIGWORDSIZE64
            int ecode = SWIG_AsVal_long(obj, &v);
#else
            int ecode = SWIG_AsVal_long_SS_long(obj, &v);
#endif
            if (SWIG_IsOK(ecode))
              return self->operator><int64_t>(v);
            else
              return false;
          }
        else if (type == uint8_t(DFF::typeId::UInt64))
          {
            uint64_t    v;
#ifdef SWIGWORDSIZE64
            int ecode = SWIG_AsVal_unsigned_SS_long(obj, &v);
#else
            int ecode = SWIG_AsVal_unsigned_SS_long_SS_long(obj, &v);
#endif
            if (SWIG_IsOK(ecode))
              return self->operator><uint64_t>(v);
            else
              return false;
          }
        else
          return false;
      }
    else if ((PyString_Check(obj)) && (type == DFF::typeId::String))
      {
        char*           cstr;

        //printf("Variant::operator>(PyObject* obj) ---> obj == PyLong_Check || PyInt_Check provided\n");
        if ((cstr = PyString_AsString(obj)) != NULL)
          return self->operator><std::string>(cstr);
        else
          return false;
      }
    else
      return false;
  }


  bool  operator<(PyObject* obj)
  {
    if (DFF_Variant_operator_Se__Se___SWIG_1(self, obj))
      return false;
    else
      return (!DFF_Variant_operator_Sg___SWIG_1(self, obj));
  }

  bool  operator>=(PyObject* obj)
  {
    if (DFF_Variant_operator_Sg___SWIG_1(self, obj) || DFF_Variant_operator_Se__Se___SWIG_1(self, obj))
      return true;
    else
      return false;
  }

  bool  operator<=(PyObject* obj)
  {
    if (DFF_Variant_operator_Sl___SWIG_1(self, obj) || DFF_Variant_operator_Se__Se___SWIG_1(self, obj))
      return true;
    else
      return false;    
  }

  %pythoncode
  %{
    funcMapper = {typeId.Char: "_Variant__Char",
                  typeId.Int16: "_Variant__Int16",
                  typeId.UInt16: "_Variant__UInt16",
                  typeId.Int32: "_Variant__Int32",
                  typeId.UInt32: "_Variant__UInt32",
                  typeId.Int64: "_Variant__Int64",
                  typeId.UInt64: "_Variant__UInt64",
                  typeId.Bool: "_Variant__Bool",
                  typeId.String: "_Variant__String",
                  typeId.CArray: "_Variant__CArray",
                  typeId.Node: "_Variant__Node",
                  typeId.Path: "_Variant__Path",
                  typeId.DateTime: "_Variant__DateTime",
                  typeId.List: "_Variant__VList",
                  typeId.Map: "_Variant__VMap",
                  typeId.VLink: "_Variant__VLink"}

    def __str__(self):
        if self.type() == typeId.Node:
           return self.value().absolute()
        elif self.type() == typeId.DateTime:
           return self.value()
        else:
           return self.toString()


    def value(self):
       try:
         valType = self.type()
         if valType in self.funcMapper.keys():
            func = getattr(self, Variant.funcMapper[valType])
            if func != None:
              val = func()
              return val
            else:
              return None
         else:
           return None
       except :
         return None
  %}
};

%extend DateTime 
{
  PyObject* DFF::DateTime::toPyDateTime(void)
  {
    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    PyDateTime_IMPORT;

    PyObject* pyTuple = Py_BuildValue("(d)", (double)self->epochTime());
    PyObject* dateTime = PyDateTime_FromTimestamp(pyTuple);
    Py_DECREF(pyTuple);
    SWIG_PYTHON_THREAD_END_BLOCK;
    return (dateTime);
  }

  %pythoncode
  %{
      def __str__(self):
        return self.toString()
  %}
};

}

%extend Variant_p 
{
  %pythoncode
  %{

    funcMapper = {typeId.Char: "_RCVariant__Char",
		  typeId.Int16: "_RCVariant__Int16",
		  typeId.UInt16: "_RCVariant__UInt16",
		  typeId.Int32: "_RCVariant__Int32",
		  typeId.UInt32: "_RCVariant__UInt32",
		  typeId.Int64: "_RCVariant__Int64",
		  typeId.UInt64: "_RCVariant__UInt64",
		  typeId.Bool: "_RCVariant__Bool",
		  typeId.String: "_RCVariant__String",
		  typeId.CArray: "_RCVariant__CArray",
		  typeId.Node: "_RCVariant__Node",
		  typeId.Path: "_RCVariant__Path",
		  typeId.DateTime: "_RCVariant__DateTime",
		  typeId.List: "_RCVariant__VList",
		  typeId.Map: "_RCVariant__VMap",
                  typeId.VLink: "_RCVariant__VLink"}

    def __str__(self):
        if self.type() == typeId.Node:
           return self.value().absolute()
        elif self.type() == typeId.DateTime:
           return self.value()
        else:
           return self.toString()


    def value(self):
       try:
         valType = self.type()
         if valType in self.funcMapper.keys():
            func = getattr(self, RCVariant.funcMapper[valType])
            if func != None:
                val = func()
                return val
            else:
                return None
         else:
            return None
       except :
        return None
  %}
};



%extend std::map<std::string, Variant_p >
{
  /* ~map<std::string, Variant_ >() */
  /*   { */
  /*   //  std::map<std::string, Variant*>::iterator	mit; */
  /*     //for (mit = self->begin(); mit != self->end(); mit++) */
  /* 	//if (mit->second != NULL) */
  /* 	  //delete mit->second; */
  /*     delete self; */
  /*   } */

  char*	__str__()
  {
    std::string					str;
    size_t					size;
    size_t					counter;
    std::map<std::string, Variant_p >::iterator	mit;
    char*					cstr;

    size = self->size();
    counter = 0;
    str = "{";
    for (mit = self->begin(); mit != self->end(); mit++)
      {
	counter++;
	str += "'" + mit->first + "': ";
	if (mit->second->type() == DFF::typeId::String || mit->second->type() == DFF::typeId::CArray || mit->second->type() == DFF::typeId::Path)
	  str += "'" + mit->second->toString() + "'";
	else
	  str += mit->second->toString();
	if (counter != size)
	  str += ", ";
      }
    str += "}";
    
    cstr = NULL;
    if ((cstr = (char*)malloc(sizeof(char) * (str.size()+1))) != NULL)
      strncpy (cstr, str.c_str(), str.size()+1);
    return cstr;
  }

  void __setitem__(std::map< std::string, Variant_p >::key_type const &key, std::map<std::string, Variant_p > &vmap)
    {
      DFF::Variant*	vptr;

      if ((vptr = new DFF::Variant(vmap)) != NULL)
	self->insert(std::pair<std::string, DFF::RCPtr< DFF::Variant > >(key, Variant_p(vptr)));
      return;
    }


  void __setitem__(std::map< std::string, Variant_p >::key_type const &key, std::list< Variant_p > &vlist)
    {
      DFF::Variant*	vptr;

      if ((vptr = new DFF::Variant(vlist)) != NULL)
	self->insert(std::pair<std::string, DFF::RCPtr< DFF::Variant > >(key, Variant_p(vptr)));
      return;
    }


  bool operator==(PyObject* obj)
  {
    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    if (PyDict_Check(obj))
      {
        //printf("std::map<std::string, Variant*>::operator==(PyObject* obj) ---> obj == PyDict\n");
        if (self->size() == (unsigned int)PyDict_Size(obj))
          {
            std::map<std::string, Variant_p >::const_iterator it;
            PyObject *value;
            for (it = self->begin(); it != self->end(); it++)
              {
                if ((value = PyDict_GetItemString(obj, it->first.c_str())) != NULL)
                  {
                    if (!DFF_Variant_operator_Se__Se___SWIG_1(it->second.get(), value))
		      {
                      SWIG_PYTHON_THREAD_END_BLOCK;
                      return false;
                    }
                  }
                else
                {
                   SWIG_PYTHON_THREAD_END_BLOCK;
                  return false;
                }
              }
            SWIG_PYTHON_THREAD_END_BLOCK;
            return true;
          }
        else
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          return false;
        }
      }
    else if (strncmp("VMap", obj->ob_type->tp_name, 5) == 0)
      {
        //printf("std::map<std::string, Variant*>::operator==(PyObject* obj) ---> obj == VMap\n");
        void* argp1 = 0;
        std::map< std::string, Variant_p > *arg1 = (std::map< std::string, Variant_p > *) 0 ;
        int res1 = SWIG_ConvertPtr(obj, &argp1, $descriptor(std::map< std::stirng, Variant_p >), 0 | 0);
        if (SWIG_IsOK(res1))
          {
            arg1 = reinterpret_cast< std::map<std::string, Variant_p > * >(argp1);
            if (arg1->size() != self->size())
	      {
		SWIG_PYTHON_THREAD_END_BLOCK;
		return false;
	      }
            else
              {
                std::map<std::string, Variant_p >::iterator smit;
                std::map<std::string, Variant_p >::iterator mit;
                for (smit = self->begin(), mit = arg1->begin(); smit != self->end(), mit != arg1->end(); smit++, mit++)
                  {
                    //std::cout << "self actual key " << smit->first << "  --  provided vmap actual key " << mit->first << std::endl;
                    if ((smit->first != mit->first) || (!(smit->second == mit->second)))
                    {
                      SWIG_PYTHON_THREAD_END_BLOCK;
                      return false;
                    }
                  }
                SWIG_PYTHON_THREAD_END_BLOCK;
                return true;
              }
          }
        else
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          return false;
        }
      }
    else
      {
	SWIG_PYTHON_THREAD_END_BLOCK;
	return false;
      }
    SWIG_PYTHON_THREAD_END_BLOCK;
    return false;
  }
};

%extend std::list<Variant_p >
{

  char*	__str__()
  {
    std::string					str;
    size_t					size;
    size_t					counter;
    std::list< Variant_p >::iterator		lit;
    char*					cstr;

    size = self->size();
    counter = 0;
    str = "[";
    for (lit = self->begin(); lit != self->end(); lit++)
      {
	counter++;
	if ((*lit)->type() == DFF::typeId::String || (*lit)->type() == DFF::typeId::CArray || (*lit)->type() == DFF::typeId::Path)
	  str += "'" + (*lit)->toString() + "'";
	else
	  str += (*lit)->toString();	
	if (counter != size)
	  str += ", ";
      }
    str += "]";
    
    cstr = NULL;
    if ((cstr = (char*)malloc(sizeof(char) * (str.size()+1))) != NULL)
      strncpy (cstr, str.c_str(), str.size()+1);
    return cstr;
  }

  void	append(std::list< Variant_p > other)
  {
    DFF::Variant*	vptr;

    if ((vptr = new DFF::Variant(other)) != NULL)      
      self->push_back(Variant_p(vptr));
    return;
  }


  void	append(std::map< std::string, Variant_p > other)
  {
    DFF::Variant*	vptr;

    if ((vptr = new DFF::Variant(other)) != NULL)      
      self->push_back(Variant_p(vptr));
    return;
  }



  bool operator==(PyObject* obj)
  {
    SWIG_PYTHON_THREAD_BEGIN_BLOCK;
    if (PyList_Check(obj))
      {
        if (self->size() == (unsigned int) PyList_Size(obj))
          {
            std::list< Variant_p >::const_iterator it;
            int i;
            PyObject* item;
            for (it = self->begin(), i = 0; it != self->end(); it++, i++)
              {
                item = PyList_GetItem(obj, i);
                if (!DFF_Variant_operator_Se__Se___SWIG_1(it->get(), item))
                {
                  SWIG_PYTHON_THREAD_END_BLOCK;
                  return false;
                }
              }
            SWIG_PYTHON_THREAD_END_BLOCK;
            return true;
          }
        else
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          return false;
        }
      }
    else if (strncmp("VList", obj->ob_type->tp_name, 5) == 0)
      {
        void* argp1 = 0;
        std::list< Variant_p > *arg1 = (std::list< Variant_p > *) 0 ;
        int res1 = SWIG_ConvertPtr(obj, &argp1, $descriptor(std::list< Variant_p >), 0 | 0);
        if (SWIG_IsOK(res1))
          {
            arg1 = reinterpret_cast< std::list<Variant_p > * >(argp1);
            if (self->size() != arg1->size())
            {
              SWIG_PYTHON_THREAD_END_BLOCK;
              return false;
            }
            else
              {
                std::list<Variant_p >::iterator	sit;
                std::list<Variant_p >::iterator	lit;
                for (sit = self->begin(), lit = arg1->begin(); sit != self->end(), lit != arg1->end(); sit++, lit++)
                  if (!(*lit == *sit))
                  {
                    SWIG_PYTHON_THREAD_END_BLOCK;
                    return false;
                  }
                SWIG_PYTHON_THREAD_END_BLOCK;
                return true;
              }
          }
        else
        {
          SWIG_PYTHON_THREAD_END_BLOCK;
          return false;
        }
      }
    else
    {
      SWIG_PYTHON_THREAD_END_BLOCK;
      return false;
    }
    SWIG_PYTHON_THREAD_END_BLOCK;
    return false;
  }
};
