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

%module(package="dff.api.vfs",docstring="libvfs: c++ generated inteface", directors="1") libvfs 
%feature("autodoc", 1); //1 = generate type for func proto, no work for typemap
%feature("docstring");

%feature("docstring") DFF::FileMapping
" 
    Most of the time (with a few exceptions), nodes in DFF are associated with a set of meta-data
    and a content. For example, a file system driver will parse the real file system of a dump
    or device and then create one node for each files and directories. These files are associated
    with content, such as pictures, text, videos, etc. The content of a file is located somewhere
    on the dump and can be found by following the file system specification. For each modules, the
    specification is different so file content position will be different.

    As far as each file systems and dumps do not have the same specification and content, it is necessary
    to have a standard way to represent their content position in DFF.

    The FileMapping class is used to give this standard way to describe file content positions on the dump.
    So when the file is opened its content can be displayed in DFF interface using a viewer.
    File content can be fragmented on the disk so generally there are several chunks to describe the
    entire content of a file, especially on big files.

    More precisely, the FileMapping class contains a list of chunks giving the different offsets
    of the file blocks on the vfile. Each chunks are used to describe one of these different positions on the vfile
    by providing two informations :
        * the offset of the data on the vfile
        * the size it occupies
    
    In other words, the chunk's list will, for each areas the file occupies, give its begining offset and its size.
    We could say something like :
     * The file `foo` first chunk start at offset 0x42 and occupies 10 bytes.
     * The second chunk of `foo` file starts at offset 0x84 and occupies 20 bytes.
     * etc.
     
    For example, lets imagine we open a 100 bytes big node which is fragmented in
    three parts. When mapping the file, three chunks will be created and will look
    like this :
        * chunk 1 => offset : x; size : s bytes
        * chunk 1 => offset : y; size : t bytes
        * chunk 1 => offset : z; size : u bytes
    
    The sum `s + t + u` should be equal to the file size (100 bytes in our example).
    The \"main\" method of FileMapping class is push, which must be called to
    create the different chunks. This method muts be called in the Node::fileMapping method,
    which is called by DFF when the node is opened.
"

%feature("docstring") DFF::FileMapping::mappedFileSize
"
        Return the total size of the different chunks. Should be equal to the node
        size.
"

%feature("docstring") DFF::FileMapping::chunkCount
"
        Return the number of mapped chunks.
"

%feature("docstring") DFF::FileMapping::firstChunk
"
        Return a pointer to the first chunk of the list.
"


%feature("docstring") DFF::FileMapping::lastChunk
"
        Return a pointer to the last chunk of the list.
"

%feature("docstring") DFF::FileMapping::chunkFromIdx
"

        Return a pointer on the chunk structure corresponding to index `idx`
        in the list of chunk.
"

%feature("docstring") DFF::FileMapping::chunkFromOffset
"

        Return a pointer to the chunk in which offset `offset` is.
"


%feature("docstring") DFF::fso
"
The fso or 'File System Object' class is the base class of the API. All
modules must inheritates it (or inherit mfso, which itself inherit fso). It provides
several virtual methods which must be reimplemented, such as start, vopen, vread, vwrite, 
vclose and vseek. They are used to read, open, write and seek within the content
of a node.
        
The start method does the job the module is supposed to do. This is the method which is
called when a module is launched.

The main difference between fso and mfso is the fact that the open, read and seek method
are pure virtual in fso and virtual in mfso. Indeed, using the fso class rather than
the mfso class, where implentations of open and read are provided, supposes that the
developer of the module does not wish to use the FileMapping system.

The behaviour, use and prototype of methods open, read and seek are pretty similar to their
UNIX equivalent. The vwrite method is generally not used, and even left empty in modules implementations.

"

%feature("docstring") DFF::fso::start
"
        This method is called when the module starts. It does the job the module
        is supposed to do. This method is declared as a pure virtual so each modules
        must reiplements it (see the developer's documentations for more details) in
        python or C++, depending on which language you choose.

        The parameter 'args' is a pointer to the arguments list which were passed to the
        module when it was launched. You can get them by using the method
         args->get(\"arg_name\", &variable)
        where variable must be of the same type than the argument \"arg_name\"

        If you create nodes, you must not forget to call the method register_tree at
        the end of the module execution.

        If an error occured while getting a parameter, a envError exception is thrown.

        Params :
                * args : the list of arguments passed to the module.

"
 
%feature("docstring") DFF::fso::vopen
"
        Open a node.

        Param :
                * n : the node you want to open

        Return the opened file descriptor, or 0 if it failed.
"

%feature("docstring") DFF::fso::vread
"
        vread(self, int32_t fd, void rbuff, uint32_t size) -> int32_t

        Perform readings on an open node and returns the number of bytes which wereread.

        Params :
                * fd : the file descriptor of the node you want to read on.
                * rbuff : a pointer to an allocated buffer where the read bytes will be stored
                * size : the number of characters you want to read.

        Return the number of read characters.
"

%feature("docstring") DFF::fso::vwrite
"
Not used.
"

%feature("docstring") DFF::fso::vclose
"
Close an open file descriptor and make it available again for others
openings.

Return `0` if everything went fine, `0` otherwise.
"

%feature("docstring") DFF::fso::vseek
"
        vseek(self, int32_t fd, uint64_t offset, int32_t whence) -> uint64_t

        This method is used to change position within an open node (i.e. modifies the
        offset of the current position). The offset is set to 0 when the file is open.

        Throws a vfsError if something goes wrong (typically if the seeking position is
        after the end of the file).

        It takes three parameters :
                * a file descriptor of an open node
                * the offset where you want to seek
                * the third parameter is optional : it defines if the offset passed in second parameter is absolute or relative.

        Return an uint64_t
"

%feature("docstring") DFF::fso::status
"
Return the status of the module.
"

%feature("docstring") DFF::fso::vtell
"
Returns the current offset in a file.
"

%feature("docstring") DFF::fso::setVerbose
"
        Set the module in verbose mode if the param `verbose` is et to `true`, 
        shutdown the verbose mode otherwise. Verbose mode should not be enabled
        in production environment.

        Params :
                * verbose : the verbosity
"

%feature("docstring") DFF::fso::verbose
"
        Return `true` if the module is in verbose mode, `false` otherwise.
"

%feature("docstring") DFF::mfso
"
The mfso purpose has pretty the same role as the fso one. It inheritates fso.

The main difference is based on the file mapping : the fso class
do not use file mapping, mfso uses it. The mfso class provides implementations
for the vopen, vread and vseek methods and a file descriptor manager (which not
the case in the fso interface). It provides an abstraction of the node's content
to developers, making the code easier to write.

File mapping is detailed in libvfs.fileMapping.
"

%feature("docstring") DFF::mfso::start
"
        start(self, argument args)

        This method is pure virtual in mfso so musts be implemented while developing
        a module.
        
        This method is called when the module starts. It does the job the module
        is supposed to do. This method is declared as a pure virtual so each modules
        must reiplements it (see the developer\'s documentations for more details) in
        python or C++, depending on which language you choose.

        The parameter \'args\' is pointer to the arguments list which were passed to the
        module when it was launched. You can get them by using the method

          args->get(\"arg_name\", &variable)

        where variable must be of the same type than the argument \"arg_name\"

        If you create nodes, you must not forget to call the method register_tree at
        the end of the module execution.

        If an error occured while getting a parameter, a envError exception is thrown.

        Params :
                * args : the list of arguments.

"
  
%feature("docstring") DFF::mfso::open
"
Open the node `n`.

Params :
        * n : the node you want to open.

An implentation of this method is provided with mfso, so developers should not have
to reimplement it.
"

%feature("docstring") DFF::mfso::vread
"
        Perform readings on an open node and returns the number of bytes which were read.
        The reading is performed at the current offset on the file. If the user tries
        to read more bytes that they are in the file, read will stop reading at the
        end of the file and return the actual number of read characters.

        Params :
                * fd : the file descroiptor of the node you want to read on.
                * buff : a pointer to an allocated buffer where the read bytes will be stored
                * size : the number of characters you want to read.

        Throw a vfsError if something goes wrong.

        An implentation of this method is provided with mfso, so developers should not have
        to reimplement it.

        Return the number of read characters.
"

%feature("docstring") DFF::mfso::vwrite
"
Not used in most cases.
"

%feature("docstring") DFF::mfso::vclose
"
        Close an open file descriptor and make it available again for others
        openings.

        An implentation of this method is provided with mfso, so developers should not have
        to reimplement it.

        Params :
                * fd : the file decsriptor you want to close.

        Return 0.

"

%feature("docstring") DFF::mfso::vseek
"

        This method is used to change offset within an open node.
        The offset is set to 0 when the file is open.

        Throws a vfsError if something goes wrong (typically if the seeking position is
        after the end of the file).

        Params :
                * fd : a file descriptor of an open node
                * offset : the offset where you want to seek
                * whence : the third parameter is optional : it defines if the offset passed in second parameter is absolute or relative.

        An implentation of this method is provided with mfso, so developers should not have
        to reimplement it.
        
        Return of how many bytes the position changed.
"

%feature("docstring") DFF::mfso::vtell
"

        Returns the current offset in a file.

        An implentation of this method is provided with mfso, so developers should not have
        to reimplement it.

        Param :
                * fd : the file descriptor of the node on which you want to use vtell.

"

%feature("docstring") DFF::mfso::setVerbose
        """
        setVerbose(self, bool verbose)

        Set the module in verbose mode if the param `verbose` is set to `true`, 
        shutdown the verbose mode otherwise.
        """

%feature("docstring") DFF::mfso::verbose
        """
        verbose(self) -> bool

        Return `true` if the module is in verbose mode, `false` otherwise.
        """

%feature("docstring") DFF::Node
"
This class is the base interface of every nodes reprensented in DFF virtual file
system tree view. Most of the modules will have to extend this class before using
it, that is why some of the methods are virtual.
"

%feature("docstring") DFF::Node::setId
"
        Set an ID of type uint32_t

        Params :
                * id : the id you want to set to node.
"

%feature("docstring") DFF::Node::id
"
        Return the ID.
"

%feature("docstring") DFF::Node::setFile
"
If the node is a file this method should be called to set proper attributes.
"

%feature("docstring") DFF::Node::setDir
"
If the node is a directory this method should be called to set proper attributes.
"

%feature("docstring") DFF::Node::setLink
"
If the node is a link this method should be called to set proper attributes.
"

%feature("docstring") DFF::Node::setDeleted
"
If the node corresponds to a data which was deleted (and recovered by the
module), this method should be called to set proper attributes.
"

%feature("docstring") DFF::Node::setSize
"
Set the node size in bytes.
"

%feature("docstring") DFF::Node::setFsobj
"
Set a fso object.
"

%feature("docstring") DFF::Node::setParent
"
Set the parent's node of the current node.
"

%feature("docstring") DFF::Node::fileMapping
"
The fileMapping method takes a pointer to an instance of a FileMapping object
as parameter. This method is called when a node is opened.

The fileMapping method must \"filled up\" the FileMapping object which was passed
to it by creating chunks of the files. A chunk is a structure containing 2
important informations :
 * The size (in bytes) of the chunk
 * Its address on the vfile.

In human speakable langugage it means that the FileMapping structure contains
a list of data structure, each of them giving a part of the file content position
on the vfile.

FileMapping can be filled up by calling their push() method.
"

%feature("docstring") DFF::Node::extendedAttributes
"
This method is used to set extended attributes to a node. It takes a pointer
to an Attributes instance as parameter. This parameter can be filled up with
attributes of any types by using the Variant type.

ExtendedAttributes can be filled up by calling their push() method.
"

%feature("docstring") DFF::Node::modifiedTime
"
Set the time of last modification
"

%feature("docstring") DFF::Node::accessedTime
"
Set the time of last access
"

%feature("docstring") DFF::Node::createdTime
"
Set the time of creation
"

%feature("docstring") DFF::Node::changedTime
"
Set the time of last change
"

%feature("docstring") DFF::Node::times
"
Return a map containing the different time informations on a node.
"

%feature("docstring") DFF::Node::size
"
Return the size of the node
"

%feature("docstring") DFF::Node::path
"
return the path to the node
"

%feature("docstring") DFF::Node::name
"
return the name of the node
"

%feature("docstring") DFF::Node::absolute
"
return the absolute path of the node (equivalent to Node::path() + Node::name())
"

%feature("docstring") DFF::Node::isFile
"
return true if the node is a file, false otherwise
"

%feature("docstring") DFF::Node::isDir
"
return true if the node is a directory, false otherwise
"

%feature("docstring") DFF::Node::isLink
"
return true if the node is a link, false otherwise
"

%feature("docstring") DFF::Node::isVDir
"
return true if the node is a link to a directory, false otherwise
"

%feature("docstring") DFF::Node::isDeleted
"
return true if the node is deleted, false otherwise
"

%feature("docstring") DFF::Node::fsobj
"
return a pointer to fso instance associated with the node
"

%feature("docstring") DFF::Node::parent
"
return a pointer to the node which is the parent of the cuurent node.
"

%feature("docstring") DFF::Node::children
"
return a vector containing pointers to the children of the current node. If the
node has no child, the vector is empty.
"

%feature("docstring") DFF::Node::addChild
"
Take a pointer to a node in parameter. This node will be added to the current node
as one of its child.
"

%feature("docstring") DFF::Node::hasChildren
"
return true if the node has one or more children, false otherwise
"

%feature("docstring") DFF::Node::childCount
"
return the number of children the node has
"

%feature("docstring") DFF::Node::open
"
Open the node and return a pointer to a VFile instance
"

%feature("docstring") DFF::VLink
"
    The class VLink inherits the Node class. It a specific type of Node corresponding
    to a link to an other node. This class can be useful to create nodes \"pointing\"
    on other nodes, such as Linux symbolic links or Windows short-cuts for example.

    Otherwise, the VLink class is pretty similar to the Node class.
"

%feature("docstring") DFF::VLink::__init__
"
        Constructor.

        Params :
                * linkedNode
                * parent : the parent's node of the VLink
                * newname : the name of the node (empty by default)
"

%feature("docstring") DFF::VLink::linkPath
"
        Return the path to the pointed node.
"

%feature("docstring") DFF::VLink::linkName
"
        Return the name of the pointed node.
"

%feature("docstring") VLink::linkAbsolute
"
        Return the absolute path + name of the pointed node. Is equivalent to
        VLink::linkPath() + \"/\" + VLink::linkName()
"

%feature("docstring") DFF::VLink::linkParent
"
        Return a pointer to the parent node of the pointed node.
"

%feature("docstring") DFF::VLink::linkChildren
"
        Return the list of children of the pointed node.
"

%feature("docstring") DFF::VLink::linkHasChildren
"
        Return `true` if the pointed node has children, `false` otherwise.
"

%feature("docstring") DFF::VLink::linkChildCount
"
        Return the number of child the pointed nodes has.
"

%feature("docstring") DFF::VLink::linkNode
"
        Return a pointer to the node pointed by the link.
"

%feature("docstring") DFF::Attributes
"
    The Attributes class is designed to store a list of  attributes related to
    a Node, such as, among others, time informations, file mode or UNIX access rights
    for example.

    Each attributes are made of a string describing the attribute and a value, which
    is Variant type. For more precisions on Variant, see the Variant documentation.
"

%feature("docstring") DFF::Attributes::push
"
        push(self, string key, Variant value)

        Add an attribute to the attributes list.

        Params :
                * key : the description of the attributes.
                * value : the value of the attribute

"

%feature("docstring") DFF::Attributes::keys
"
        keys(self) -> std::list<(std::string,std::allocator<(std::string)>)>

        Returns a std::list<std::string> where each values are a key of attributes.
"

%feature("docstring") DFF::Attributes::value
"
        value(self, string key) -> Variant
        
        Return the value of the attributes which key is `key`
"

%feature("docstring") DFF::Attributes::attributes
"
        attributes(self) -> std::map<(std::string,p.Variant,std::less<(std::string)>,std::allocator<(std::pair<(q(const).std::string,p.Variant)>)>)>

        Return a std::map<std::string, Variant \*> which contains the entire list of attributes
"

%feature("docstring") DFF::FdManager
"
    The FdManager is used to manage all open file descriptors.
"

%feature("docstring") DFF::FdManager::get
"
        Return a pointer to the fdinfo structure correponding to file descriptor `fd`

        Params :
                * fd : the file decsriptor on which you want to get the fdinfo structure
"

%feature("docstring") DFF::FdManager::remove
"
        Free the resources occupied by the fdinfo structure correponding to `fd`
"

%feature("docstring") DFF::FdManager::push
"
        Push the fdinfo `fi` into the list of opened file descriptors.
"
#pragma SWIG nowarn=473
%warnfilter(SWIGWARN_IGNORE_OPERATOR_EQ,SWIGWARN_LANG_IDENTIFIER);

%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "std_vector.i"
%include "std_except.i"

#ifndef WIN32
	%include "stdint.i"
#elif _MSC_VER >= 1600
	%include "stdint.i"
#else
	%include "wstdint.i"
#endif
%include "windows.i"


%feature("director") DFF::fso;
%feature("director") DFF::mfso;
%feature("director") DFF::Node;
%feature("director") DFF::VLink;
%feature("director") DFF::AttributesHandler;

%newobject DFF::VFile::search;
%newobject DFF::VFile::indexes;

%newobject DFF::Node::open;
%newobject DFF::VLink::open;

/* %feature("director:except") fso */
/* { */
/*     if ($error != NULL) */
/*     {       */
/*       throw Swig::DirectorMethodException(); */
/*     } */
/* } */

/* %feature("director:except") mfso */
/* { */
/*     if ($error != NULL) */
/*     { */
/*       throw Swig::DirectorMethodException(); */
/*     } */
/* } */

/* %feature("director:except") Node */
/* { */
/*     if ($error != NULL) */
/*     { */
/*       throw Swig::DirectorMethodException(); */
/*     } */
/* } */

/* %feature("director:except") VLink  */
/* { */
/*     if ($error != NULL) */
/*     { */
/*       throw Swig::DirectorMethodException(); */
/*     } */
/* } */

%import "../exceptions/libexceptions.i"

//XXX fix iterator !
%typemap(out) (DFF::Node*)
{
  //#int dcast = 0;
  DFF::VLink *dobj = dynamic_cast<DFF::VLink*>($1);
  if (dobj)
  {
    %set_output(SWIG_NewPointerObj(dobj, SWIGTYPE_p_DFF__VLink, $owner | %newpointer_flags));
  }
  else
  {
    %set_output(SWIG_NewPointerObj($1, SWIGTYPE_p_DFF__Node, $owner | %newpointer_flags));
  }
}

%typemap(directorargout)  (int32_t fd, void *rbuff, uint32_t size)
{
  if (output)
  {
    if (c_result > 0 && c_result <= (int32_t)size)
      memcpy((char *)rbuff, PyString_AsString($result) , c_result);
    else
     c_result = 0;
  }
  else
    PyErr_Clear();
}

%typemap(out) DFF::pdata*
{
  Py_XDECREF($result);
  $result = PyString_FromStringAndSize((const char *)$1->buff, $1->len);
  free($1->buff);
  delete $1;
}

%typecheck(SWIG_TYPECHECK_CHAR) unsigned char
{
  $1 = (((PyString_Check($input) && ((PyString_Size($input) == 1) || PyString_Size($input) == 0))) 
	|| (PyInt_Check($input) && ((PyInt_AsLong($input) >= 0) && (PyInt_AsLong($input) <= 255)))) ? 1 : 0;
}

%typemap(in) (unsigned char wildcard)
{
  if (!PyString_Check($input) || (PyString_Size($input) > 1))
    {
      PyErr_SetString(PyExc_ValueError, "Expecting a string");
      return NULL;
    }
  $1 = (unsigned char) PyString_AsString($input)[0];
}

%ignore   DFF::VFile::find(unsigned char* needle, uint32_t nlen);
%ignore   DFF::VFile::find(unsigned char* needle, uint32_t nlen, unsigned char wildcard);
%ignore   DFF::VFile::find(unsigned char* needle, uint32_t nlen, unsigned char wildcard, uint64_t start);
%ignore   DFF::VFile::find(unsigned char* needle, uint32_t nlen, unsigned char wildcard, uint64_t start, uint64_t end);

%ignore   DFF::VFile::rfind(unsigned char* needle, uint32_t nlen);
%ignore   DFF::VFile::rfind(unsigned char* needle, uint32_t nlen, unsigned char wildcard);
%ignore   DFF::VFile::rfind(unsigned char* needle, uint32_t nlen, unsigned char wildcard, uint64_t start);
%ignore   DFF::VFile::rfind(unsigned char* needle, uint32_t nlen, unsigned char wildcard, uint64_t start, uint64_t end);

%ignore   DFF::VFile::count(unsigned char* needle, uint32_t nlen);
%ignore   DFF::VFile::count(unsigned char* needle, uint32_t nlen, unsigned char wildcard);
%ignore   DFF::VFile::count(unsigned char* needle, uint32_t nlen, unsigned char wildcard, int32_t maxcount);
%ignore   DFF::VFile::count(unsigned char* needle, uint32_t nlen, unsigned char wildcard, int32_t maxcount, uint64_t start);
%ignore   DFF::VFile::count(unsigned char* needle, uint32_t nlen, unsigned char wildcard, int32_t maxcount, uint64_t start, uint64_t end);

%ignore	  DFF::VFile::indexes(unsigned char* needle, uint32_t nlen);
%ignore	  DFF::VFile::indexes(unsigned char* needle, uint32_t nlen, unsigned char wildcard);
%ignore	  DFF::VFile::indexes(unsigned char* needle, uint32_t nlen, unsigned char wildcard, uint64_t start);
%ignore	  DFF::VFile::indexes(unsigned char* needle, uint32_t nlen, unsigned char wildcard, uint64_t start, uint64_t end);


%{
#include "rc.hpp"
#include "tags.hpp"
#include "eventhandler.hpp"
#include "vfs.hpp"
#include "exceptions.hpp"
#include "filemapping.hpp"
#include "export.hpp"
#include "fso.hpp"
#include "mfso.hpp"
#include "vfile.hpp"
#include "node.hpp"
#include "rootnode.hpp"
#include "vlink.hpp"
#include "variant.hpp"
#include "datetime.hpp"
#include "path.hpp"
#include "iostat.hpp"
#include "fdmanager.hpp"
//#include "datatype.hpp"
%}

%import "../types/libtypes.i"

%refobject DFF::RCObj "$this->addref();"
%unrefobject DFF::RCObj "$this->delref();"
%import "../events/libevents.i"

%include "../include/rc.hpp"
%include "../include/tags.hpp"
%include "../include/vfs.hpp"
%include "../include/export.hpp"
%include "../include/filemapping.hpp"
%include "../include/exceptions.hpp"
%include "../include/fso.hpp"
%include "../include/mfso.hpp"
%include "../include/vfile.hpp"
%include "../include/node.hpp"
%include "../include/rootnode.hpp"
%include "../include/vlink.hpp"
%include "../include/fdmanager.hpp"
//%include "../include/iostat.hpp" // need to be export to python ?

namespace std
{
  %template(VecNode)		std::vector<DFF::Node*>;
  %template(ListNode)		std::list<DFF::Node*>;
  %template(SetNode)		std::set<DFF::Node *>;
  %template(VectChunk)		std::vector<DFF::chunk *>;
  %template(Listui64)		std::list<uint64_t>;
  %template(Vectui64)		std::vector<uint64_t>;
  %template(Vectui32)		std::vector<uint32_t>;
  %template(MapDateTime)		std::map<std::string, DFF::DateTime*>;
  %template(MapNameTypes)	std::map<std::string, uint8_t>;
  %template(FsoVect)		std::vector<DFF::fso*>;
  %template(TagVect)            std::vector<DFF::Tag* >;
//%template(ListDataType)       list<DFF::DataTypeHandler*>; need to be exported to python ?
//%template(MapDataType)        map<std::string, uint32_t>; 
}

/* %traits_swigtype(Variant); */
/* %fragment(SWIG_Traits_frag(Variant)); */
//%traits_swigtype(DateTime); already in libtypes.i
//%fragment(SWIG_Traits_frag(DateTime));

namespace DFF
{

%extend VFile
{
%pythoncode
    %{
    def __iter__(self):
        return self
    
    def next(self):
        cpos = self.tell()
        idx = self.find('\n')
        if idx != -1:
           self.seek(cpos)
           buff = self.read(idx - cpos+1)
           if len(buff) == 0:
               raise StopIteration()
           else:
               return buff
        else:
           raise StopIteration()
    %}
};

%extend mfso
{
%pythoncode
%{
def vread(self, *args):
  return (_libvfs.mfso_vread(self, *args),)
%}
}

%extend Node
{

%pythoncode
%{
def __iter__(self):
  for node in self.next:  
     yield node
%}

}

}
