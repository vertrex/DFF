# This file was automatically generated by SWIG (http://www.swig.org).
# Version 2.0.11
#
# Do not make changes to this file unless you know what you are doing--modify
# the SWIG interface file instead.





from sys import version_info
if version_info >= (2,6,0):
    def swig_import_helper():
        from os.path import dirname
        import imp
        fp = None
        try:
            fp, pathname, description = imp.find_module('_ntfs', [dirname(__file__)])
        except ImportError:
            import _ntfs
            return _ntfs
        if fp is not None:
            try:
                _mod = imp.load_module('_ntfs', fp, pathname, description)
            finally:
                fp.close()
            return _mod
    _ntfs = swig_import_helper()
    del swig_import_helper
else:
    import _ntfs
del version_info
try:
    _swig_property = property
except NameError:
    pass # Python < 2.2 doesn't have 'property'.
def _swig_setattr_nondynamic(self,class_type,name,value,static=1):
    if (name == "thisown"): return self.this.own(value)
    if (name == "this"):
        if type(value).__name__ == 'SwigPyObject':
            self.__dict__[name] = value
            return
    method = class_type.__swig_setmethods__.get(name,None)
    if method: return method(self,value)
    if (not static):
        self.__dict__[name] = value
    else:
        raise AttributeError("You cannot add attributes to %s" % self)

def _swig_setattr(self,class_type,name,value):
    return _swig_setattr_nondynamic(self,class_type,name,value,0)

def _swig_getattr(self,class_type,name):
    if (name == "thisown"): return self.this.own()
    method = class_type.__swig_getmethods__.get(name,None)
    if method: return method(self)
    raise AttributeError(name)

def _swig_repr(self):
    try: strthis = "proxy of " + self.this.__repr__()
    except: strthis = ""
    return "<%s.%s; %s >" % (self.__class__.__module__, self.__class__.__name__, strthis,)

try:
    _object = object
    _newclass = 1
except AttributeError:
    class _object : pass
    _newclass = 0


try:
    import weakref
    weakref_proxy = weakref.proxy
except:
    weakref_proxy = lambda x: x


class SwigPyIterator(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, SwigPyIterator, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, SwigPyIterator, name)
    def __init__(self, *args, **kwargs): raise AttributeError("No constructor defined - class is abstract")
    __repr__ = _swig_repr
    __swig_destroy__ = _ntfs.delete_SwigPyIterator
    __del__ = lambda self : None;
    def value(self): return _ntfs.SwigPyIterator_value(self)
    def incr(self, n=1): return _ntfs.SwigPyIterator_incr(self, n)
    def decr(self, n=1): return _ntfs.SwigPyIterator_decr(self, n)
    def distance(self, *args): return _ntfs.SwigPyIterator_distance(self, *args)
    def equal(self, *args): return _ntfs.SwigPyIterator_equal(self, *args)
    def copy(self): return _ntfs.SwigPyIterator_copy(self)
    def next(self): return _ntfs.SwigPyIterator_next(self)
    def __next__(self): return _ntfs.SwigPyIterator___next__(self)
    def previous(self): return _ntfs.SwigPyIterator_previous(self)
    def advance(self, *args): return _ntfs.SwigPyIterator_advance(self, *args)
    def __eq__(self, *args): return _ntfs.SwigPyIterator___eq__(self, *args)
    def __ne__(self, *args): return _ntfs.SwigPyIterator___ne__(self, *args)
    def __iadd__(self, *args): return _ntfs.SwigPyIterator___iadd__(self, *args)
    def __isub__(self, *args): return _ntfs.SwigPyIterator___isub__(self, *args)
    def __add__(self, *args): return _ntfs.SwigPyIterator___add__(self, *args)
    def __sub__(self, *args): return _ntfs.SwigPyIterator___sub__(self, *args)
    def __iter__(self): return self
SwigPyIterator_swigregister = _ntfs.SwigPyIterator_swigregister
SwigPyIterator_swigregister(SwigPyIterator)

import dff.api.vfs.libvfs
import dff.api.exceptions.libexceptions
import dff.api.types.libtypes
import dff.api.events.libevents
class NTFS(dff.api.vfs.libvfs.mfso):
    """1"""
    __swig_setmethods__ = {}
    for _s in [dff.api.vfs.libvfs.mfso]: __swig_setmethods__.update(getattr(_s,'__swig_setmethods__',{}))
    __setattr__ = lambda self, name, value: _swig_setattr(self, NTFS, name, value)
    __swig_getmethods__ = {}
    for _s in [dff.api.vfs.libvfs.mfso]: __swig_getmethods__.update(getattr(_s,'__swig_getmethods__',{}))
    __getattr__ = lambda self, name: _swig_getattr(self, NTFS, name)
    __repr__ = _swig_repr
    def __init__(self): 
        """
        __init__(NTFS self) -> NTFS

        1
        """
        this = _ntfs.new_NTFS()
        try: self.this.append(this)
        except: self.this = this
    __swig_destroy__ = _ntfs.delete_NTFS
    __del__ = lambda self : None;
    def start(self, *args):
        """
        start(NTFS self, VMap args)

        start(self, argument args)

        This method is pure virtual in mfso so musts be implemented while developing
        a module.

        This method is called when the module starts. It does the job the module
        is supposed to do. This method is declared as a pure virtual so each modules
        must reiplements it (see the developer's documentations for more details) in
        python or C++, depending on which language you choose.

        The parameter 'args' is pointer to the arguments list which were passed to the
        module when it was launched. You can get them by using the method

          args->get("arg_name", &variable)

        where variable must be of the same type than the argument "arg_name"

        If you create nodes, you must not forget to call the method register_tree at
        the end of the module execution.

        If an error occured while getting a parameter, a envError exception is thrown.

        Params :
                * args : the list of arguments.


        """
        return _ntfs.NTFS_start(self, *args)

    def setStateInfo(self, *args):
        """
        setStateInfo(NTFS self, std::string const & arg2)

        1
        """
        return _ntfs.NTFS_setStateInfo(self, *args)

    def opt(self):
        """
        opt(NTFS self) -> NTFSOpt *

        1
        """
        return _ntfs.NTFS_opt(self)

    def mftManager(self):
        """
        mftManager(NTFS self) -> MFTEntryManager *

        1
        """
        return _ntfs.NTFS_mftManager(self)

    def vread(self, *args):
        """
        vread(NTFS self, int fd, void * buff, unsigned int size) -> int32_t

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

        """
        return _ntfs.NTFS_vread(self, *args)

NTFS_swigregister = _ntfs.NTFS_swigregister
NTFS_swigregister(NTFS)

from dff.api.module.module import * 
from dff.api.types.libtypes import * 

class ntfs(Module):
  def __init__(self):
    Module.__init__(self, 'ntfs', NTFS)
    self.conf.addArgument({"name": "file",
                           "description": "Path to a file containing NTFS",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"name" : "recovery",
                           "description" : "If set the module will try to recover files and folders by carving MFT in unallocated clusters",
                           "input": Argument.Empty})
    self.conf.addArgument({"name" : "advanced-attributes",
                           "description" : "Provides advanced attributes for nodes",
                           "input": Argument.Empty})
    self.conf.addArgument({"name" : "no-bootsector-check",
                           "description" : "If set the module will continue even if the bootsector is corrupted",
                           "input": Argument.Empty})
    self.conf.addConstant({"name": "mime-type",
                           "description": "managed mime type",
                           "type" : typeId.String,
                           "values" : ["filesystem/ntfs"]})
    self.conf.addArgument({"name" : "drive-name",
                          "description": "Use this drive name to link reparse point and symlink",
                          "input" : Argument.Optional|Argument.Single|typeId.String,
                          "values": ["C:"]})
    self.conf.description = "Creates a tree from a NTFS file system, for regular and deleted/orphan files and folders.\nIt also provides human-readable dump of MFT or Indexex entries."
    self.tags = "File systems"

# This file is compatible with both classic and new-style classes.


