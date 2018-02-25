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
            fp, pathname, description = imp.find_module('_DEVICES', [dirname(__file__)])
        except ImportError:
            import _DEVICES
            return _DEVICES
        if fp is not None:
            try:
                _mod = imp.load_module('_DEVICES', fp, pathname, description)
            finally:
                fp.close()
            return _mod
    _DEVICES = swig_import_helper()
    del swig_import_helper
else:
    import _DEVICES
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
    __swig_destroy__ = _DEVICES.delete_SwigPyIterator
    __del__ = lambda self : None;
    def value(self): return _DEVICES.SwigPyIterator_value(self)
    def incr(self, n=1): return _DEVICES.SwigPyIterator_incr(self, n)
    def decr(self, n=1): return _DEVICES.SwigPyIterator_decr(self, n)
    def distance(self, *args): return _DEVICES.SwigPyIterator_distance(self, *args)
    def equal(self, *args): return _DEVICES.SwigPyIterator_equal(self, *args)
    def copy(self): return _DEVICES.SwigPyIterator_copy(self)
    def next(self): return _DEVICES.SwigPyIterator_next(self)
    def __next__(self): return _DEVICES.SwigPyIterator___next__(self)
    def previous(self): return _DEVICES.SwigPyIterator_previous(self)
    def advance(self, *args): return _DEVICES.SwigPyIterator_advance(self, *args)
    def __eq__(self, *args): return _DEVICES.SwigPyIterator___eq__(self, *args)
    def __ne__(self, *args): return _DEVICES.SwigPyIterator___ne__(self, *args)
    def __iadd__(self, *args): return _DEVICES.SwigPyIterator___iadd__(self, *args)
    def __isub__(self, *args): return _DEVICES.SwigPyIterator___isub__(self, *args)
    def __add__(self, *args): return _DEVICES.SwigPyIterator___add__(self, *args)
    def __sub__(self, *args): return _DEVICES.SwigPyIterator___sub__(self, *args)
    def __iter__(self): return self
SwigPyIterator_swigregister = _DEVICES.SwigPyIterator_swigregister
SwigPyIterator_swigregister(SwigPyIterator)

import dff.api.vfs.libvfs
import dff.api.exceptions.libexceptions
import dff.api.types.libtypes
import dff.api.events.libevents
class DeviceNode(dff.api.vfs.libvfs.Node):
    """1"""
    __swig_setmethods__ = {}
    for _s in [dff.api.vfs.libvfs.Node]: __swig_setmethods__.update(getattr(_s,'__swig_setmethods__',{}))
    __setattr__ = lambda self, name, value: _swig_setattr(self, DeviceNode, name, value)
    __swig_getmethods__ = {}
    for _s in [dff.api.vfs.libvfs.Node]: __swig_getmethods__.update(getattr(_s,'__swig_getmethods__',{}))
    __getattr__ = lambda self, name: _swig_getattr(self, DeviceNode, name)
    __repr__ = _swig_repr
    def __init__(self, *args): 
        """
        __init__(DeviceNode self, std::string devname, uint64_t size, fso fsobj, std::string name) -> DeviceNode

        1
        """
        this = _DEVICES.new_DeviceNode(*args)
        try: self.this.append(this)
        except: self.this = this
    def icon(self):
        """
        icon(DeviceNode self) -> std::string

        1
        """
        return _DEVICES.DeviceNode_icon(self)

    __swig_setmethods__["__devname"] = _DEVICES.DeviceNode___devname_set
    __swig_getmethods__["__devname"] = _DEVICES.DeviceNode___devname_get
    if _newclass:__devname = _swig_property(_DEVICES.DeviceNode___devname_get, _DEVICES.DeviceNode___devname_set)
    __swig_destroy__ = _DEVICES.delete_DeviceNode
    __del__ = lambda self : None;
DeviceNode_swigregister = _DEVICES.DeviceNode_swigregister
DeviceNode_swigregister(DeviceNode)

class devices(dff.api.vfs.libvfs.fso):
    """1"""
    __swig_setmethods__ = {}
    for _s in [dff.api.vfs.libvfs.fso]: __swig_setmethods__.update(getattr(_s,'__swig_setmethods__',{}))
    __setattr__ = lambda self, name, value: _swig_setattr(self, devices, name, value)
    __swig_getmethods__ = {}
    for _s in [dff.api.vfs.libvfs.fso]: __swig_getmethods__.update(getattr(_s,'__swig_getmethods__',{}))
    __getattr__ = lambda self, name: _swig_getattr(self, devices, name)
    __repr__ = _swig_repr
    def __init__(self): 
        """
        __init__(devices self) -> devices

        1
        """
        this = _DEVICES.new_devices()
        try: self.this.append(this)
        except: self.this = this
    __swig_destroy__ = _DEVICES.delete_devices
    __del__ = lambda self : None;
    __swig_setmethods__["devicePath"] = _DEVICES.devices_devicePath_set
    __swig_getmethods__["devicePath"] = _DEVICES.devices_devicePath_get
    if _newclass:devicePath = _swig_property(_DEVICES.devices_devicePath_get, _DEVICES.devices_devicePath_set)
    def start(self, *args):
        """
        start(devices self, VMap args)

        This method is called when the module starts. It does the job the module
        is supposed to do. This method is declared as a pure virtual so each modules
        must reiplements it (see the developer's documentations for more details) in
        python or C++, depending on which language you choose.

        The parameter 'args' is a pointer to the arguments list which were passed to the
        module when it was launched. You can get them by using the method
         args->get("arg_name", &variable)
        where variable must be of the same type than the argument "arg_name"

        If you create nodes, you must not forget to call the method register_tree at
        the end of the module execution.

        If an error occured while getting a parameter, a envError exception is thrown.

        Params :
                * args : the list of arguments passed to the module.


        """
        return _DEVICES.devices_start(self, *args)

    def vopen(self, *args):
        """
        vopen(devices self, Node handle) -> int32_t

        Open a node.

        Param :
                * n : the node you want to open

        Return the opened file descriptor, or 0 if it failed.

        """
        return _DEVICES.devices_vopen(self, *args)

    def vread(self, *args):
        """
        vread(devices self, int fd, void * buff, unsigned int size) -> int32_t

        vread(self, int32_t fd, void rbuff, uint32_t size) -> int32_t

        Perform readings on an open node and returns the number of bytes which wereread.

        Params :
                * fd : the file descriptor of the node you want to read on.
                * rbuff : a pointer to an allocated buffer where the read bytes will be stored
                * size : the number of characters you want to read.

        Return the number of read characters.

        """
        return _DEVICES.devices_vread(self, *args)

    def vclose(self, *args):
        """
        vclose(devices self, int fd) -> int32_t

        Close an open file descriptor and make it available again for others
        openings.

        Return `0` if everything went fine, `0` otherwise.

        """
        return _DEVICES.devices_vclose(self, *args)

    def vseek(self, *args):
        """
        vseek(devices self, int fd, uint64_t offset, int whence) -> uint64_t

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

        """
        return _DEVICES.devices_vseek(self, *args)

    def vwrite(self, *args):
        """
        vwrite(devices self, int fd, void * buff, unsigned int size) -> int32_t

        Not used.

        """
        return _DEVICES.devices_vwrite(self, *args)

    def status(self):
        """
        status(devices self) -> uint32_t

        Return the status of the module.

        """
        return _DEVICES.devices_status(self)

    def vtell(self, *args):
        """
        vtell(devices self, int32_t fd) -> uint64_t

        Returns the current offset in a file.

        """
        return _DEVICES.devices_vtell(self, *args)

devices_swigregister = _DEVICES.devices_swigregister
devices_swigregister(devices)

__dff_module_devices_version__ = "1.0.0"

from dff.api.module.module import *
from dff.api.types.libtypes import *
from dff.api.vfs import vfs
class DEVICES(Module):
  """Access devices connected to your computer."""
  def __init__(self):
    Module.__init__(self, 'devices', devices)
    self.tags = "Connectors"  
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node, 
                           "name": "parent", 
                           "description": "Devices will be mount as child of this node or at root node by default.",
                           "parameters": {"type": Parameter.Editable,
                                          "predefined": [vfs.vfs().getnode("/")]}
                          })
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Path,  
                           "name": "path", 
                           "description": "Path to the local device on your operating system."})
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.UInt64,
                        "name": "size",
                        "description": "Size of the device."})
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.String,
                        "name": "name",
                        "description": "Name to associate to the corresponding node."})
    self.icon = ":dev_hd.png"

# This file is compatible with both classic and new-style classes.


