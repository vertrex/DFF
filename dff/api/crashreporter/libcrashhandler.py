# This file was automatically generated by SWIG (http://www.swig.org).
# Version 2.0.9
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
            fp, pathname, description = imp.find_module('_libcrashhandler', [dirname(__file__)])
        except ImportError:
            import _libcrashhandler
            return _libcrashhandler
        if fp is not None:
            try:
                _mod = imp.load_module('_libcrashhandler', fp, pathname, description)
            finally:
                fp.close()
            return _mod
    _libcrashhandler = swig_import_helper()
    del swig_import_helper
else:
    import _libcrashhandler
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
    __swig_destroy__ = _libcrashhandler.delete_SwigPyIterator
    __del__ = lambda self : None;
    def value(self): return _libcrashhandler.SwigPyIterator_value(self)
    def incr(self, n=1): return _libcrashhandler.SwigPyIterator_incr(self, n)
    def decr(self, n=1): return _libcrashhandler.SwigPyIterator_decr(self, n)
    def distance(self, *args): return _libcrashhandler.SwigPyIterator_distance(self, *args)
    def equal(self, *args): return _libcrashhandler.SwigPyIterator_equal(self, *args)
    def copy(self): return _libcrashhandler.SwigPyIterator_copy(self)
    def next(self): return _libcrashhandler.SwigPyIterator_next(self)
    def __next__(self): return _libcrashhandler.SwigPyIterator___next__(self)
    def previous(self): return _libcrashhandler.SwigPyIterator_previous(self)
    def advance(self, *args): return _libcrashhandler.SwigPyIterator_advance(self, *args)
    def __eq__(self, *args): return _libcrashhandler.SwigPyIterator___eq__(self, *args)
    def __ne__(self, *args): return _libcrashhandler.SwigPyIterator___ne__(self, *args)
    def __iadd__(self, *args): return _libcrashhandler.SwigPyIterator___iadd__(self, *args)
    def __isub__(self, *args): return _libcrashhandler.SwigPyIterator___isub__(self, *args)
    def __add__(self, *args): return _libcrashhandler.SwigPyIterator___add__(self, *args)
    def __sub__(self, *args): return _libcrashhandler.SwigPyIterator___sub__(self, *args)
    def __iter__(self): return self
SwigPyIterator_swigregister = _libcrashhandler.SwigPyIterator_swigregister
SwigPyIterator_swigregister(SwigPyIterator)

class CrashHandler(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, CrashHandler, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, CrashHandler, name)
    __repr__ = _swig_repr
    def __init__(self): 
        this = _libcrashhandler.new_CrashHandler()
        try: self.this.append(this)
        except: self.this = this
    __swig_destroy__ = _libcrashhandler.delete_CrashHandler
    __del__ = lambda self : None;
    def setSilentReport(self, *args): return _libcrashhandler.CrashHandler_setSilentReport(self, *args)
    def setVersion(self, *args): return _libcrashhandler.CrashHandler_setVersion(self, *args)
    def setHandler(self): return _libcrashhandler.CrashHandler_setHandler(self)
    def unsetHandler(self): return _libcrashhandler.CrashHandler_unsetHandler(self)
CrashHandler_swigregister = _libcrashhandler.CrashHandler_swigregister
CrashHandler_swigregister(CrashHandler)

# This file is compatible with both classic and new-style classes.


