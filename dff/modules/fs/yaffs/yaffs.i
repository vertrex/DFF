%module yaffs 

%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "std_vector.i"
%include "windows.i"

%ignore YAFFS::parent;
%ignore YAFFS::yaffs;
%ignore YAFFS::root;
%ignore YAFFS::deleted;
%ignore YAFFS::unlinked;
%ignore YAFFS::lostnfound;
%ignore YAFFS::orphaned;

%{
#include "exceptions.hpp"
#include "rootnode.hpp"

#include "yaffs.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "yaffs.hpp"

%pythoncode
%{
from dff.api.module.module import *
from dff.api.types.libtypes import * 

class yaffs(Module):
  def __init__(self):
    Module.__init__(self, 'yaffs', YAFFS)
    self.conf.addArgument({"name": "file",
                           "description": "Path to a file containing YAFFS",
                           "input": Argument.Required|Argument.Single|typeId.Node})

    self.conf.description = "Creates a tree from a YAFFS file system."
    self.tags = "File systems"
%}
