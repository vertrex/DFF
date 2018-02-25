/* 
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 * 
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
 *  Solal Jacob <sja@digital-forensic.org>
 */

%module agent
 
%include "windows.i"
%include "exception.i"

%{
#include "rootnode.hpp"
#include "exceptions.hpp"
#include "agent.hpp"
#include "mfso.hpp"
%}

%import "../../../../api/vfs/libvfs.i"

%ignore AgentCache;
%ignore Agent::open;
#%ignore Agent::rootNode;
%ignore Agent::createNode;
%ignore DeviceFdInfo;
%ignore Agent::vreadSmall;
%clear (DFF::Node*);

%include "agent.hpp"

%pythoncode
%{
from dff.api.module.module import * 
from dff.api.types.libtypes import * 
from dff.api.destruct import DStructs


imp = DStructs().find("Import").newObject() #XXX elswhere
imp.file("dff/api/destruct/examples/modules/libdestruct_rpczmq.so")
imp.file("dff/api/destruct/examples/modules/libdestruct_threading.so")
imp.file("dff/api/destruct/examples/modules/libdestruct_device.so")
 
class agent(Module):
  def __init__(self):
    Module.__init__(self, 'agent', Agent)
    self.conf.addArgument({"name": "host",
                           "input": Argument.Required|Argument.Single|typeId.String,
                           "description": "IP Address of the agent",
                           "parameters":   
                           {"type" :   Parameter.Editable,
                           "predefined": ["10.42.1.195"]}

                          })
    self.conf.addArgument({"name": "port",
                           "input": Argument.Required|Argument.Single|typeId.UInt32,
                           "description": "Port of the DFF agent",
                           "parameters":   
                           {"type" :   Parameter.Editable,
                           "predefined": ["3583"]}
                          })
    self.conf.addArgument({"input": Argument.Optional|Argument.Single|typeId.Node, 
                           "name": "parent", 
                           "description": "files or folders will be added as child(ren) of this node or as the root node by default",
                           "parameters": {"type": Parameter.Editable,
                           "predefined": [vfs.vfs().getnode("/")]}
                          })
    self.conf.description = "Connect to a distant PC devices."
    self.tags = "Connectors"
    #self.icon = ":password.png"
%}
