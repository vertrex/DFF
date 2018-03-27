DFF 2 : 
=======

DFF 2 is a new version of DFF. It include ArxSys dff-pro enhancement and modules.
The goal is to have a fresh project that can be compiled easily on lastest linux distro, is stable and documented. 
For that the first step is to port DFF GUI to PyQt5, make the compilation tool use the lastest version of dependencies, and document the API. 
Once the main goal will be achieved, DFF 2 could replace DFF and new features could be added to the project.

TODO :  
------

- add lacking CMakeList (needed to compile in build/ ex:export.csv) : Done

- Push a dff version in a new git without submodules (they will maybe come back later) : Done

- Merge pro in dff (remove the /pro directory and merge the inherited classes) better to do before porting to Qt5 or we will port code that will be merged ... :
  * Merge pro/modules in dff/modules : Done
    XXX (but need to merge modules/pro/i8n into DFF i18n or remove translation)
    XXX need to rework on modules/__init__.py it was usefull whith multiple module path but now it's make seem more weird (base module base must not be filled)
  * Merge dff/pro/api in dff/api
    XXX dff/ui/gui/i18n/CMakeLists.txt
    Merge done but need test (Ex: report button appear in error output but not in taskmanager)

- add destruct as git submodule (needed to compile in build/) : Done
  In fact remove destruct dependencies as it's not needed in this version (just for the agent)

- merge pro api/gui & ui/gui : done
  XXX scan -> report never finish so there is no total time (maybe because there is no webkit) but all module is in finish or failed state

- use swig 3.12 rather than swig 2.11 : seem to work by default ?? : done ?


- move api/gui in ui/gui as there was never a real gui api
- Remove dead code (ide etc...)
- Remove unused Qt template generation
- Replace PyQt4 by PyQt5 (change Qt4 signal to Qt5 signal, use PyQt API V2 then use Qt5)
- Renable the report as QtWebView is available on debian in PyQt5

- compile without -std=c++98
- add : dff-extractor & dff-auto-report & unsuported module & other things from sides project
- remove all deprecated call to dependencies 
- Optionally port it to Python 3 (or for DFF 3 ;)
- Fix all bug reported by differents tools
- Test 
- Document
- Package
- Release 
