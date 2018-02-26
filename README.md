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
  * Merge modules but need to merge modules/pro/i8n into DFF i18n or remove translation 
  


- Remove dead code (ide etc...)
- Remove unused Qt template generation
- Replace PyQt4 by PyQt5
- Renable the report as QtWebView is available on debian in PyQt5
- add destruct as git submodule (needed to compile in build/)
- compile without -std=c++98
- use swig 3.12 rather than swig 2.11
- remove all deprecated call to dependencies 
- Optionally port it to Python 3 (or for DFF 3 ;)
- Fix all bug reported by differents tools
- Test 
- Document
- Package
- Release 
