# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
# This program is free software, distributed under the terms of
# the GNU General Public License Version 2. See the LICENSE file
# at the top of the source tree.
#  
# See http://www.digital-forensic.org for more information about this
# project. Please do not directly contact any of the maintainers of
# DFF for assistance; the project provides a web site, mailing lists
# and IRC channels for your use.
# 
# Author(s):
#  Solal Jacob <sja@digital-forensic.org>
# 
#code borrowed from unoconv : https://github.com/dagwieers/unoconv

import os, sys, subprocess, glob

class Office:
    def __init__(self, basepath, urepath, unopath, pyuno, binary, python, pythonhome):
        self.basepath = basepath
        self.urepath = urepath
        self.unopath = unopath
        self.pyuno = pyuno
        self.binary = binary
        self.python = python
        self.pythonhome = pythonhome

    def __str__(self):
        return self.basepath

    def __repr__(self):
        return self.basepath

class UnoImporter(object):
  def __init__(self):
     pass

  def realpath(self, *args):
    ''' Implement a combination of os.path.join(), os.path.abspath() and
        os.path.realpath() in order to normalize path constructions '''
    ret = ''
    for arg in args:
        ret = os.path.join(ret, arg)
    return os.path.realpath(os.path.abspath(ret))

  def find_offices(self):
    ret = []
    extrapaths = []

    ### Try using UNO_PATH first (in many incarnations, we'll see what sticks)
    if 'UNO_PATH' in os.environ:
        extrapaths += [ os.environ['UNO_PATH'],
                        os.path.dirname(os.environ['UNO_PATH']),
                        os.path.dirname(os.path.dirname(os.environ['UNO_PATH'])) ]

    else:
        if os.name in ( 'nt', 'os2' ):
            if 'PROGRAMFILES' in list(os.environ.keys()):
                extrapaths += glob.glob(os.environ['PROGRAMFILES']+'\\LibreOffice*') + \
                              glob.glob(os.environ['PROGRAMFILES']+'\\OpenOffice.org*')

            if 'PROGRAMFILES(X86)' in list(os.environ.keys()):
                extrapaths += glob.glob(os.environ['PROGRAMFILES(X86)']+'\\LibreOffice*') + \
                              glob.glob(os.environ['PROGRAMFILES(X86)']+'\\OpenOffice.org*')

        elif os.name in ( 'mac', ) or sys.platform in ( 'darwin', ):
            extrapaths += [ '/Applications/LibreOffice.app/Contents',
                            '/Applications/NeoOffice.app/Contents',
                            '/Applications/OpenOffice.app/Contents',
                            '/Applications/OpenOffice.org.app/Contents' ]

        else:
            extrapaths += glob.glob('/usr/lib*/libreoffice*') + \
                          glob.glob('/usr/lib*/openoffice*') + \
                          glob.glob('/usr/lib*/ooo*') + \
                          glob.glob('/opt/libreoffice*') + \
                          glob.glob('/opt/openoffice*') + \
                          glob.glob('/opt/ooo*') + \
                          glob.glob('/usr/local/libreoffice*') + \
                          glob.glob('/usr/local/openoffice*') + \
                          glob.glob('/usr/local/ooo*') + \
                          glob.glob('/usr/local/lib/libreoffice*')

    ### Find a working set for python UNO bindings
    for basepath in extrapaths:
        if os.name in ( 'nt', 'os2' ):
            officelibraries = ( 'pyuno.pyd', )
            officebinaries = ( 'soffice.exe' ,)
            pythonbinaries = ( 'python.exe', )
            pythonhomes = ()
        elif os.name in ( 'mac', ) or sys.platform in ( 'darwin', ):
            officelibraries = ( 'pyuno.so', 'libpyuno.dylib' )
            officebinaries = ( 'soffice.bin', 'soffice')
            pythonbinaries = ( 'python.bin', 'python' )
            pythonhomes = ( 'OOoPython.framework/Versions/*/lib/python*', )
        else:
            officelibraries = ( 'pyuno.so', )
            officebinaries = ( 'soffice.bin', )
            pythonbinaries = ( 'python.bin', 'python', )
            pythonhomes = ( 'python-core-*', )

        ### Older LibreOffice/OpenOffice and Windows use basis-link/ or basis/
        libpath = 'error'
        for basis in ( 'basis-link', 'basis', '' ):
            for lib in officelibraries:
                for libdir in ( 'program', 'Frameworks' ):
                    if os.path.isfile(self.realpath(basepath, basis, libdir, lib)):
                        libpath = self.realpath(basepath, basis, libdir)
                        officelibrary = self.realpath(libpath, lib)
                        #print  "Found %s in %s" % (lib, libpath)
                        # Break the inner loop...
                        break
                # Continue if the inner loop wasn't broken.
                else:
                    continue
                break
            # Continue if the inner loop wasn't broken.
            else:
                continue
            # Inner loop was broken, break the outer.
            break
        else:
            continue

        ### MacOSX have soffice binaries installed in MacOS subdirectory, not program
        unopath = 'error'
        for basis in ( 'basis-link', 'basis', '' ):
            for bin in officebinaries:
                for bindir in ( 'program', 'MacOS' ):
                    if os.path.isfile(self.realpath(basepath, basis, bindir, bin)):
                        unopath = self.realpath(basepath, basis, bindir)
                        officebinary = self.realpath(unopath, bin)
                        #print "Found %s in %s" % (bin, unopath)
                        # Break the inner loop...
                        break
                # Continue if the inner loop wasn't broken.
                else:
                    continue
                break
            # Continue if the inner loop wasn't broken.
            else:
                continue
            # Inner loop was broken, break the outer.
            break
        else:
            continue

        ### Windows does not provide or need a URE/lib directory ?
        urepath = ''
        for basis in ( 'basis-link', 'basis', '' ):
            for ure in ( 'ure-link', 'ure', 'URE', '' ):
                if os.path.isfile(self.realpath(basepath, basis, ure, 'lib', 'unorc')):
                    urepath = self.realpath(basepath, basis, ure)
                    #print "Found %s in %s" % ('unorc', self.realpath(urepath, 'lib'))
                    # Break the inner loop...
                    break
            # Continue if the inner loop wasn't broken.
            else:
                continue
            # Inner loop was broken, break the outer.
            break

        pythonhome = None
        for home in pythonhomes:
            if glob.glob(self.realpath(libpath, home)):
                pythonhome = glob.glob(self.realpath(libpath, home))[0]
                #print "Found %s in %s" % (home, pythonhome)
                break

        for pythonbinary in pythonbinaries:
            if os.path.isfile(self.realpath(unopath, pythonbinary)):
                #print "Found %s in %s" % (pythonbinary, unopath)
                ret.append(Office(basepath, urepath, unopath, officelibrary, officebinary,
                                  self.realpath(unopath, pythonbinary), pythonhome))
        else:
            #print "Considering %s" % basepath
            ret.append(Office(basepath, urepath, unopath, officelibrary, officebinary,
                              sys.executable, None))
    return ret

  def office_environ(self, office):
    ### Set PATH so that crash_report is found
    if 'PATH' in os.environ:
        os.environ['PATH'] = self.realpath(office.basepath, 'program') + os.pathsep + os.environ['PATH']
    else:
        os.environ['PATH'] = self.realpath(office.basepath, 'program')

    ### Set UNO_PATH so that "officehelper.bootstrap()" can find soffice executable:
    os.environ['UNO_PATH'] = office.unopath

    ### Set URE_BOOTSTRAP so that "uno.getComponentContext()" bootstraps a complete
    ### UNO environment
    if os.name in ( 'nt', 'os2' ):
        os.environ['URE_BOOTSTRAP'] = 'vnd.sun.star.pathname:' + self.realpath(office.basepath, 'program', 'fundamental.ini')
    else:
        os.environ['URE_BOOTSTRAP'] = 'vnd.sun.star.pathname:' + self.realpath(office.basepath, 'program', 'fundamentalrc')

        ### Set LD_LIBRARY_PATH so that "import pyuno" finds libpyuno.so:
        if 'LD_LIBRARY_PATH' in os.environ:
            os.environ['LD_LIBRARY_PATH'] = office.unopath + os.pathsep + \
                                            self.realpath(office.urepath, 'lib') + os.pathsep + \
                                            os.environ['LD_LIBRARY_PATH']
        else:
            os.environ['LD_LIBRARY_PATH'] = office.unopath + os.pathsep + \
                                            self.realpath(office.urepath, 'lib')

    if office.pythonhome:
        for libpath in ( self.realpath(office.pythonhome, 'lib'),
                         self.realpath(office.pythonhome, 'lib', 'lib-dynload'),
                         self.realpath(office.pythonhome, 'lib', 'lib-tk'),
                         self.realpath(office.pythonhome, 'lib', 'site-packages'),
                         office.unopath):
            sys.path.insert(0, libpath)
    else:
        ### Still needed for system python using LibreOffice UNO bindings
        ### Although we prefer to use a system UNO binding in this case
        sys.path.append(office.unopath)

  def python_switch(self, office):
    if office.pythonhome:
        os.environ['PYTHONHOME'] = office.pythonhome
        os.environ['PYTHONPATH'] = self.realpath(office.pythonhome, 'lib') + os.pathsep + \
                                   self.realpath(office.pythonhome, 'lib', 'lib-dynload') + os.pathsep + \
                                   self.realpath(office.pythonhome, 'lib', 'lib-tk') + os.pathsep + \
                                   self.realpath(office.pythonhome, 'lib', 'site-packages') + os.pathsep + \
                                   office.unopath

    os.environ['UNO_PATH'] = office.unopath

    #print "-> Switching from %s to %s" % (sys.executable, office.python)
    if os.name in ('nt', 'os2'):
        ### os.execv is broken on Windows and can't properly parse command line
        ### arguments and executable name if they contain whitespaces. subprocess
        ### fixes that behavior.
        ret = subprocess.call([office.python, ] + sys.argv[0:])
        sys.exit(ret)
    else:

        ### Set LD_LIBRARY_PATH so that "import pyuno" finds libpyuno.so:
        if 'LD_LIBRARY_PATH' in os.environ:
            os.environ['LD_LIBRARY_PATH'] = office.unopath + os.pathsep + \
                                            self.realpath(office.urepath, 'lib') + os.pathsep + \
                                            os.environ['LD_LIBRARY_PATH']
        else:
            os.environ['LD_LIBRARY_PATH'] = office.unopath + os.pathsep + \
                                            self.realpath(office.urepath, 'lib')

        try:
            os.execvpe(office.python, [office.python, ] + sys.argv[0:], os.environ)
        except OSError:
            ### Mac OS X versions prior to 10.6 do not support execv in
            ### a process that contains multiple threads.  Instead of
            ### re-executing in the current process, start a new one
            ### and cause the current process to exit.  This isn't
            ### ideal since the new process is detached from the parent
            ### terminal and thus cannot easily be killed with ctrl-C,
            ### but it's better than not being able to autoreload at
            ### all.
            ### Unfortunately the errno returned in this case does not
            ### appear to be consistent, so we can't easily check for
            ### this error specifically.
            ret = os.spawnvpe(os.P_WAIT, office.python, [office.python, ] + sys.argv[0:], os.environ)
            sys.exit(ret)

  def importUno(self):
    for of in self.find_offices():
        if of.python != sys.executable and not sys.executable.startswith(of.basepath):
            self.python_switch(of)
        self.office_environ(of)
        try:
            return  of
            break
        except:
            raise ("unoconv: Cannot find a suitable pyuno library and python binary combination in %s", of)
    else:
        raise ("unoconv: Cannot find a suitable office installation on your system.")
