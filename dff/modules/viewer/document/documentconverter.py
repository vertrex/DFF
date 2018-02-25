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

import sys, glob, os, subprocess,time 
from distutils.version import LooseVersion

#save python import as uno overwrite it with it's own
import __builtin__
pythonImporter = __builtin__.__dict__["__import__"]

from unoimporter import UnoImporter
office = UnoImporter().importUno()

import uno, unohelper

from com.sun.star.beans import PropertyValue
from com.sun.star.connection import NoConnectException
from com.sun.star.document.UpdateDocMode import QUIET_UPDATE
from com.sun.star.lang import DisposedException, IllegalArgumentException
from com.sun.star.io import IOException, XOutputStream
from com.sun.star.script import CannotConvertException
from com.sun.star.uno import Exception as UnoException
from com.sun.star.uno import RuntimeException

#restore python import
__builtin__.__dict__["__import__"] = pythonImporter 

class OutputStream(unohelper.Base, XOutputStream):
   def __init__( self ):
        self.closed = 0
        self.buff = ""

   def closeOutput(self):
         self.closed = 1

   def writeBytes(self, seq):
         try:
           self.buff += seq.value
         except AttributeError as e:
           pass  

   def flush(self):
         pass

class DocumentConverter(object):
  TypeFilter = { 
               #"document" : "writer_pdf_Export",
               #"web" : "writer_web_pdf_Export",
               #"spreedsheet": "calc_pdf_Export",
               #"graphics": "draw_pdf_Export",
               #"presentation": "impress_pdf_Export", 

               "document/rtf" : "writer_pdf_Export",

               "document/word" : "writer_pdf_Export", 
               "document/powerpoint" : "impress_pdf_Export",
               "document/excel": "calc_pdf_Export",
            
               "document/ooffice-document" : "writer_pdf_Export",
               "document/ooffice-presentation": "impress_pdf_Export",
               "document/ooffice-impress": "impress_pdf_Export",
               "document/ooffice-spreadsheet": "calc_pdf_Export",
               "document/ooffice-calc": "calc_pdf_Export",
               "document/ooffice-draw": "draw_pdf_Export",

               "document/opendocument-text" : "writer_pdf_Export",
               "document/opendocument-presentation": "impress_pdf_Export",
               "document/opendocument-spreadsheet" : "calc_pdf_Export",
               "document/opendocument-text-web" : "writer_web_pdf_Export",
               "document/opendocument-graphics" : "draw_pdf_Export",

               "doc" : "writer_pdf_Export",
               "ppt" : "impress_pdf_Export",
               "xls" : "calc_pdf_Export",

               "odt" : "writer_pdf_Export",
               "odp" : "impress_pdf_Export",
               "stc" : "calc_pdf_Export",
             }
  def __init__(self):
     self.connection = "socket,host=127.0.0.1,port=2002,tcpNoDelay=1;urp;StarOffice.ComponentContext" 
     self.getContext()
 
  def unoProps(self, **args):
    props = []
    for key in args:
      prop = PropertyValue()
      prop.Name = key
      prop.Value = args[key]
      props.append(prop)
    return tuple(props)
 
  def getFilterName(self, node):
     dataType = node.dataType()
     try:
       return self.TypeFilter[dataType]
     except:
       pass
     try:
       return self.TypeFilter[node.extension()]
     except:
       pass 

  def getContext(self):
     self.context = uno.getComponentContext()
     self.svcmgr = self.context.ServiceManager
     resolver = self.svcmgr.createInstanceWithContext("com.sun.star.bridge.UnoUrlResolver", self.context)
     unocontext = self.connect(resolver)
     if not unocontext:
        raise("Unable to connect or start own listener. Aborting.")
     unosvcmgr = unocontext.ServiceManager
     self.desktop = unosvcmgr.createInstanceWithContext("com.sun.star.frame.Desktop", unocontext)

  def connect(self, resolver):
    unocontext = None
    try:
      unocontext = resolver.resolve("uno:%s" % self.connection)
    except NoConnectException as e:
      try:
        product = self.svcmgr.createInstance("com.sun.star.configuration.ConfigurationProvider").createInstanceWithArguments("com.sun.star.configuration.ConfigurationAccess", self.unoProps(nodepath="/org.openoffice.Setup/Product"))
        if product.ooName not in ('LibreOffice', 'LOdev') or LooseVersion(product.ooSetupVersion) <= LooseVersion('3.3'):
          ooproc = subprocess.Popen([office.binary, "-headless", "-invisible", "-nocrashreport", "-nodefault", 
                                      "-nofirststartwizard", "-nologo", "-norestore", "-accept=%s" % self.connection],
                                       env=os.environ)
        else:
          ooproc = subprocess.Popen([office.binary, "--headless", "--invisible", "--nocrashreport", "--nodefault",
                                      "--nofirststartwizard", "--nologo", "--norestore", "--accept=%s" % self.connection], 
                                      env=os.environ)
        timeout = 0
        while timeout <= 6:
          retcode = ooproc.poll()
          if retcode == 81:
            #print "Caught exit code 81 (new installation). Restarting listener."
            return self.connect(resolver)
            break
          elif retcode != None:
            #print "Process %s (pid=%s) exited with %s." % (office.binary, ooproc.pid, retcode)
            break
          try:
            unocontext = resolver.resolve("uno:%s" % self.connection)
            break
          except NoConnectException:
            time.sleep(0.5)
            timeout += 0.5
          except:
            raise
        #else:
          #print("Failed to connect to %s (pid=%s) in %d seconds.\n%s" % (office.binary, ooproc.pid, op.timeout, e))
      except Exception as e:
        raise ("Launch of %s failed.\n%s" % (office.binary, e))
    return unocontext

  def doConvert(self, buff):
     inputprops = self.unoProps(Hidden=True, ReadOnly=True, UpdateDocMode=QUIET_UPDATE)
     inputStream = self.svcmgr.createInstanceWithContext("com.sun.star.io.SequenceInputStream", self.context)
     inputStream.initialize((uno.ByteSequence(buff),)) #Use stream from node ?
     inputprops += self.unoProps(InputStream=inputStream)
     inputurl = 'private:stream'
     document = self.desktop.loadComponentFromURL(inputurl , "_blank", 0, inputprops)
     if not document:
        raise Exception("The document could not be opened.")
     outputStream = OutputStream()                                       
     outputprops = self.unoProps(FilterName=self.filterName, OutputStream=outputStream, Overwrite=True)
     outputurl = "private:stream"
     try:
        document.storeToURL(outputurl, tuple(outputprops))
     except IOException as e:
        raise Exception("Unable to store document to %s (ErrCode %d)\n\nProperties: %s" % (outputurl, e.ErrCode, outputprops), None)

     document.dispose()
     document.close(True)
     return outputStream.buff 

  def convert(self, node):
     self.filterName = self.getFilterName(node)
     if not self.filterName:
       raise Exception("Unsuported document type")
     file = node.open()
     buffer = file.read()
     file.close()
     return self.doConvert(buffer)
