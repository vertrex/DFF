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
#  Christophe Malinge <cma@digital-forensic.org>
# 
import sys, os

from PyQt4.QtCore import QCoreApplication, QTranslator, QLibraryInfo

from dff.ui.conf import Conf

class Translator():
    """ This singleton class handle Qt and DFF translations
    """
    class __Translator():
        def __init__(self):
            self.translators = {}
            self.conf = Conf()
            if hasattr(sys, "frozen"):
                translationPath = os.path.abspath(os.path.join(os.path.dirname(sys.executable), "resources/i18n"))
                self.addTranslationPath(os.path.join(translationPath, "qt_"))
                self.addTranslationPath(os.path.join(translationPath, "Dff_"))
            else:
               self.addTranslationPath(os.path.join(unicode(QLibraryInfo.location(QLibraryInfo.TranslationsPath)), "qt_"))
               self.addTranslationPath("dff/ui/gui/i18n/Dff_")
            self.loadLanguage()

        def addTranslationPath(self, path):
            translator = QTranslator()
            QCoreApplication.installTranslator(translator)
            self.translators[translator] = path

        def currentLanguage(self):
            return str(self.conf.getLanguage()).lower()[:2]

        def loadLanguage(self, language = None):
            if language == None:
              language = self.currentLanguage() 

            for translator in self.translators:
               self.translators[translator] + language
               translator.load(self.translators[translator] + language)

    __instance = None
    
    def __init__(self):
        if Translator.__instance is None:
            Translator.__instance = Translator.__Translator()
            
    def __setattr__(self, attr, value):
	setattr(self.__instance, attr, value)
  
    def __getattr__(self, attr):
        return getattr(self.__instance, attr)
