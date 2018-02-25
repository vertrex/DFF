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
#  Jeremy Mounier <jmo@digital-forensic.org>
# 
from PyQt4.QtGui import *
from PyQt4.QtCore import *

from dff.ui.gui.utils.utils import Utils
from dff.ui.gui.resources.ui_idewizard import Ui_IdeWizard

class IdeWizard(QWizard, Ui_IdeWizard):
    def __init__(self, mainWindow):
        super(IdeWizard,  self).__init__(mainWindow)
        self.main = mainWindow
        self.setupUi(self)
        self.translation()
        
        pix = QPixmap(":script-new.png")
        self.introPage.setPixmap(QWizard.LogoPixmap, pix)
        self.introPage.registerField("typeS", self.type_script)
        self.introPage.registerField("typeG", self.type_graphical)
        self.introPage.registerField("typeD", self.type_driver)
        self.introPage.registerField("name*", self.name)
        self.introPage.registerField("path*", self.path)
        
        self.descriptionPage.setPixmap(QWizard.LogoPixmap, pix)
        self.descriptionPage.registerField("description", self.description, "plainText")
        
        self.authorPage.setPixmap(QWizard.LogoPixmap, pix)
        self.authorPage.registerField("authFName*", self.auth_fname)
        self.authorPage.registerField("authLName*", self.auth_lname)
        self.authorPage.registerField("authMail*", self.auth_mail)
        
        self.tags = []
        setags = Utils.getSetTags()
        for tag in setags:
            if not tag == "builtins":
                self.tags.append(tag)
                self.category.addItem(QString(tag))

        self.connect(self.brwButton, SIGNAL("clicked()"), self.browseBack)
        
    def browseBack(self):
        dirName = QFileDialog.getExistingDirectory(self, self.locationTitle)
        self.path.setText(dirName)

    def translation(self):
        self.locationTitle = self.tr("Location")
        
    def changeEvent(self, event):
        """ Search for a language change event

        This event have to call retranslateUi to change interface language on
        the fly.
        """
        if event.type() == QEvent.LanguageChange:
            self.retranslateUi(self)
            self.translation()
        else:
            QWizard.changeEvent(self, event)


