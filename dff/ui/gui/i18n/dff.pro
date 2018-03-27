# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
#
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

FORMS           += ../../../ui/gui/resources/about.ui
FORMS           += ../../../ui/gui/resources/applymodule.ui
FORMS           += ../../../ui/gui/resources/attributes_selection_dialog.ui
FORMS           += ../../../ui/gui/resources/bookmarkdialog.ui
FORMS           += ../../../ui/gui/resources/browser_toolbar.ui
FORMS           += ../../../ui/gui/resources/devicesdialog.ui
FORMS           += ../../../ui/gui/resources/dico_manager.ui
FORMS           += ../../../ui/gui/resources/errors.ui
FORMS           += ../../../ui/gui/resources/evidencedialog.ui
FORMS           += ../../../ui/gui/resources/extractdialog.ui
FORMS           += ../../../ui/gui/resources/filter_add.ui
FORMS           += ../../../ui/gui/resources/filter_attributes.ui
FORMS           += ../../../ui/gui/resources/filter_bar.ui
FORMS           += ../../../ui/gui/resources/filter_conjunction.ui
FORMS           += ../../../ui/gui/resources/filter_dico.ui
FORMS           += ../../../ui/gui/resources/filter_fields.ui
FORMS           += ../../../ui/gui/resources/filter_matchmode.ui
FORMS           += ../../../ui/gui/resources/filter_mime.ui
FORMS           += ../../../ui/gui/resources/filter_mimedialog.ui
FORMS           += ../../../ui/gui/resources/filter_mode.ui
FORMS           += ../../../ui/gui/resources/filter_only.ui
FORMS           += ../../../ui/gui/resources/filter_operators.ui
FORMS           += ../../../ui/gui/resources/filter_tagwidget.ui
FORMS           += ../../../ui/gui/resources/filter_widget.ui
FORMS           += ../../../ui/gui/resources/interpreter.ui
FORMS           += ../../../ui/gui/resources/is_deleted.ui
FORMS           += ../../../ui/gui/resources/is_file_or_folder.ui
FORMS           += ../../../ui/gui/resources/mainwindow.ui
FORMS           += ../../../ui/gui/resources/modulebrowserdialog.ui
FORMS           += ../../../ui/gui/resources/modulegeneratorwidget.ui
FORMS           += ../../../ui/gui/resources/modules.ui
FORMS           += ../../../ui/gui/resources/node_f_box.ui
FORMS           += ../../../ui/gui/resources/nodeactions.ui
FORMS           += ../../../ui/gui/resources/nodefilterbox.ui
FORMS           += ../../../ui/gui/resources/output.ui
FORMS           += ../../../ui/gui/resources/preferences.ui
FORMS           += ../../../ui/gui/resources/search_customtable.ui
FORMS           += ../../../ui/gui/resources/search_panel.ui
FORMS           += ../../../ui/gui/resources/search_requests.ui
FORMS           += ../../../ui/gui/resources/select_attributes.ui
FORMS           += ../../../ui/gui/resources/selection_actions.ui
FORMS           += ../../../ui/gui/resources/shell.ui
FORMS           += ../../../ui/gui/resources/tagedit.ui
FORMS           += ../../../ui/gui/resources/tags.ui
FORMS           += ../../../ui/gui/resources/taskmanager.ui
FORMS           += ../../../ui/gui/resources/varianttreewidget.ui
FORMS           += ../../../ui/gui/resources/pdf_toolbar.ui
FORMS           += ../../../ui/gui/resources/sqlitemanager.ui

SOURCES         += ../../../ui/gui/widget/propertytable.py
SOURCES         += ../../../ui/gui/widget/dockwidget.py
SOURCES         += ../../../ui/gui/dialog/tagmanager.py
SOURCES         += ../../../ui/gui/dialog/extractor.py
SOURCES         += ../../../ui/gui/dialog/applymodule.py
SOURCES         += ../../../ui/gui/dialog/selectattributes.py
SOURCES         += ../../../ui/gui/model/tree.py
SOURCES         += ../../../ui/gui/widget/layoutmanager.py
SOURCES         += ../../../ui/gui/widget/generateModuleShape.py
SOURCES         += ../../../ui/gui/widget/varianttreewidget.py
SOURCES         += ../../../ui/gui/widget/search/dico_manager.py
SOURCES         += ../../../ui/gui/widget/search/search_widget.py
SOURCES         += ../../../ui/gui/widget/search/thread.py

SOURCES         += ../../../ui/gui/mainwindow.py
SOURCES         += ../../../ui/gui/dialog/preferences.py
SOURCES         += ../../../ui/gui/dialog/dialog.py
SOURCES         += ../../../ui/gui/widget/taskmanager.py
SOURCES         += ../../../ui/gui/widget/preview.py
SOURCES         += ../../../ui/gui/widget/help.py
SOURCES         += ../../../ui/gui/utils/menumanager.py
SOURCES         += ../../../ui/gui/utils/menu.py

TRANSLATIONS    += ../../../ui/gui/i18n/Dff_de.ts
TRANSLATIONS    += ../../../ui/gui/i18n/Dff_en.ts
TRANSLATIONS    += ../../../ui/gui/i18n/Dff_es.ts
TRANSLATIONS    += ../../../ui/gui/i18n/Dff_fr.ts
TRANSLATIONS    += ../../../ui/gui/i18n/Dff_it.ts
TRANSLATIONS    += ../../../ui/gui/i18n/Dff_nl.ts
TRANSLATIONS    += ../../../ui/gui/i18n/Dff_zh.ts
