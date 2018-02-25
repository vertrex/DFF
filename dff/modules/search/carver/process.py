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
#  Frederic B. <fba@digital-forensic.org>
import string
import time
from typeSelection import filetypes

from PyQt4.QtGui import QWidget, QVBoxLayout, QGridLayout, QLabel, QProgressBar, QHBoxLayout, QCheckBox, QPushButton, QTabWidget, QSplitter, QMessageBox
from PyQt4.Qt import SIGNAL

from dff.api.module.module import Module
from dff.api.module.script import Script
from dff.api.events.libevents import EventHandler, event
from dff.api.types.libtypes import typeId, Argument, Parameter, VList, VMap, Variant
from dff.api.taskmanager.taskmanager import TaskManager

from dff.modules.carver.utils import QFFSpinBox
from dff.modules.carver.CARVER import Carver

class CarvingProcess(QWidget, EventHandler):
    def __init__(self, selector, vnode):
        QWidget.__init__(self)
        EventHandler.__init__(self)
        self.vnode = vnode.value()
        self.filesize = self.vnode.size()
        self.tm = TaskManager()
        self.selector = selector
        self.setLayout(QVBoxLayout())
        self.factor = 1
        self.parsetime = 0
        self.time = time.time()
        self.starttime = time.time()
        self.createStartOffset()
        self.createButtons()
        self.createStateInfo()


    def createStartOffset(self):
        self.offsetLayout = QHBoxLayout()
        self.offsetSpinBox = QFFSpinBox(self)
        self.offsetSpinBox.setMinimum(0)
        self.offsetSpinBox.setMaximum(self.filesize)
        self.offsetLabel = QLabel("start offset:")
        self.offsetLayout.addWidget(self.offsetLabel)
        self.offsetLayout.addWidget(self.offsetSpinBox)
        self.layout().addLayout(self.offsetLayout)


    def createButtons(self):
        self.startButton = QPushButton("Start")
        self.stopButton = QPushButton("Stop")
        self.stopButton.setEnabled(False)
        self.connect(self.stopButton, SIGNAL("clicked()"), self.stopCarving)
        self.connect(self.startButton, SIGNAL("clicked()"), self.startCarving)
        self.connect(self, SIGNAL("ended"), self.carvingEnded)
        self.buttonLayout = QHBoxLayout()
        self.buttonLayout.addWidget(self.startButton)
        self.buttonLayout.addWidget(self.stopButton)
        self.layout().addLayout(self.buttonLayout)


    def createStateInfo(self):
        self.stateLayout = QVBoxLayout()

        self.overallLayout = QHBoxLayout()
        self.currentLabel = QLabel("Overall progress :")
        self.currentProgress = QProgressBar()
        self.overallLayout.addWidget(self.currentLabel)
        self.overallLayout.addWidget(self.currentProgress)
        self.stateLayout.addLayout(self.overallLayout)

        self.elapsedLabel = QLabel("elapsed time:    00d00h00m00s")
        self.stateLayout.addWidget(self.elapsedLabel)
        self.estimatedLabel = QLabel("estimated time: 00d00h00m00s")
        self.stateLayout.addWidget(self.estimatedLabel)
        self.totalLabel = QLabel("total headers found: 0")
        self.stateLayout.addWidget(self.totalLabel)
        self.stateLayout.setEnabled(False)
        self.layout().addLayout(self.stateLayout)


    def createContext(self, selected):
        lpatterns = VList()
        for filetype in selected.iterkeys():
            patterns = selected[filetype][0]
            aligned = selected[filetype][1]
            for pattern in patterns:
                vpattern = VMap()
                vpattern["filetype"] = Variant(filetype, typeId.String)

                header = VMap()
                header["needle"] = Variant(pattern[0], typeId.String)
                header["size"] = Variant(len(pattern[0]), typeId.UInt32)

                footer = VMap()
                footer["needle"] = Variant(pattern[1], typeId.String)
                footer["size"] = Variant(len(pattern[1]), typeId.UInt32)

                vpattern["header"] = Variant(header)
                vpattern["footer"] = Variant(footer)
                vpattern["window"] = Variant(int(pattern[2]), typeId.UInt32)
                vpattern["aligned"] = Variant(aligned, typeId.Bool)
                lpatterns.append(vpattern)
        return lpatterns



    def startCarving(self):
        selected = self.selector.selectedItems()
        if len(selected):
            try:
                f = self.vnode.open()
                f.close()
            except:
                mbox = QMessageBox(QMessageBox.Warning, 
                                   self.tr("Carver bad input"),
                                   self.tr("The provided input file seems to be a directory. Please, apply the module on a file"),
                                   QMessageBox.Ok, self)
                mbox.exec_()
                return
            patterns = self.createContext(selected)
            args = VMap()
            args["patterns"] = Variant(patterns)
            args["file"] = Variant(self.vnode)
            args["start-offset"] = Variant(self.offsetSpinBox.value(), typeId.UInt64)
            factor = round(float(self.filesize) / 2147483647)
            self.startButton.setEnabled(False)
            self.stopButton.setEnabled(True)
            self.stopButton.setDown(False)
            if factor == 0:
                factor = 1
            proc = self.tm.add("carver", args, ["gui", "thread"])
            if proc:
                self.doJob(self.filesize, factor, self.offsetSpinBox.value())
                self.stateLayout.setEnabled(True)
                self.connection(proc.inst)
                proc.inst.connection(self)
                #self.connect(self, SIGNAL("stateInfo(QString)"), self.setStateInfo)
        else:
            mbox = QMessageBox(QMessageBox.Warning, 
                               self.tr("Carver no items selected"),
                               self.tr("No items have been provided to know what to look for. Please chose types you want to search."),
                               QMessageBox.Ok, self)
            mbox.exec_()
            return
            


    def carvingEnded(self, res):
        #results = str(res).split("\n")
        #print results
        #for item in results:
        #    begidx = item.find(":")
        #    self.res.add_const(str(item[:begidx]), str(item[begidx+1:] + "\n"))
        self.startButton.setEnabled(True)
        self.stopButton.setEnabled(False)
        self.stateLayout.setEnabled(False)


    def stopCarving(self):
        self.killJob()
        self.stopButton.setDown(True)


    def strtime(self, day, hour, min, sec):
        day = str(day)
        hour = str(hour)
        min = str(min)
        sec = str(sec)
        res = "0" * (2-len(day)) + day + "d" + "0" * (2-len(hour)) + hour + "h" + "0" * (2-len(min)) + min + "m" + "0" * (2-len(sec)) + sec + "s"
        return res


    def timesec2str(self, timesec):
        day = hour = min = sec = 0
        if timesec > 3600 * 24:
            day = timesec / (3600 * 24)
            timesec = timesec % (3600 * 24)
        if timesec > 3600:
            hour = timesec / 3600
            timesec = timesec % 3600
        if timesec > 60:
            min = timesec / 60
            timesec = timesec % 60
        sec = timesec
        res = self.strtime(int(day), int(hour), int(min), int(sec))
        return res


    def Event(self, e):
        if e.type == Carver.Position:
            self.emit(SIGNAL("updatePosition"), e)
        elif e.type == Carver.Matches:
            self.emit(SIGNAL("updateMatches"), e)
        elif e.type == Carver.EndOfProcessing:
            self.emit(SIGNAL("ended"), "")


    def updatePosition(self, e):
        ref = time.time() - self.time
        self.time = time.time()
        if not str(ref).startswith("0.0"):
            ref *= self.parsetime
            res = self.timesec2str(ref)
            self.estimatedLabel.setText("estimated time: " + res)
        res = self.timesec2str(time.time() - self.starttime)
        self.elapsedLabel.setText("elapsed time:    " + res)
        i = int(e.value.value() / self.factor)
        if i > 2147483647:
            i = 2147483647
        self.emit(SIGNAL("valueChanged(int)"), i)
        info = self.currentProgress.text() + " - " + self.totalLabel.text()
        self.emit(SIGNAL("stateInfo(QString)"), info)


    def updateMatches(self, e):
        self.totalLabel.setText("total headers found: " + str(e.value))
            


    def doJob(self, filesize, factor, start):
        self.factor = factor
        self.parsetime = filesize / (10*1204*1024)
        self.elapsedLabel.setText("elapsed time:    00d00h00m00s")
        self.estimatedLabel.setText("estimated time: 00d00h00m00s")
        self.totalLabel.setText("total headers found: 0")
        maxrange = int(filesize / self.factor)
        if maxrange > 2147483647:
            maxrange = 2147483647
        self.currentProgress.setRange(0, maxrange)
        self.currentProgress.setValue(0)
        self.connect(self, SIGNAL("valueChanged(int)"), self.currentProgress.setValue)
        self.time = time.time()
        self.starttime = time.time()
        self.connect(self, SIGNAL("updateMatches"), self.updateMatches)
        self.connect(self, SIGNAL("updatePosition"), self.updatePosition)


    def killJob(self):
        e = event()
        e.thisown = False
        e.type = Carver.Stop
        self.notify(e)
