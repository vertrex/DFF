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
#  Solal Jacob <sja@digital-forensic.org>
# 

__dff_module_player_version__ = "1.0.0"

from PyQt4.QtGui import QWidget, QAction, QStyle, QToolBar, QLabel, QPalette, QPixmap, QLCDNumber, QSizePolicy, QHBoxLayout, QVBoxLayout, QMessageBox
from PyQt4.QtCore import SIGNAL, SLOT, QTime, Qt
from PyQt4.phonon import Phonon 

from dff.api.module.script import Script 
from dff.api.module.module import Module
from dff.api.vfs.iodevice import IODevice
from dff.api.types.libtypes import Argument, typeId
from dff.api.vfs import *

#avoid bug in phonon
audio = None
video = None
media = None

class PLAYER(QWidget, Script):
  def __init__(self):
     Script.__init__(self, "player")
     self.vfs = vfs.vfs() 


  def start(self, args):
    try:
      self.node = args["file"].value()
    except:
      pass

  def closeEvent(self, event):
     media.stop()
     media.clearQueue()
     self.src.close()

  def updateWidget(self):
    pass

  def g_display(self):
     QWidget.__init__(self)
     global audio,video,media
     if media is None:
       media = Phonon.MediaObject(self)
       video = Phonon.VideoWidget(self)
       audio = Phonon.AudioOutput(Phonon.MusicCategory, self)
       media.setTickInterval(1000)
       media.tick.connect(self.tick)
       Phonon.createPath(media, video)
       Phonon.createPath(media, audio)
     media.stateChanged.connect(self.stateChanged)
     self.setupActions()
     self.setupUi()
     self.timeLcd.display("00:00") 
     self.play(self.node)

  def play(self, node):
     wasPlaying = (media.state() == Phonon.PlayingState)
     media.stop()
     media.clearQueue()
     self.src = IODevice(node)
     source = Phonon.MediaSource(self.src)
     if source.type() != -1:
	media.setCurrentSource(source)
        if  wasPlaying:
          media.play()
        else :
	  media.stop()
     else:
	print "error can find file"

  def tick(self, time):
        displayTime = QTime(0, (time / 60000) % 60, (time / 1000) % 60)
        self.timeLcd.display(displayTime.toString('mm:ss'))

  def stateChanged(self, newState, oldState):
        if newState == Phonon.ErrorState:
	    pass
            #if media.errorType() == Phonon.FatalError:
                #QMessageBox.warning(self, "Fatal Error",
                        #media.errorString())
            #else:
                #QMessageBox.warning(self, "Error",
                        #media.errorString())

        elif newState == Phonon.PlayingState:
            self.playAction.setEnabled(False)
            self.pauseAction.setEnabled(True)
            self.stopAction.setEnabled(True)

        elif newState == Phonon.StoppedState:
            self.stopAction.setEnabled(False)
            self.playAction.setEnabled(True)
            self.pauseAction.setEnabled(False)
            self.timeLcd.display("00:00")

        elif newState == Phonon.PausedState:
            self.pauseAction.setEnabled(False)
            self.stopAction.setEnabled(True)
            self.playAction.setEnabled(True)


  def setupActions(self):
        self.playAction = QAction(
                self.style().standardIcon(QStyle.SP_MediaPlay), "Play",
                self, shortcut="Ctrl+P", enabled=False,
                triggered=media.play)

        self.pauseAction = QAction(
                self.style().standardIcon(QStyle.SP_MediaPause),
                "Pause", self, shortcut="Ctrl+A", enabled=False,
                triggered=media.pause)

        self.stopAction = QAction(
                self.style().standardIcon(QStyle.SP_MediaStop), "Stop",
                self, shortcut="Ctrl+S", enabled=False,
                triggered=media.stop)

        self.nextAction = QAction(
                self.style().standardIcon(QStyle.SP_MediaSkipForward),
                "Next", self, shortcut="Ctrl+N")

        self.previousAction = QAction(
                self.style().standardIcon(QStyle.SP_MediaSkipBackward),
                "Previous", self, shortcut="Ctrl+R")

  def setupUi(self):
        bar = QToolBar()

        bar.addAction(self.playAction)
        bar.addAction(self.pauseAction)
        bar.addAction(self.stopAction)

        self.seekSlider = Phonon.SeekSlider(self)
        self.seekSlider.setMediaObject(media)

        self.volumeSlider = Phonon.VolumeSlider(self)
        self.volumeSlider.setAudioOutput(audio)
        self.volumeSlider.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)

        volumeLabel = QLabel()
        volumeLabel.setPixmap(QPixmap('images/volume.png'))

        palette = QPalette()
        palette.setBrush(QPalette.Light, Qt.darkGray)

        self.timeLcd = QLCDNumber()
        self.timeLcd.setPalette(palette)

        headers = ("Title", "Artist", "Album", "Year")

        seekerLayout = QHBoxLayout()
        seekerLayout.addWidget(self.seekSlider)
        seekerLayout.addWidget(self.timeLcd)

        playbackLayout = QHBoxLayout()
        playbackLayout.addWidget(bar)
        playbackLayout.addStretch()
        playbackLayout.addWidget(volumeLabel)
        playbackLayout.addWidget(self.volumeSlider)

        mainLayout = QVBoxLayout()
        mainLayout.addWidget(video)
        mainLayout.addLayout(seekerLayout)
        mainLayout.addLayout(playbackLayout)

        self.setLayout(mainLayout)


class player(Module):
  """Video and Audio player"""
  def __init__(self):
   Module.__init__(self, "player", PLAYER)
   self.conf.addArgument({"name": "file",
                          "description": "multimedia file to play",
                          "input": Argument.Required|Argument.Single|typeId.Node})
   self.tags = "Viewers"
   #for mimeType in Phonon.BackendCapabilities.availableMimeTypes():
     #self.conf.add_const("mime-type", str(mimeType))
   #self.conf.addConstant({"name": "mime-type", 
                          #"type": typeId.String,
                          #"description": "managed mime type",
                          #"values": ["video", "audio"]})
   self.icon = ":multimedia"
