#!/usr/bin/python
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
# 
import curses
import binascii
import string

from dff.api.vfs import *
from dff.api.module import *

from curses import panel

bottom_box_height = 5
global nodePath

def start(node):
   global Node
   Node = node
   curses.wrapper(main_loop)

class HexFF():
   global nodePath

   def __init__(self, scr):
#      node = Core.getnode(nodePath)
#      if not node:
#        return

      self.node = Node
#      self.nodePath = nodePath
      self.vfsFile = self.node.open() 
      self.fileSize = self.node.size()

      self.scr = scr
      self.x, self.y = scr.getmaxyx()

      self.addrWidth = len(hex(self.fileSize))
      self.addrView = 0#self.fileSize - 1000
      self.readBuffer = []
      self.read = 0

#XXX should be userdefined
      self.bigEndian = 1

   def __del__(self):
      self.vfsFile.close()

#TODO
      self.actual_offset = 0

   def loop(stdscr):
      pass

   def createPanel(self, h, w, x, y):
      win = curses.newwin(h, w, x, y)
      pan = panel.new_panel(win)
      pan.show()
      return pan   
   
   def obtainHex(self, offset):
      if (offset > 0):
         self.vfsFile.seek(offset)
      buff = self.vfsFile.read(1024)
#TODO
      return buff
      out = []
      for i in range(len(buff)):
         if not i % 2:
            c = buff[i]
            out.append(buff[i + 1])
         else:
            out.append(c)
      return out

   def debug(self, pan, message):
      win = pan.window()
      win.move(3, 26)
      win.addstr(message)
      panel.update_panels()

   def offsetMove(self, move):
      self.addrView += move

   def fillToolbar(self, pan):
      win = pan.window()
      win.move(1, 3)
      sizeString = str(self.fileSize)[::-1]
      vString = ""
      for i in range(len(sizeString)):
         if not i % 3 and i:
            vString = vString + "." + sizeString[i]
         else:
            vString = vString + sizeString[i]

      win.addstr("Dump size : " + vString[::-1] + " bytes (" + hex(self.fileSize) + ")")
      win.move(2, 13)
      win.addstr("<Q>uit")
      win.border(0, 0, 0x20, 0, curses.ACS_VLINE, curses.ACS_VLINE, 0, 0)
      panel.update_panels()
      curses.doupdate()

   def fillAddress(self, pan, height):
      sAddr = self.addrView
      win = pan.window()

      for i in range(1, height):
         win.move(i, 1)
         startAddr = hex(sAddr)
         startAddr = startAddr[2:]
         s = "0x"
         for i in range(self.addrWidth - len(startAddr) - 2):
            s = s + "0"
         startAddr = s + startAddr
         win.addstr(startAddr[0:self.addrWidth])
         sAddr += 16
      win.border(0, 0, 0, 0, 0, curses.ACS_TTEE, curses.ACS_LTEE, 0)
      curses.doupdate()
      panel.update_panels()

   def fillHexPan(self, pan):
      win = pan.window()
      h, w = win.getmaxyx()
      y = 1
      for j in range(h - 2):
         win.move(j + 1, 1)
         disp = ""
         i = 0
         for k in range(16):
            if k + j * 16 < len(self.readBuffer):
               disp += str(binascii.b2a_hex(self.readBuffer[k + j * 16]))
            else:
               disp += "  "
            i += 1
            if i != 8:
               disp += " "
            if i == 8:
               disp += "  "
         win.addstr(disp)
         y += 1
      win.border(0x20, 0x20, 0, 0x20, curses.ACS_HLINE, curses.ACS_HLINE, 0x20, 0x20)
      panel.update_panels()

   def fillASCII(self, pan):
      win = pan.window()
      h, w = win.getmaxyx()
      y = 1
      for j in range(h - 2):
         win.move(j + 1, 1)
         disp = ""
         i = 0
         for k in range(16):
            if k + j * 16 < len(self.readBuffer):
               c = self.readBuffer[k + (j * 16)]
               if c in string.digits or c in string.letters or c in string.punctuation:
                  disp += c
               else:
                  disp += "."
            else:
               disp += " "
         win.addstr(disp)
         y += 1
      win.border(0, 0, 0, 0, curses.ACS_TTEE, 0, 0, curses.ACS_RTEE)
      panel.update_panels()
      curses.doupdate()
      return

   def seek(self, offset):
      self.readBuffer = self.obtainHex(offset)


def main_loop(stdscr):
   stdscr.clear()
   y, x = stdscr.getmaxyx()
   subwin = stdscr.subwin(y, x, 0, 0)
   hexff = HexFF(subwin)

   w, h = stdscr.getmaxyx()
   stdscr.clear()

   x, y = 0, hexff.addrWidth + 2
#XXX   stdscr.clear()
   stdscr.refresh()

   addr_max = pow(16, hexff.addrWidth - 4) - 1
   addr = 0

   hexff.seek(hexff.addrView)

   toolbar_pan = hexff.createPanel(bottom_box_height, hexff.addrWidth + 68, w - bottom_box_height, 0)
   hexff.fillToolbar(toolbar_pan)

   address_pan = hexff.createPanel(w - bottom_box_height, hexff.addrWidth + 2, 0, 0)
   hexff.fillAddress(address_pan, w - bottom_box_height - 1)

   hex_pan = hexff.createPanel(w - bottom_box_height, 50, 0, hexff.addrWidth + 2)
   hexff.fillHexPan(hex_pan)

   ascii_pan = hexff.createPanel(w - bottom_box_height, 16, 0, hexff.addrWidth + 52)
   hexff.fillASCII(ascii_pan)

   while (1):
      stdscr.move(x + 1, y + 1)
      c = stdscr.getch()
      c_debug = c
      if 0 < c < 256:
         c = chr(c)
         if c in 'Qq':
            break
         else:
            pass
      elif c == curses.KEY_UP and x > 0:
         x -= 1
      elif c == curses.KEY_DOWN and x < w - bottom_box_height - 3:
         x += 1
      elif c == curses.KEY_LEFT and y > hexff.addrWidth + 2:
         y -= 1
      elif c == curses.KEY_RIGHT and y < 55:
         y += 1
#Top or Bottom reached
      elif c == curses.KEY_UP and x == 0 and hexff.addrView != 0:
         hexff.offsetMove(-16)
         hexff.fillAddress(address_pan, w - bottom_box_height - 1)
         hexff.seek(hexff.addrView)
         hexff.fillHexPan(hex_pan)
         hexff.fillASCII(ascii_pan)
      elif c == curses.KEY_DOWN and x == w - bottom_box_height - 3 and hexff.addrView != hexff.fileSize - (w - bottom_box_height) + 3:
         hexff.offsetMove(+16)
         hexff.fillAddress(address_pan, w - bottom_box_height - 1)
         hexff.seek(hexff.addrView)
         hexff.fillHexPan(hex_pan)
         hexff.fillASCII(ascii_pan)
#PageUp
      elif c == 0x153 and hexff.addrView - ((w - bottom_box_height - 2) * 16) >= 0:
         hexff.offsetMove(-((w - bottom_box_height - 2) * 16))
         hexff.fillAddress(address_pan, w - bottom_box_height - 1)
         hexff.seek(hexff.addrView)
         hexff.fillHexPan(hex_pan)
         hexff.fillASCII(ascii_pan)
#PageDown
      elif c == 0x152 and hexff.addrView + ((w - bottom_box_height - 2) * 16) <= hexff.fileSize:
         hexff.offsetMove((w - bottom_box_height - 2) * 16)
         hexff.fillAddress(address_pan, w - bottom_box_height - 1)
         hexff.seek(hexff.addrView)
         hexff.fillHexPan(hex_pan)
         hexff.fillASCII(ascii_pan)
      else:
         pass
      hexff.debug(toolbar_pan, "Keycode: " + hex(c_debug) + " View offset: " + str(hexff.addrView) + "(" + hex(hexff.addrView) + ")" )
