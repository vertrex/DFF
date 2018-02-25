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
#  Frederic Baguelin <fba@digital-forensic.org>
#
import sys, os, string, struct, re, types, unicodedata

if os.name == "posix":
  import tty, termios, fcntl
elif os.name == "nt":
  import msvcrt
  from ctypes import windll, create_string_buffer

from dff.api.types.libtypes import typeId

SYMBOLS = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
PREFIX = {}
 
for i, s in enumerate(SYMBOLS):
  PREFIX[s] = 1 << (i+1)*10


def bytesToHuman(self, size):
  for s in reversed(SYMBOLS):
    if size >= PREFIX[s]:
      value = float(size) / PREFIX[s]
      return '%.1f%s' % (value, s)
  return str(size)


def unistr(instr):
    if type(instr) == types.UnicodeType:
      return instr.encode('utf-8')
    elif type(instr) == types.StringType:
      return unicode(instr, 'utf-8', 'replace').encode('utf-8')
    else:
      return str(instr)

# The following function comes from http://bugs.python.org/issue12568#msg155361
# It is used because there is currently no way to determine character width (in terms
# of columns length when printed) by default in Python
def wcwidth(c, legacy_cjk=False):
  if c in u'\t\r\n\10\13\14': raise ValueError('character %r has no intrinsic width' % c)
  if c in u'\0\5\7\16\17': return 0
  if u'\u1160' <= c <= u'\u11ff': return 0 # hangul jamo
  if unicodedata.category(c) in ('Mn', 'Me', 'Cf') and c != u'\u00ad': return 0 # 00ad = soft hyphen
  eaw = unicodedata.east_asian_width(c)
  if eaw in ('F', 'W'): return 2
  if legacy_cjk and eaw == 'A': return 2
  return 1


def wcstr_width(buff, legacy_cjk=False):
  buff = unicode(buff, 'utf-8', 'replace') if type(buff) == types.StringType else buff
  width = 0
  for c in buff:
    try:
      width += wcwidth(c, legacy_cjk)
    except ValueError:
      pass
  return width


class ColumnInfo():
  def __init__(self, colcount, icount, max_width):
    remain = 1 if icount % colcount != 0 else 0
    self.row_count = icount / colcount + remain
    self.icount = icount
    self.col_count = colcount
    self.cols_len = [0 for i in xrange(0, self.col_count)]
    self.max_width = max_width
    self.line_len = 0
    self.cur_col = 0
    self.cur_row = 0
    self.cur_item = 0
    self.valid = True

  def push(self, length):
    tab = 2 if self.cur_col != self.col_count else 0
    if length > self.cols_len[self.cur_col]:
      self.cols_len[self.cur_col] = length
    self.cur_row += 1
    self.cur_item += 1
    if self.cur_row == self.row_count or self.cur_item == self.icount:
      self.cur_row = 0
      if self.line_len + self.cols_len[self.cur_col] + tab < self.max_width:
        self.line_len += self.cols_len[self.cur_col] + tab
      else:
        self.valid = False
      self.cur_col += 1
    if self.cur_item == self.icount and self.cur_col != self.col_count:
      self.valid = False
      

class ColumnView():
  MinColumnWidth = 3

  def __init__(self):
    self.debug = 0


  def getColumnsInfo(self, items):
    max_width = ConsoleAttributes().terminalSize()
    icount = len(items)
    cols_info = [ColumnInfo(i+1, icount, max_width) for i in xrange(0, min(icount, max_width / ColumnView.MinColumnWidth))]
    for item in items:
      for col_info in cols_info:
        if col_info.valid:
          col_info.push(wcstr_width(item))
    i = len(cols_info) - 1
    if self.debug:
      for col_info in cols_info:
        print "{:<5s}  {:<3d} / {:<3d}  {:<3d}  {:<4d}  {:s}".format(str(col_info.valid), col_info.cur_col, 
                                                                     col_info.col_count, col_info.row_count, 
                                                                     col_info.line_len, str(col_info.cols_len))
    while i != 0 and not cols_info[i].valid:
      i -= 1
    col_info = cols_info[i]
    return (col_info.col_count, col_info.row_count, col_info.cols_len)


  def iterRows(self, items):
    max_col, self.rows, cols_len = self.getColumnsInfo(items)
    icount = len(items)
    if icount % max_col == 0:
      last_row = -1
    else:
      last_row = len(items) % self.rows
    row = 0
    while row != self.rows:
      if last_row == 0:
        cols = max_col - 1
      else:
        cols = max_col
        last_row -= 1
      col_fmt = ""
      for i in cols_len[:cols-1]:
        col_fmt += "{:<" + str(i) + "s}  "
      col_fmt += "{:<" + str(cols_len[cols-1]) + "s}"
      printable_items = [unistr(item) for item in items[row::self.rows]]
      yield col_fmt.format(*printable_items)
      row += 1
    return


class ConsoleAttributes():
    class __posix():
        def __init__(self):
            pass

        def terminalSize(self):
            width = 80
            s = struct.pack('HHHH', 0, 0, 0, 0)
            s = fcntl.ioctl(1, termios.TIOCGWINSZ, s)
            twidth = struct.unpack('HHHH', s)[1]
            if twidth > 0:
                width = twidth
            return width

    class __nt():
        def __init__(self):
            pass

        def terminalSize(self):
            h = windll.kernel32.GetStdHandle(-12)
            csbi = create_string_buffer(22)
            res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
            if res:
                (bufx, bufy, curx, cury, wattr, left, top, right, bottom, maxx, maxy) = struct.unpack("hhhhHhhhhhh", csbi.raw)
                sizex = right - left + 1
            else:
                sizex = 80
            return sizex


    def __init__(self):
        if os.name == "posix":
            ConsoleAttributes.__instance = ConsoleAttributes.__posix()
        elif os.name == "nt":
            ConsoleAttributes.__instance = ConsoleAttributes.__nt()


    def __setattr__(self, attr, value):
        setattr(self.__instance, attr, value)
  

    def __getattr__(self, attr):
        return getattr(self.__instance, attr)


class VariantTreePrinter():
    def __init__(self):
        self.consoleAttr = ConsoleAttributes()
        self.maxitems = -1
        self.maxdepth = -1
        self.currentdepth = 0


    def setMaxItemListToExpand(self, maxitems=-1):
        self.maxitems = maxitems


    def setMaxDepth(self, maxdepth=-1):
        self.maxdepth = maxdepth
        self.currentdepth = 0


    def fillMap(self, spacer, vmap, res=""):
        self.termsize = self.consoleAttr.terminalSize()
        for key in vmap.iterkeys():
            vval = vmap[key]
            res += "\n" + ("\t" * spacer) + str(key)
            if vval.type() == typeId.Map:
                if (self.maxdepth == -1 or self.currentdepth < self.maxdepth):
                    vvmap = vval.value()
                    self.currentdepth += 1
                    res += self.fillMap(spacer+1, vvmap)
                    self.currentdepth -= 1
            elif vval.type() == typeId.List:
                vlist = vval.value()
                size = len(vlist)
                res += ": total items (" + str(size) + ")\n"
                res += self.fillList(spacer+1, vlist)
            else:
                if vval.type() == typeId.DateTime:
                    dateTime = vval.value()
                    res += ": " + str(dateTime)
                elif vval.type() in [typeId.Char, typeId.Int16, typeId.UInt16, typeId.Int32, typeId.UInt32, typeId.Int64, typeId.UInt64]:                
                    res += ": " + str(vval.toString() + " - " + vval.toHexString())
                elif vval.type() == typeId.Node:
                    res += ": " + str(vval.value().absolute())
                elif vval.type() in [typeId.Path, typeId.String, typeId.Bool]:
                    res += ": " + str(vval.toString())
        return res


    def fillList(self, spacer, vlist, res=""):
        x = self.consoleAttr.terminalSize()
        res += "\n" + (spacer * "\t")
        count = len(vlist) - 1
        crop = False
        if self.maxitems != -1:
            cropbegidx = self.maxitems / 2
            cropendidx = count - self.maxitems / 2
        else:
            cropbegidx = -1
            cropendidx = -1
        idx = 0
        xpos = len("\t" * spacer)
        for vval in vlist:
            if vval.type() == typeId.Map:
                vmap = vval.value()
                self.currentdepth -= 1
                res += self.fillMap(spacer, vmap)
                self.currentdepth += 1
            elif vval.type() == typeId.List:
                vvlist = vval.value()
                res += self.fillList(spacer, vvlist)
            else:
                vstr = ""
                if not crop:
                    if vval.type == typeId.DateTime:
                        dateTime = vval.value()
                        vstr = str(dateTime)
                    elif vval.type() == typeId.Node:
                        vstr = str(vval.value().absolute())
                    elif vval.type() in [typeId.Path, typeId.String]:
                        vstr = str(vval.toString())
                    else:
                        vstr = str(vval.toString() + " - " + vval.toHexString())
                    if count:
                        vstr += ", "
                    xpos += len(vstr)
                    if xpos > x - 20:
                        res += "\n" + (spacer * "\t") + vstr
                        xpos = len(spacer * "\t") + len(vstr)
                    else:
                        res += vstr
            if cropbegidx != -1 and idx == cropbegidx:
                crop = True
                res += "\n\n" + (spacer * "\t") + (" " * ((x - 20 - len(spacer * "\t")) / 2)) + "[...]" + "\n\n" + (spacer * "\t")
                xpos = len(spacer * "\t")
            if cropendidx != -1 and idx == cropendidx:
                crop = False
            count -= 1
            idx += 1
        return res
