#!/usr/bin/env python
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
#  jeremy Mounier <jeremy.mounier@arxsys.fr>
#
# This is a refactored version of the demork.py 
# Original work could be found here : https://bugzilla.mozilla.org/attachment.cgi?id=175024&action=view
# The xml output is replaced by JSON
# Note : Use xmltree instead of writing to stdout
# Mork specifications
# https://developer.mozilla.org/en-US/docs/Mork_Structure

import sys
import re
from sys import stdin, stdout, stderr

class Database:
    def __init__ (self):
        self.cdict  = { }
        self.adict  = { }
        self.tables = { }

class Table:
    def __init__ (self):
        self.id     = None
        self.scope  = None
        self.kind   = None
        self.rows   = { }

class Row:
    def __init__ (self):
        self.id     = None
        self.scope  = None
        self.cells  = [ ]

class Cell:
    def __init__ (self):
        self.column = None
        self.atom   = None

class Mork(object):
    def __init__(self):
        self._cellText = re.compile(r'\^(.+?)=(.*)')
        self._cellOid = re.compile(r'\^(.+?)\^(.+)')
        self._cellEscape = re.compile(r'((?:\\[\$\0abtnvfr])|(?:\$..))')
        self._backslash = { '\\\\' : '\\',
                            '\\$'  : '$',
                            '\\0'  : chr(0),
                            '\\a'  : chr(7),
                            '\\b'  : chr(8),
                            '\\t'  : chr(9),
                            '\\n'  : chr(10),
                            '\\v'  : chr(11),
                            '\\f'  : chr(12),
                            '\\r'  : chr(13) }

    def escapeData(self, match):
        return match.group() \
            .replace('\\\\n', '$0A') \
            .replace('\\)', '$29') \
            .replace('>', '$3E') \
            .replace('}', '$7D') \
            .replace(']', '$5D')

    def unescapeMork(self, match):
        s = match.group()
        if s[0] == '\\':
            return self._backslash[s]
        else:
            return chr(int(s[1:], 16))

    def decodeMorkValue(self, value):
        return self._cellEscape.sub(self.unescapeMork, value)

    def addToDict(self, dict, cells):
        for cell in cells:
            eq  = cell.find('=')
            key = cell[1:eq]
            val = cell[eq+1:-1]
            dict[key] = self.decodeMorkValue(val)

    def getRowIdScope(self, rowid, cdict):
        idx = rowid.find(':')
        if idx > 0:
            return (rowid[:idx], cdict[rowid[idx+2:]])
        else:
            return (rowid, None)
        
    def delRow(self, db, table, rowid):
        (rowid, scope) = self.getRowIdScope(rowid, db.cdict)
        if scope:
            rowkey = rowid + "/" + scope
        else:
            rowkey = rowid + "/" + table.scope
        if table.rows.has_key(rowkey):
            del table.rows[rowkey]

    def addRow(self, db, table, rowid, cells):
        row = Row()
        (row.id, row.scope) = self.getRowIdScope(rowid, db.cdict)
        for cell in cells:
            obj = Cell()
            cell = cell[1:-1]
            match = self._cellText.match(cell)
            if match:
                obj.column = db.cdict[match.group(1)]
                obj.atom   = self.decodeMorkValue(match.group(2))
            else:
                match = self._cellOid.match(cell)
                if match:
                    try:
                        obj.column = db.cdict[match.group(1)]
                        obj.atom   = db.adict[match.group(2)]
                    except:
                        return
            if obj.column and obj.atom:
                row.cells.append(obj)
        if row.scope:
            rowkey = row.id + "/" + row.scope
        else:
            rowkey = row.id + "/" + table.scope
        if table.rows.has_key(rowkey):
            print >>stderr, "ERROR: duplicate rowid/scope %s" % rowkey
            print >>stderr, cells
        table.rows[rowkey] = row
    
    def digest(self, data):
        # Remove beginning comment
        pComment = re.compile('//.*')
        data = pComment.sub('', data, 1)
        # Remove line continuation backslashes
        pContinue = re.compile(r'(\\(?:\r|\n))')
        data = pContinue.sub('', data)
        # Remove line termination
        pLine = re.compile(r'(\n\s*)|(\r\s*)|(\r\n\s*)')
        data = pLine.sub('', data)
        # Create a database object
        db          = Database()
        # Compile the appropriate regular expressions
        pCell       = re.compile(r'(\(.+?\))')
        pSpace      = re.compile(r'\s+')
        pColumnDict = re.compile(r'<\s*<\(a=c\)>\s*(?:\/\/)?\s*(\(.+?\))\s*>')
        pAtomDict   = re.compile(r'<\s*(\(.+?\))\s*>')
        pTable      = re.compile(r'\{-?(\d+):\^(..)\s*\{\(k\^(..):c\)\(s=9u?\)\s*(.*?)\}\s*(.+?)\}')
        pRow        = re.compile(r'(-?)\s*\[(.+?)((\(.+?\)\s*)*)\]')
        pTranBegin  = re.compile(r'@\$\$\{.+?\{\@')
        pTranEnd    = re.compile(r'@\$\$\}.+?\}\@')
        # Escape all '%)>}]' characters within () cells
        data = pCell.sub(self.escapeData, data)
        # Iterate through the data
        index  = 0
        length = len(data)
#        print length
        match  = None
        tran   = 0
        while 1:
            if match:  index += match.span()[1]
            if index >= length:  break
            sub = data[index:]
            # Skip whitespace
            match = pSpace.match(sub)
            if match:
                index += match.span()[1]
                continue
            # Parse a column dictionary
            match = pColumnDict.match(sub)
            if match:
                m = pCell.findall(match.group())
                # Remove extraneous '(f=iso-8859-1)'
                if len(m) >= 2 and m[1].find('(f=') == 0:
                    m = m[1:]
                self.addToDict(db.cdict, m[1:])
                continue
            # Parse an atom dictionary
            match = pAtomDict.match(sub)
            if match:
                cells = pCell.findall(match.group())
                self.addToDict(db.adict, cells)
                continue
            # Parse a table
            match = pTable.match(sub)
            if match:
                id = match.group(1) + ':' + match.group(2)
                try:
                    table = db.tables[id]
                except KeyError:
                    table = Table()
                    table.id    = match.group(1)
                    table.scope = db.cdict[match.group(2)]
                    table.kind  = db.cdict[match.group(3)]
                    db.tables[id] = table
                rows = pRow.findall(match.group())
                for row in rows:
                    cells = pCell.findall(row[2])
                    rowid = row[1]
                    if tran and rowid[0] == '-':
                        rowid = rowid[1:]
                        self.delRow(db, db.tables[id], rowid)
                    if tran and row[0] == '-':
                        pass
                    else:
                        self.addRow(db, db.tables[id], rowid, cells)
                continue
            # Transaction support
            match = pTranBegin.match(sub)
            if match:
                tran = 1
                continue
            match = pTranEnd.match(sub)
            if match:
                tran = 0
                continue
            match = pRow.match(sub)
            if match and tran:
#                print >>stderr, "WARNING: using table '1:^80' for dangling row: %s" % match.group()
                rowid = match.group(2)
                if rowid[0] == '-':
                    rowid = rowid[1:]

                cells = pCell.findall(match.group(3))
                try:
                    self.delRow(db, db.tables['1:80'], rowid)
                    if row[0] != '-':
                        self.addRow(db, db.tables['1:80'], rowid, cells)
                    continue
                except:
                    continue
            # Syntax error
#            print >>stderr, "ERROR: syntax error while parsing MORK file"
#            print >>stderr, "context[%d]: %s" % (index, sub[:40])
            index += 1
#        print db
        return db
    # def escapeMindy(self, match):
    #     s = match.group()
    #     if s == '\\': return '\\\\'
    #     if s == '\0': return '\\0'
    #     if s == '\r': return '\\r'
    #     if s == '\n': return '\\n'
    #     return "\\x%02x" % ord(s)
    # def encodeMindyValue(self, value):
    #     print value, type(value)
    #     pMindyEscape = re.compile('([\x00-\x1f\x80-\xff\\\\])')
    #     return pMindyEscape.sub(self.escapeMindy, value)
    def json(self, db):
        tables = db.tables.keys()
        entries = []
        for table in [ db.tables[k] for k in tables ]:
            rows = table.rows.keys()
            for row in [ table.rows[k] for k in rows ]:
                entry = {}
                for cell in row.cells:
                    entry[cell.column] = cell.atom
                    entries.append(entry)
        return entries
#        print entries
    # def outputMindy(self, db):
    #     print '<?xml version="1.0" standalone="yes"?>'
    #     print '<history>'
    #     tables = db.tables.keys()
    #     for table in [ db.tables[k] for k in tables ]:
    #         rows = table.rows.keys()
    #         for row in [ table.rows[k] for k in rows ]:
    #             print '  <entry table="%s" row="%s">' % (table.id, row.id)
    #             for cell in row.cells:
    #                 print '    <%s>%s</%s>' % (cell.column, self.encodeMindyValue(cell.atom), cell.column)
    #             print '  </entry>'
    #     print '</history>'
# Testing purpose




# with open("/home/jmo/dumps/history.dat", "r") as f:
#     data = f.read()
#     mork = Mork()
#     db = mork.digest(data)
#    print mork.json(db)
