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
from PyQt4.QtGui import QTextCharFormat, QFont, QSyntaxHighlighter
from PyQt4.QtCore import Qt, SIGNAL, QRegExp

class highlightRule(object):
    def __init__(self, pattern, format):
        super(highlightRule, self).__init__()
        self.__pattern = QRegExp(pattern)
        self.__format = QTextCharFormat(format)

    def pattern(self):
        return self.__pattern
        
    def format(self):
        return self.__format

class Highlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super(Highlighter, self).__init__(parent)
        self.highlightingRules = []

    def setRule(self, pattern, format):
        if (pattern != ""):
            self.highlightingRules.insert(0, highlightRule(pattern,format))
        self.rehighlight()

    def highlightBlock(self, text):
        for rule in self.highlightingRules:
            expression = rule.pattern()
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, rule.format())
                index = expression.indexIn(text, index + length)
        self.setCurrentBlockState(0)
        
class commentHighlighter(Highlighter):
    def __init__(self, parent=None):
        super(commentHighlighter, self).__init__(parent)
        CommentFormat = QTextCharFormat()
        CommentFormat.setForeground(Qt.red)
        self.setRule("#[^\n]*", CommentFormat)

class pythonHighlighter(commentHighlighter):
    def __init__(self, parent=None):
        super(pythonHighlighter, self).__init__(parent)
        quotationFormat = QTextCharFormat()
        quotationFormat.setForeground(Qt.darkGreen)
        self.setRule("\".*\"", quotationFormat)
        functionFormat = QTextCharFormat()
        functionFormat.setFontItalic(True)
        functionFormat.setForeground(Qt.blue)
        self.setRule("\\b[A-Za-z0-9_]+(?=\\()", functionFormat)

        keywordFormat = QTextCharFormat()
        keywordFormat.setForeground(Qt.darkBlue)
        keywordFormat.setFontWeight(QFont.Bold)
        pythonKeywordPatterns = ["\\band\\b", "\\bdel\\b", "\\bfrom\\b", 
                                 "\\bnot\\b", "\\bwhile\\b", "\\bas\\b",
                                 "\\belif\\b", "\\bglobal\\b", "\\bor\\b", 
                                 "\\bwith\\b", "\\bassert\\b", "\\belse\\b", 
                                 "\\bif\\b", "\\bpass\\b", "\\byield\\b",
                                 "\\bbreak\\b", "\\bexcept\\b", "\\bimport\\b", 
                                 "\\bprint\\b", "\\bclass\\b", "\\bexec\\b",
                                 "\\bin\\b", "\\braise\\b", "\\bcontinue\\b", 
                                 "\\bfinally\\b", "\\bis\\b", "\\breturn\\b",
                                 "\\bdef\\b", "\\bfor\\b", "\\blambda\\b", "\\btry\\b"]

        for pattern in pythonKeywordPatterns:
            self.setRule(pattern, keywordFormat)
