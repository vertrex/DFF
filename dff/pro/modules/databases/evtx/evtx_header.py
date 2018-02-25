# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
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
#  Romain Bertholon <rbe@digital-forensic.org>
# 

from datetime import datetime

from dff.modules.evtx.decoder import decoder, BuffDecoder, STRING_T, UINT64_T, UINT32_T, UINT16_T, UINT8_T, INT64_T

EVTX_HEADER = [
    ("Magic",[0x0, 0x8, STRING_T]),
    ("OldestChunk",[0x8, 0x8, UINT64_T]),
    ("CurrentChunkNum",[16, 0x8, UINT64_T]),
    ("NextRecordNum",[24, 0x8, UINT64_T]),
    ("HeaderPart1Len",[32, 0x4, UINT32_T]),
    ("MinorVersion",[36, 0x2, UINT16_T]),
    ("MajorVersion",[38, 0x2, UINT16_T]),
    ("HeaderSize",[40, 0x2, UINT16_T]),
    ("ChunkCount",[42, 0x2, UINT16_T]),
    ("unknown",[44, 76, STRING_T]),
    ("Flags",[120, 0x4, UINT32_T]),
    ("Checksum",[124, 0x4, UINT32_T])
]

EVTX_CHUNK = [
    ("Magic",[0x0, 0x8, STRING_T]),
    ("NumLogRecFirst",[0x8, 0x8, INT64_T]),
    ("NumLogRecLast",[16, 0x8, INT64_T]),
    ("NumFileRecFirst",[24, 0x8, INT64_T]),
    ("NumFileRecLast",[32, 0x8, INT64_T]),
    ("OfsTables",[40, 0x4, UINT32_T]),
    ("OfsRecLast",[44, 0x4, UINT32_T]),
    ("OfsRecNext",[48, 0x4,  UINT32_T]),
    ("DataCRC",[52, 0x4, UINT32_T]),
    ("unknown",[56, 0x44, STRING_T]),
    ("HeaderCRC",[124, 0x4,  UINT32_T]),
    ("StringTable",[128, 0x100, STRING_T]),
    ("TemplateTable",[384, 0x80,  STRING_T])
]

EVTX_RECORD = [
    ("Magic",[0x0, 0x4, STRING_T]),
    ("Length1",[0x4, 0x4, UINT32_T]),
    ("NumLogRecord",[0x8, 0x8, UINT64_T]),
    ("TimeCreated",[0x10, 0x8, UINT64_T])
]

EVTX_TEMPLATE_DEF = [
    ("def",[0, 2, UINT16_T]),
    ("id",[2, 4, UINT32_T]),
    ("offset",[6, 4, UINT32_T])
]

EVTX_TEMPLATE_HEADER = [
    ("unknown1",[0, 4, UINT32_T]),
    ("id",[4, 4, UINT32_T]),
    ("unknown2",[8, 12, STRING_T]),
    ("size",[20, 2, UINT16_T])
]

EVTX_SUBSTITUTION = [
    ("size",[0, 2, UINT16_T]),
    ("type",[2, 1, UINT8_T]),
    ("empty",[3, 1, UINT8_T]) #always 0x00
]

XML_TOKENIZED = [
    ("def",[0, 1, UINT8_T]),
    ("type",[1, 1, UINT8_T]),
    ("unknown",[2, 16, STRING_T]),
    ("size",[32, 2, UINT16_T])
]

class EvtxHeader(decoder):
    def __init__(self, vfile, offset = 0, template = EVTX_HEADER):
        decoder.__init__(self, vfile, offset, template)

class EvtxChunk(BuffDecoder):
    def __init__(self, vfile, offset = 0, template = EVTX_CHUNK):
        BuffDecoder.__init__(self, vfile, offset, template)

class EvtxRecord(BuffDecoder):
    def __init__(self, vfile, offset = 0, template = EVTX_RECORD):
        BuffDecoder.__init__(self, vfile, offset, template)

class EvtxTemplateDef(BuffDecoder):
    def __init__(self, vfile, offset, template = EVTX_TEMPLATE_DEF):
        BuffDecoder.__init__(self, vfile, offset, template)

class EvtxTemplateHeader(BuffDecoder):
    def __init__(self, vfile, offset = 0, template = EVTX_TEMPLATE_HEADER):
        BuffDecoder.__init__(self, vfile, offset, template)

class SubstitutionEntry(BuffDecoder):
    def __init__(self, vfile, offset, template = EVTX_SUBSTITUTION):
        BuffDecoder.__init__(self, vfile, offset, template)

class BinXMLStruct(BuffDecoder):
    def __init__(self, vfile, offset, template = XML_TOKENIZED):
        BuffDecoder.__init__(self, vfile, offset, template)
