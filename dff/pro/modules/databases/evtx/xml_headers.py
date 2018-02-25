# DFF -- An Open Source Digital Forensics Framework
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
#  Romain BERTHOLON < rbe@digital-forensic.fr>

# this file contains the headers of the xml depending on the value of the opcode

from dff.modules.evtx.decoder import *

XML_NODE_0x00 = [ 
    ("opcode",[0x0, 0x1, UINT8_T]),
    ("unknown1",[0x1, 0x1, UINT8_T]),
    ("unknown2",[0x2, 0x2, UINT16_T])
]

XML_NODE_0x01 = [
    ("opcode",[0x0, 0x1, UINT8_T]),
    ("unknown1",[0x1, 0x2, UINT16_T]),
    ("len",[0x3, 0x4, UINT32_T]),
    ("Pointer",[0x7, 0x4, UINT32_T])
]

XML_NODE_0x05 = [
    ("opcode",[0x00, 0x01, UINT8_T]),
    ("unknown",[0x01, 0x01, UINT8_T]),
    ("len",[0x02, 0x02, UINT16_T])
]

XML_NODE_0x06 = [
    ("opcode",[0x00, 0x01, UINT8_T]),
    ("pointer",[0x01, 0x04, UINT32_T])
]


XML_NODE_0x0c = [
    ("opcode",[0x0, 0x1, UINT8_T]), 
    ("unknown1",[0x1, 0x1, UINT8_T]), 
    ("TemplateId",[0x2, 0x4, UINT32_T]), 
    ("Pointer",[0x6, 0x4, UINT32_T])  # sur le debut de la template relatif au debut
                                    # du chunk
]

XML_NODE_0x0e = [
    ("opcode",[0x0, 0x1, UINT8_T]),
    ("index",[0x1, 0x2, UINT16_T]),
    ("type",[0x3, 0x1, UINT8_T])
]

TEMPLATE_XML = [
    ("next",[0x0, 0x4, UINT32_T]),
    ("templateId",[0x4, 0x4, UINT32_T]),
    ("guid",[0x8, 0x0c, STRING_T]),   # pointe sur le tab de substitution :
                                    # offset relatif au debut du contenu de la
                                    # template (ben ouais...)
    ("size",[0x14, 0x04, UINT32_T])
]

STRING_INFOS = [
    ("next",[0x00, 0x04, UINT32_T]),
    ("hash",[0x04, 0x02, UINT16_T]),
    ("len",[0x06, 0x02, UINT16_T])
]

USER_SID = [
    ("revision",[0, 1, UINT8_T]),
    ("SubAuthorityCount",[1, 1, UINT8_T]),
    ("IdentifierAuthority",[2, 6, STRING_T])
]

class UserSID(BuffDecoder):
    def __init__(self, vfile, offset, template = USER_SID):
        BuffDecoder.__init__(self, vfile, offset, template)

class XMLNode0x00(BuffDecoder):
    def __init__(self, vfile, offset, template = XML_NODE_0x00):
        BuffDecoder.__init__(self, vfile, offset, template)

class XMLNode0x01(BuffDecoder):
    def __init__(self, vfile, offset, template = XML_NODE_0x01):
        BuffDecoder.__init__(self, vfile, offset, template)

class XMLNode0x05(BuffDecoder):
    def __init__(self, vfile, offset, template = XML_NODE_0x05):
        BuffDecoder.__init__(self, vfile, offset, template)

class XMLNode0x06(BuffDecoder):
    def __init__(self, vfile, offset, template = XML_NODE_0x06):
        BuffDecoder.__init__(self, vfile, offset, template)

class XMLNode0x0c(BuffDecoder):
    def __init__(self, vfile, offset, template = XML_NODE_0x0c):
        BuffDecoder.__init__(self, vfile, offset, template)

class XMLNode0x0e(BuffDecoder):
    def __init__(self, vfile, offset, template = XML_NODE_0x0e):
        BuffDecoder.__init__(self, vfile, offset, template)

class TemplateXml(BuffDecoder):
    def __init__(self, vfile, offset, template = TEMPLATE_XML):
        BuffDecoder.__init__(self, vfile, offset, template)

class StringInfos(BuffDecoder):
    def __init__(self, vfile, offset, template = STRING_INFOS):
        BuffDecoder.__init__(self, vfile, offset, template)
