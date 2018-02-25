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
#  Solal Jacob <sja@arxsys.fr>
#

from struct import unpack

class ChatSync(object):
  def __init__(self, node):
    f = node.open()
    hdata = f.read(4)
    header = unpack('<I', hdata)[0]
    if header != 0x42644373:
      raise Exception("Can't find skype chatsync header")
