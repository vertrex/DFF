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

from msodraw import OfficeArtBStoreDelay, PictureNode

class PPT(object):
  def __init__(self, picturesStream):
     self.picturesStream = picturesStream

  def pictures(self):
     pictures = []
     vfile = self.picturesStream.open()
     try :
       oabsc = OfficeArtBStoreDelay(vfile)
     except :
	vfile.close()
	raise
     vfile.close()
     for blip in oabsc.blips:
	pictures.append((blip.offset, blip.size, self.picturesStream))
     return pictures

  def createPictureNodes(self):
     pictures = self.pictures()
     count = 1
     for offset, size, node in pictures:
	PictureNode(node, offset, size, count)
	count += 1

