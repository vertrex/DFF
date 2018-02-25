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
#  Romain Bertholon <rbe@digital-forensic.org>
class   IndexMimeTypes():
    def __init__(self):
        self.types = {"application/images" : IndexMimeTypes.images,
                      "application/videos" : IndexMimeTypes.videos,
                      "application/animation" : IndexMimeTypes.animation,
                      "application/document": IndexMimeTypes.document,
                      "application/mail" : IndexMimeTypes.mail,
                      "application/audio" : IndexMimeTypes.audio,
                      "application/pgp" : IndexMimeTypes.pgp,
                      "application/package" : IndexMimeTypes.package,
                      "application/registry" : IndexMimeTypes.registry,
                      "application/archiver": IndexMimeTypes.archiver,
                      "application/vm" : IndexMimeTypes.vm,
                      }

    def images(self):
        return ["art", "gif", "jpg", "png",  "bmp", "tif"]

    def videos(self):
        return ["avi", "mov", "mpg"] 

    def animation(self):
        return ["fws"]        

    def document(self):
        return ["doc", "pdf", "txt", "wpc", "pdf", "htm"]

    def mail(self):
        return ["pst", "ost", "dbx", "idx", "mbx", "aolmail"]

    def audio(self):
        return ["wav", "ra"]

    def pgp(self):
        return ["pgd", "pgp", "txt"]

    def package(self):
        return  ["rpm"]

    def registry(self):
        return ["dat"]

    def archiver(self):
        return ["zip"]

    def vm(self):
        return ["java"]
