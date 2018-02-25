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


art = [["\x4a\x47\x04\x0e", "\xcf\xc7\xcb", 150000],
       ["\x4a\x47\x03\x0e", "\xd0\xcb\x00\x00", 150000]]

gif = [["\x47\x49\x46\x38", "\x00\x3b", 5000000]]

jpg = [["\xff\xd8\xff", "\xff\xd9", 200000000]]

png = [["\x89\x50\x4e\x47", "\xff\xfc\xfd\xfe", 20000000]]

bmp = [["BM", "", 100000]]

tif = [["\x49\x49\x2a\x00", "", 200000000],
       ["\x4D\x4D\x00\x2A", "", 200000000]]

avi = [["RIFF", "", 50000000]]

mov = [["moov", "", 10000000],
       ["mdat", "", 10000000],
       ["widev", "", 10000000],
       ["skip", "", 10000000],
       ["free", "", 10000000],
       ["idsc", "", 10000000],
       ["pckg", "", 10000000]]

mpg = [["\x00\x00\x01\xba", "\x00\x00\x01\xb9", 50000000],
       ["\x00\x00\x01\xb3", "\x00\x00\x01\xb7", 50000000]]

fws = [["FWS", "", 4000000]]

doc = [["\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00", "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00", 10000000],
       ["\xd0\xcf\x11\xe0\xa1\xb1", "", 10000000]]

pst = [["\x21\x42\x4e\xa5\x6f\xb5\xa6", "", 500000000]]

ost = [["\x21\x42\x44\x4e", "", 500000000]]

dbx = [["\xcf\xad\x12\xfe\xc5\xfd\x74\x6f", "", 10000000]]

idx = [["\x4a\x4d\x46\x39", "", 10000000]]

mbx = [["\x4a\x4d\x46\x36", "", 10000000]]

wpc = [["WPC", "", 1000000]]

htm = [["<html", "</html>", 50000]]

pdf = [["%PDF", "%EOF\x0d", 5000000],
       ["%PDF", "%EOF\x0a", 5000000]]

mail = [["\x41\x4f\x4c\x56\x4d", "", 500000]]

pgd = [["\x50\x47\x50\x64\x4d\x41\x49\x4e\x60\x01", "", 500000]]

pgp = [["\x99\x00", "", 100000],
       ["\x95\x01", "", 100000],
       ["\x95\x00", "", 100000],
       ["\xa6\x00", "", 100000]]

txt = [["-----BEGIN\040PGP", "", 100000]]

rpm = [["\xed\xab", "", 1000000]]

wav = [["RIFF", "", 200000]]

ra = [["\x2e\x72\x61\xfd", "", 1000000],
      [".RMF", "", 1000000]]

dat = [["regf", "", 4000000],
       ["CREG", "", 4000000]]

zip = [["PK\x03\x04", "\x3c\xac", 10000000]]

java = [["\xca\xfe\xba\xbe", "", 1000000]]

max = [["\x56\x69\x47\x46\x6b\x1a\x00\x00\x00\x00", "\x00\x00\x05\x80\x00\x00", 1000000]]


filetypes = {"application/images": {"art": art, "gif": gif, "jpg": jpg, "png": png, 
"bmp": bmp, "tif": tif},
             "application/videos": {"avi": avi, "mov": mov, "mpg": mpg}, 
             "application/animation": {"fws": fws},
             "application/document": {"doc": doc, "pdf": pdf, "txt": txt, "wpc": wpc, "pdf": pdf, "htm": htm},
             "application/mail": {"pst": pst, "ost": ost, "dbx": dbx, "idx": idx, "mbx": mbx, "aolmail": mail},
             "application/audio": {"wav": wav, "ra": ra},
             "application/pgp": {"pgd": pgd, "pgp": pgp, "txt": txt},
             "application/package": {"rpm": rpm},
             "application/registry": {"dat": dat},
             "application/archiver": {"zip": zip},
             "application/vm": {"java": java}}
