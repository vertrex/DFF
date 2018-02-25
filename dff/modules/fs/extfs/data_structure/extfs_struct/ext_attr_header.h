/* 
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 * 
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 * 
 * See http://www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Romain Bertholon <rbe@digital-forensic.org>
 *
 */

#ifndef __EXT_ATTR_HEADER_H__
#define __EXT_ATTR_HEADER_H__

typedef struct	__ext_attr_header_s
{
  uint32	signature; //0xEA020000
  uint32	reference_count;
  uint32	blocks_number;
  uint32	hash;
  uint32	reserved[4];
}		ext_attr_header;

#endif
