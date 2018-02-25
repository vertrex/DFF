/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
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
 *  Solal J. <sja@digital-forensic.org>
 */

#ifndef __TYPESCONV_HPP__

namespace DFF
{

union s_ull
{
  struct 
  {
    unsigned long Low;
    unsigned long High;
  };
  struct 
  {
    unsigned long Low;
    unsigned long High;
  }    u;
  unsigned long long ull;
};

#define bytes_swap64(x)\
  ((((x) & 0xff00000000000000ull) >> 56)\
   | (((x) & 0x00ff000000000000ull) >> 40)\
   | (((x) & 0x0000ff0000000000ull) >> 24)\
   | (((x) & 0x000000ff00000000ull) >> 8)\
   | (((x) & 0x00000000ff000000ull) << 8)\
   | (((x) & 0x0000000000ff0000ull) << 24)\
   | (((x) & 0x000000000000ff00ull) << 40)\
   | (((x) & 0x00000000000000ffull) << 56))

#define bytes_swap32(x)\
  ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) |\
   (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))


}

#endif
