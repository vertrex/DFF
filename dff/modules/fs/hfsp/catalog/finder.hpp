/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2014 ArxSys
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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#ifndef __HFSP_FINDER_HPP__
#define __HFSP_FINDER_HPP__

#include <stdint.h>

#include "export.hpp"

/* 
 Fields are not the same depending on the source :
   - https://developer.apple.com/legacy/library/technotes/tn/tn1150.html#FinderInfo
   - http://www.opensource.apple.com/source/xnu/xnu-2782.1.97/bsd/hfs/hfs_format.h
 Which on is the most up to date or relevant?
 Finder flags (finderFlags, fdFlags and frFlags)
 detailed information can be found in finder_interface.pdf
 Extended flags (extendedFinderFlags, fdXFlags and frXFlags) 
*/


PACK_START
typedef struct s_point
{
  int16_t	v;
  int16_t	h;
}		point;
PACK_END


PACK_START
typedef struct s_rect
{
  int16_t	top;
  int16_t	left;
  int16_t	bottom;
  int16_t	right;
}		rect;
PACK_END


PACK_START
typedef struct s_file_info 
{
  uint32_t	fileType;           /* The type of the file */
  uint32_t	fileCreator;        /* The file's creator */
  uint16_t	flags;
  point		location;           /* File's location in the folder. */
  int16_t	opaque;
}		file_info;
PACK_END


PACK_START
typedef struct s_efile_info
{
  uint32_t	documentId;
  uint32_t	dateAdded;
  uint16_t	extendedFlags;
  uint16_t	reserved2;
  uint32_t	putAwayFolderId;
}		efile_info;
PACK_END


PACK_START
typedef struct s_folder_info
{
  rect		windowBounds;
  uint16_t	flags;
  point		location;
  int16_t	opaque;
}		folder_info;
PACK_END


PACK_START
typedef struct s_efolder_info
{
  point		scrollPosition;
  int32_t	reserved1;
  uint16_t	extendedFlags;
  int16_t	reserved2;
  int32_t	putAwayFolderID;
}		efolder_info;
PACK_END


class FinderInfo
{
protected:
  enum finder_flags
    {
      isOnDesk		= 0x0001,
      color		= 0x000E,
      isShared		= 0x0040,
      hasNoINITs	= 0x0080,
      hasBeenInited	= 0x0100,
      hasCustomIcon	= 0x0400,
      isStationery	= 0x0800,
      nameLocked	= 0x1000,
      hasBundle		= 0x2000,
      isInvisible	= 0x4000,
      isAlias		= 0x8000
    };
  enum extended_flags
    {
      areInvalid	= 0x8000,
      hasCustomBadge	= 0x0100,
      hasRoutingInfo	= 0x0004
    };
public:
  FinderInfo();
  ~FinderInfo();
};


class FinderFile : public FinderInfo
{
public:
  FinderFile();
  ~FinderFile();
};


class FinderFolder : public FinderInfo
{
public:
  FinderFolder();
  ~FinderFolder();
};

#endif
