/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: *www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Solal Jacob <sja@digital-forensic.org>
 */

#ifndef __PFF_ITEM_INFO_HH__
#define __PFF_ITEM_INFO_HH__

#include "pff_common.hpp"
#include "pff_macro.hpp"

class Item
{
private:
  Item*                 __attacher;
  libpff_item_t*        __item;
  libpff_item_t*        __attachment;
public:
  Item(libpff_item_t* item);
  Item(libpff_item_t* item, Item* attacher, libpff_item_t* attachment);
  ~Item();
  libpff_item_t*       pff_item();
};

class ItemInfo
{
public:
  enum ItemStatusType
  {
    Normal,
    Recovered,
    AttachmentItem,
    SubItem,
    SubFolder,
    Orphan 
  };
  ItemInfo(libpff_item_t* item, int index, ItemStatusType statusType, ItemInfo* attachedInfo = NULL);
  ItemInfo(ItemInfo* item);
  ~ItemInfo();
  libpff_item_t*        pff_item(void);
  Item*                 item(libpff_file_t* const pff_file);
  ItemInfo*             attachedInfo(void);
  ItemStatusType        statusType(void);
  uint32_t              identifier(void);
  uint8_t               type(void);
  int                   index(void);
private:
  libpff_item_t*        __item;
  int                   __index;
  ItemStatusType        __statusType;
  uint32_t              __id;
  ItemInfo*             __attachedInfo;
};

#endif
