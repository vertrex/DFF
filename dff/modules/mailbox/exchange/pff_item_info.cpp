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

#include "pff_item_info.hpp"

Item::Item(libpff_item_t* item)
{
  this->__item = item;
  this->__attacher = NULL;
  this->__attachment = NULL;
}

Item::Item(libpff_item_t* item, Item* attacher, libpff_item_t* attachment) : __attacher(attacher), __item(item), __attachment(attachment)
{
}

Item::~Item()
{
  libpff_error_t* pff_error = NULL;

  if (this->__item != NULL)
  {
    if (libpff_item_free(&this->__item, &pff_error) != 1)
      check_error(pff_error);
    this->__item = NULL;
  }
  if (this->__attacher != NULL)
  {
    delete this->__attacher;
    this->__attacher = NULL;
  }
  if (this->__attachment != NULL)
  {
    if (libpff_item_free(&this->__attachment, &pff_error) != 1)
      check_error(pff_error);
    this->__attachment = NULL;
  }
}

libpff_item_t* Item::pff_item(void)
{
  return (this->__item);
}

ItemInfo::ItemInfo(libpff_item_t* item, int index, ItemStatusType statusType, ItemInfo* attachedInfo) : __item(item), __index(index), __statusType(statusType), __id(0), __attachedInfo(attachedInfo)
{
  libpff_error_t* pff_error;

  if (this->__statusType != Recovered && this->__statusType != Orphan && this->__statusType != AttachmentItem)
    if (libpff_item_get_identifier(this->__item, &(this->__id), &pff_error) != 1)
      check_error(pff_error);
}

ItemInfo::ItemInfo(ItemInfo* itemInfo): __item(NULL), __index(itemInfo->index()), __statusType(itemInfo->statusType()), __id(itemInfo->identifier()) 
{
  if (itemInfo->attachedInfo() != NULL)
    this->__attachedInfo = new ItemInfo(itemInfo->attachedInfo());
  else
    this->__attachedInfo = NULL;
}

ItemInfo::~ItemInfo()
{
}

libpff_item_t*  ItemInfo::pff_item(void)
{
  return (this->__item);
}

Item*  ItemInfo::item(libpff_file_t* const pff_file)
{
  libpff_item_t*  pff_item = NULL;
  libpff_error_t* pff_error = NULL;

  if (this->__statusType == Recovered)
  {
    if (libpff_file_get_recovered_item(pff_file, this->__index, &pff_item, &pff_error) == 1)
      return (new Item(pff_item));  
    else
      check_error(pff_error);
  }
  else if (this->__statusType == Orphan)
  {
    if (libpff_file_get_orphan_item(pff_file, this->__index, &pff_item, &pff_error) == 1)
      return (new Item(pff_item));
    else
      check_error(pff_error);
  }
  else if (this->__statusType == AttachmentItem)
  {
    Item* attacher;
    if ((attacher = this->__attachedInfo->item(pff_file)) != NULL)
    {
       libpff_item_t* attachment = NULL;
       if (libpff_message_get_attachment(attacher->pff_item(), this->__index, &attachment, &pff_error) == 1)
       {
         if (libpff_attachment_get_item(attachment, &pff_item, &pff_error) == 1)
           return (new Item(pff_item, attacher, attachment));
         else
           check_error(pff_error)
         delete attacher;
         if (libpff_item_free(&attachment, &pff_error) != 1)
           check_error(pff_error);
       }
       else
       {
         delete attacher;
       }
    }
  }
  else 
  {
    if (libpff_file_get_item_by_identifier(pff_file, this->__id, &pff_item, &pff_error) == 1)
      return (new Item(pff_item));
    else
      check_error(pff_error);
  }

  return (NULL);
}

ItemInfo* ItemInfo::attachedInfo(void)
{
  return (this->__attachedInfo);
}

ItemInfo::ItemStatusType  ItemInfo::statusType(void)
{
  return (this->__statusType);
}

uint32_t        ItemInfo::identifier(void)
{
  return (this->__id);
}

uint8_t         ItemInfo::type(void)
{
  uint8_t         item_type;
  libpff_error_t* pff_error = NULL;

  if (libpff_item_get_type(this->pff_item(), &item_type, &pff_error) == 1)
    return (item_type);

  check_error(pff_error)  
  throw std::string("Can't get item type");
}

int             ItemInfo::index(void)
{
  return (this->__index);
}
