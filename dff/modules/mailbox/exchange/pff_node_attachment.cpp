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

#include "pff.hpp"

PffNodeAttachment::PffNodeAttachment(std::string name, Node* parent, pff* fsobj, ItemInfo* itemInfo, size64_t size, int attachment_iterator) : PffNodeEMail(name, parent, fsobj, itemInfo)
{
  this->attachment_iterator = attachment_iterator;
  this->setSize(size);
}


std::string	PffNodeAttachment::icon(void)
{
  return (":attach");
}

uint8_t*	PffNodeAttachment::dataBuffer(void)
{
  uint8_t*		buff = NULL;
  Item*	                item = NULL;
  libpff_item_t* 	attachment = NULL;
  libpff_error_t*       pff_error = NULL;

  if (this->size() <= 0)
    return (NULL);
 
  if ((item = this->__itemInfo->item(this->__pff()->pff_file())) == NULL) 
     return (NULL);

  if (libpff_message_get_attachment(item->pff_item(), attachment_iterator, &attachment, &pff_error) != 1)
  {
    check_error(pff_error)
    delete item; 

    return (NULL);
  }

  buff = new uint8_t[this->size()];
  
  ssize_t read_count                         = 0;

  if (libpff_attachment_data_seek_offset(attachment, 0, SEEK_SET, &pff_error) != 0)
  {
    check_error(pff_error) 
    if (libpff_item_free(&attachment, &pff_error) != 1)
      check_error(pff_error) 
    delete item;
    delete[] buff;

    return (NULL);
  }

  read_count = libpff_attachment_data_read_buffer(attachment, (uint8_t*)buff , this->size(), &pff_error);
  if (read_count != (ssize_t)this->size())
    check_error(pff_error) 
  if (libpff_item_free(&attachment, &pff_error) != 1)
    check_error(pff_error) 
  delete item;

  return (buff);
}
