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

PffNodeEmailTransportHeaders::PffNodeEmailTransportHeaders(std::string name, Node* parent, pff* fsobj, ItemInfo* itemInfo) : PffNodeEMail(name, parent, fsobj, itemInfo)
{
  size_t 	 headers_size = 0; 
  Item*           item        = NULL;
  libpff_error_t* pff_error   = NULL;

  if ((item = this->__itemInfo->item(this->__pff()->pff_file())) == NULL)
    return ; 

  if (libpff_message_get_utf8_transport_headers_size(item->pff_item(), &headers_size, &pff_error) == 1)
  {
    if (headers_size > 0)
       this->setSize(headers_size); 
  }
  else
    check_error(pff_error)

  delete item;
}

uint8_t*	PffNodeEmailTransportHeaders::dataBuffer(void)
{
  uint8_t*		entry_string = NULL;
  Item*	                item         = NULL;
  libpff_error_t*       pff_error    = NULL;

  if (this->size() <= 0)
    return (NULL);

  if ((item = this->__itemInfo->item(this->__pff()->pff_file())) == NULL)
    return (NULL);

  entry_string =  new uint8_t [this->size()];
  if (libpff_message_get_utf8_transport_headers(item->pff_item(), entry_string, this->size(), &pff_error ) != 1)
  {
    check_error(pff_error)
    delete item;
    delete[] entry_string;
    return (NULL);
  }
  delete item; 

  return (entry_string);
}
