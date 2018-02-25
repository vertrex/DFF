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


libpff_macro_s LIBPFF_VALID_FOLDER_MASK[8] = 
{
    { LIBPFF_VALID_FOLDER_MASK_SUBTREE, "Subtree" },
    { LIBPFF_VALID_FOLDER_MASK_INBOX, "Inbox" },
    { LIBPFF_VALID_FOLDER_MASK_OUTBOX, "Outbox" },
    { LIBPFF_VALID_FOLDER_MASK_WASTEBOX, "Wastebox" },
    { LIBPFF_VALID_FOLDER_MASK_SENTMAIL, "Sentmail" },
    { LIBPFF_VALID_FOLDER_MASK_VIEWS, "Views" },
    { LIBPFF_VALID_FOLDER_MASK_COMMON_VIEWS, "Common views" },
    { LIBPFF_VALID_FOLDER_MASK_FINDER, "Finder" }
};
 


libpff_macro_s FILE_CONTENT_TYPE[3] = 
{
    { LIBPFF_FILE_CONTENT_TYPE_PAB, "Personal Address Book (PAB)" },
    { LIBPFF_FILE_CONTENT_TYPE_PST, "Personal Storage Tables (PST)" },
    { LIBPFF_FILE_CONTENT_TYPE_OST, "Offline Storage Tables (OST)" }
};


libpff_macro_s FILE_TYPE[2] =  
{
    { LIBPFF_FILE_TYPE_32BIT, "32-bit" },
    { LIBPFF_FILE_TYPE_64BIT, "64-bit" }
};
  
libpff_macro_s FILE_ENCRYPTION_TYPE[3] = 
{
    { LIBPFF_ENCRYPTION_TYPE_NONE, "none" },
    { LIBPFF_ENCRYPTION_TYPE_COMPRESSIBLE, "compressible" },
    { LIBPFF_ENCRYPTION_TYPE_HIGH, "high" }
}; 

void pff::info()
{
   this->info_file();
   this->info_message_store();
}


void pff::info_file()
{
  libpff_error_t* pff_error       = NULL;
  size64_t	file_size	  = 0;
  uint8_t 	file_content_type = 0;
  uint8_t 	file_type         = 0;
  uint8_t 	encryption_type   = 0;
  

  if (libpff_file_get_size(this->__pff_file, &file_size, &(pff_error)) != 1)
  {
    check_error(pff_error);
    return ;
  }
  if (libpff_file_get_content_type(this->__pff_file, &file_content_type, &(pff_error)) != 1)
  {
    check_error(pff_error);
    return ;
  }
  if (libpff_file_get_type(this->__pff_file, &file_type, &(pff_error)) != 1)
  {
    check_error(pff_error);
    return ;
  }
  if (libpff_file_get_encryption_type(this->__pff_file, &encryption_type, &(pff_error)) != 1)
  {
    check_error(pff_error);
    return ;
  } 
  std::string message = ""; 
  for (uint8_t n = 0;  n <  3; n++)
  {
    if (file_content_type == FILE_CONTENT_TYPE[n].type)
    {
      message = FILE_CONTENT_TYPE[n].message;
      break;
    }
  } 
  if (message != "")
    this->res["File type content"] = new Variant(message);
  else
    this->res["File type content"] = new Variant(std::string("Unknown"));

  message = "";
  for (uint8_t n = 0;  n <  2; n++)
  {
    if (file_type == FILE_TYPE[n].type)
    {
      message = FILE_TYPE[n].message;
      break;
    }
  } 
  if (message != "") 
    this->res["PFF file type"] = new Variant(message);
  else
    this->res["PFF file type"] = new Variant(std::string("Unknown"));
 
  message = "";
  for (uint8_t n = 0;  n <  3; n++)
  {
    if (encryption_type == FILE_ENCRYPTION_TYPE[n].type)
    {
      message = FILE_ENCRYPTION_TYPE[n].message;
      break;
    }
  } 
  if (message != "") 
    this->res["Encryption type"] = new Variant(message);
  else
    this->res["Encryption type"] = new Variant(std::string("Unknown"));
}

void pff::info_message_store()
{
  libpff_error_t* pff_error           = NULL;
  libpff_item_t*  message_store       = NULL;
  uint32_t        password_checksum   = 0;

  if (libpff_file_get_message_store(this->__pff_file, &message_store, &(pff_error)) == -1)
  {
    check_error(pff_error)
    return ;
  }
  if (libpff_message_store_get_password_checksum(message_store, &password_checksum, NULL) == 1)
  {
     if (password_checksum == 0)
       this->res["Password checksum"] = new Variant(std::string("N/A"));
     else
       this->res["Password checksum"] = new Variant(password_checksum);
  }
  if (libpff_item_free(&message_store, &(pff_error)) != 1)
  {
    check_error(pff_error)
    return ;
  }
}
