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

#include <stdlib.h>
#include <sstream>

#include "pff.hpp"

void pff::export_sub_items(libpff_item_t *item, Node* parent)
{
  libpff_error_t* pff_error           = NULL;
  libpff_item_t*  sub_item            = NULL;
  int 		  number_of_sub_items = 0;
  int 		  sub_item_iterator   = 0;

  if (libpff_item_get_number_of_sub_items(item, &number_of_sub_items, &(pff_error)) != 1)
  {
    std::string error_name = "error on " + parent->name();
    this->res[error_name] = new Variant(std::string("Unable to retrieve number of items."));
    check_error(pff_error)
    return ;
  }
  for (sub_item_iterator = 0; sub_item_iterator < number_of_sub_items; sub_item_iterator++)
  {
    if (libpff_item_get_sub_item(item, sub_item_iterator, &sub_item, &(pff_error)) != 1)
    {
      error_on_item("Unable to retrieve subitem", sub_item_iterator, parent)
      check_error(pff_error)
      continue ;
    }

    ItemInfo itemInfo = ItemInfo(sub_item, sub_item_iterator, ItemInfo::SubItem);
    this->export_item(&itemInfo, parent);
    if (libpff_item_free(&sub_item, &(pff_error)) != 1)
    {
      error_on_item("Unable to free subitem", sub_item_iterator, parent)
      check_error(pff_error)
      continue ;
    }
  } 
}

int pff::export_item(ItemInfo * itemInfo, Node* parent)
{
  uint8_t 	item_type		= 0;
  int 		result			= 0;

  try
  {
    item_type = itemInfo->type();
  }
  catch (std::string error)
  {
    return (0);
  }

  if (item_type == LIBPFF_ITEM_TYPE_ACTIVITY)
  {
    result = this->export_message_default(itemInfo, parent, std::string("Activity"));
  }
  else if (item_type == LIBPFF_ITEM_TYPE_APPOINTMENT)
  {
    result = this->export_appointment(itemInfo, parent);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_CONTACT)
  {
    result = this->export_contact(itemInfo, parent);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_DOCUMENT)
  {
    result = this->export_message_default(itemInfo, parent, std::string("Document"));
  }
  else if (item_type == LIBPFF_ITEM_TYPE_CONFLICT_MESSAGE || item_type == LIBPFF_ITEM_TYPE_EMAIL || item_type == LIBPFF_ITEM_TYPE_EMAIL_SMIME)
  {
    result = this->export_email(itemInfo, parent);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_FOLDER)
  {
    result = this->export_folder(itemInfo, parent);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_MEETING)
  {
    result = this->export_meeting(itemInfo, parent); 
  }
  else if (item_type == LIBPFF_ITEM_TYPE_NOTE)
  {
    result = this->export_note(itemInfo, parent);	
  }
  else if (item_type == LIBPFF_ITEM_TYPE_RSS_FEED)
  {
    result = this->export_message_default(itemInfo, parent, std::string("RSS"));
  }
  else if (item_type == LIBPFF_ITEM_TYPE_TASK)
  {
    result = this->export_task(itemInfo, parent);
  }
  else
  {
    error_on_item("Exporting unknown type for item", itemInfo->index(), parent)
    result = 1;
  }
 return (result);
}

int pff::export_message_default(ItemInfo* itemInfo, Node* parent, std::string item_type_name)
{
  std::ostringstream folderName;

  folderName << std::string(item_type_name) << itemInfo->index() + 1;
  PffNodeFolder* nodeFolder = new PffNodeFolder(folderName.str(), parent, this);

  new PffNodeEmailMessageText(std::string(item_type_name), nodeFolder, this, itemInfo);

  return (1);
}

int pff::export_note(ItemInfo* itemInfo, Node* parent)
{
  int 			result;
  std::ostringstream 	folderName;
  libpff_error_t*       pff_error           = NULL;
  size_t 		subject_string_size = 0;

  result = libpff_message_get_utf8_subject_size(itemInfo->pff_item(), &subject_string_size, &(pff_error));
  if (result != 0 && result != -1 && subject_string_size > 0)
  {
    char*	subject = (char*)malloc(sizeof(char) * subject_string_size);
    if (libpff_message_get_utf8_subject(itemInfo->pff_item(), (uint8_t*)subject, subject_string_size, &(pff_error)) != 1)
      check_error(pff_error)
    folderName << std::string(subject);
    free(subject);
  }    
  else
  {
    check_error(pff_error)
    folderName << "Note" << itemInfo->index() + 1;
  }

  PffNodeFolder* nodeFolder = new PffNodeFolder(folderName.str(), parent, this);
  new PffNodeNote("Note", nodeFolder, this, itemInfo);

  return (1);
}

int pff::export_meeting(ItemInfo* itemInfo, Node* parent)
{
  libpff_error_t* pff_error           = NULL;
  std::ostringstream 	folderName;
  size_t 		subject_string_size = 0;
  int 			result;

  result = libpff_message_get_utf8_subject_size(itemInfo->pff_item(), &subject_string_size, &(pff_error));
  if (result != 0 && result != -1 && subject_string_size > 0)
  {
    char*	subject = (char*)malloc(sizeof(char) * subject_string_size);
    if (libpff_message_get_utf8_subject(itemInfo->pff_item(), (uint8_t*)subject, subject_string_size, &(pff_error)) != 1)
      check_error(pff_error)
    folderName << std::string(subject);
    free(subject);
  }    
  else
  {
    check_error(pff_error)
    folderName << "Meeting" << itemInfo->index() + 1;
  } 
  PffNodeFolder* nodeFolder = new PffNodeFolder(folderName.str(), parent, this);

  new PffNodeMeeting("Meeting", nodeFolder, this, itemInfo); 

  return (1);
}

int pff::export_task(ItemInfo* itemInfo, Node* parent)
{
  libpff_error_t* pff_error           = NULL;
  std::ostringstream 	taskName;
  size_t 		subject_string_size = 0;
  int 			result;

  result = libpff_message_get_utf8_subject_size(itemInfo->pff_item(), &subject_string_size, &(pff_error));
  if (result != 0 && result != -1 && subject_string_size > 0)
  {
    char*	subject = (char*)malloc(sizeof(char) * subject_string_size);
    if (libpff_message_get_utf8_subject(itemInfo->pff_item(), (uint8_t*)subject, subject_string_size, &(pff_error)) != 1)
      check_error(pff_error)
    taskName << std::string(subject);
    free(subject);
  }    
  else
  {
    check_error(pff_error)
    taskName << std::string("Task") << itemInfo->index() + 1;
  }
  PffNodeFolder* nodeFolder = new PffNodeFolder(taskName.str(), parent, this);

  new PffNodeTask(std::string("Task"), nodeFolder, this, itemInfo);
  this->export_attachments(itemInfo, nodeFolder);
 
  return (1);
}


int pff::export_contact(ItemInfo* itemInfo, Node* parent)
{
  libpff_error_t* pff_error           = NULL;
  std::ostringstream 	contactName;
  size_t 		subject_string_size = 0;
  int 			result;

  result = libpff_message_get_utf8_subject_size(itemInfo->pff_item(), &subject_string_size, &(pff_error));
  if (result != 0 && result != -1 && subject_string_size > 0)
  {
    char*	subject = (char*)malloc(sizeof(char ) * subject_string_size);
    if (libpff_message_get_utf8_subject(itemInfo->pff_item(), (uint8_t*)subject, subject_string_size, &(pff_error)) != -1)
      check_error(pff_error)
    contactName << std::string(subject);
    free(subject);
  }    
  else
  { 
    check_error(pff_error)
    contactName << std::string("Contact") << itemInfo->index() + 1;
  }
  PffNodeFolder* nodeFolder = new PffNodeFolder(contactName.str(), parent, this);

  new PffNodeContact(std::string("Contact"), nodeFolder, this, itemInfo);

  this->export_attachments(itemInfo, nodeFolder);

  return (1);
}

int pff::export_appointment(ItemInfo* itemInfo, Node* parent)
{
  libpff_error_t* pff_error           = NULL;
  std::ostringstream 	messageName; 
  size_t 		subject_string_size = 0;
  int 			result;

  result = libpff_message_get_utf8_subject_size(itemInfo->pff_item(), &subject_string_size, &(pff_error));
  if (result != 0 && result != -1 && subject_string_size > 0)
  {
    char*	subject = (char*)malloc(sizeof(char) * subject_string_size);
    if (libpff_message_get_utf8_subject(itemInfo->pff_item(), (uint8_t*)subject, subject_string_size, &(pff_error)) != -1)
      check_error(pff_error)
    messageName << std::string(subject);
    free(subject);
  }    
  else
  {
    check_error(pff_error)
    messageName << std::string("Appointment")  << itemInfo->index() + 1;
  } 
  PffNodeFolder* nodeFolder = new PffNodeFolder(messageName.str(), parent, this);

  new PffNodeAppointment(std::string("Appointment"), nodeFolder, this, itemInfo);

  this->export_attachments(itemInfo, nodeFolder);

  return (1);
}

int pff::export_folder(ItemInfo* itemInfo, Node* parent)
{
  libpff_error_t* pff_error           = NULL;
  PffNodeFolder* 	subFolder	 = NULL;
  uint8_t*	 	folder_name	 = NULL;
  size_t 		folder_name_size = 0;
  int 			result		 = 0;

  result = libpff_folder_get_utf8_name_size(itemInfo->pff_item(), &folder_name_size, &(pff_error));
  if (result == 0 || result == -1 || folder_name_size == 0)
  {
    std::ostringstream folderName;

    folderName << std::string("Folder") << itemInfo->index() + 1;
    subFolder = new PffNodeFolder(folderName.str(), parent, this);
  }
  else
  {
    folder_name = (uint8_t *) new uint8_t[folder_name_size];
    result = libpff_folder_get_utf8_name(itemInfo->pff_item(), folder_name, folder_name_size, NULL);
    subFolder = new PffNodeFolder(std::string((char *)folder_name), parent, this);
  }

  if (export_sub_folders(itemInfo, subFolder) != 1)
  {
    check_error(pff_error)
    error_on_item("Unable to export subfolders", itemInfo->index(), subFolder)
    return (0);
  }
  if (export_sub_messages(itemInfo, subFolder) != 1)
  {
    check_error(pff_error)
    error_on_item("Unable to export submessages", itemInfo->index(), subFolder)
    return (0);
  }

  return (1);
}

int pff::export_email(ItemInfo* itemInfo, Node *parent)
{
  libpff_error_t* pff_error           = NULL;
  size_t 	email_html_body_size = 0;
  size_t 	email_rtf_body_size = 0;
  size_t 	email_text_body_size = 0;
  size_t	transport_headers_size = 0;
  size_t 	subject_string_size = 0;
  int 		result;
  int 		has_html_body = 0;
  int 		has_rtf_body = 0;
  int 		has_text_body = 0;

  std::ostringstream messageName; 

  result = libpff_message_get_utf8_subject_size(itemInfo->pff_item(), &subject_string_size, &(pff_error));
  if (result != 0 && result != -1 && subject_string_size > 0)
  {
    char*	subject = (char*)malloc(sizeof(char ) * subject_string_size);
    if (libpff_message_get_utf8_subject(itemInfo->pff_item(), (uint8_t*)subject, subject_string_size, &(pff_error)) != -1)
      check_error(pff_error)
    messageName << std::string(subject);
    free(subject);
  }    
  else
  {
    check_error(pff_error)
    messageName << std::string("Message")  << itemInfo->index() + 1;
  }
  has_html_body = libpff_message_get_html_body_size(itemInfo->pff_item(), &email_html_body_size, &(pff_error));
  has_rtf_body = libpff_message_get_rtf_body_size(itemInfo->pff_item(), &email_rtf_body_size, &(pff_error));
  has_text_body = libpff_message_get_plain_text_body_size(itemInfo->pff_item(), &email_text_body_size, &(pff_error)); 
  
  PffNodeFolder* nodeFolder = new PffNodeFolder(messageName.str(), parent, this);

  if (libpff_message_get_utf8_transport_headers_size(itemInfo->pff_item(), &transport_headers_size, &(pff_error)) == 1)
  {
    if (transport_headers_size > 0)
      new PffNodeEmailTransportHeaders("Transport Headers", nodeFolder, this, itemInfo);
  }
  else
    check_error(pff_error)
    
  if (has_text_body == 1)
  {
    new PffNodeEmailMessageText("Message.txt", nodeFolder, this, itemInfo);
  }
  else
    check_error(pff_error)
  if (has_html_body == 1)
  {
    new PffNodeEmailMessageHTML("Message.html", nodeFolder, this, itemInfo);
  }
  else
    check_error(pff_error)
  if (has_rtf_body == 1)
  {
    new PffNodeEmailMessageRTF("Message.rtf", nodeFolder, this, itemInfo);
  }
  else
    check_error(pff_error)

  this->export_attachments(itemInfo, nodeFolder);

  return (1);
}

int pff::export_attachments(ItemInfo* itemInfo, Node* parent)
{
  int		result 				= 0;
  int 		attachment_type         	= 0;
  int 		attachment_iterator     	= 0;
  int 		number_of_attachments   	= 0;
  size_t 	attachment_filename_size	= 0;
  size64_t 	attachment_data_size            = 0;
  uint8_t*	attachment_filename     	= NULL;
  libpff_error_t* pff_error                     = NULL;

  if (libpff_message_get_number_of_attachments(itemInfo->pff_item(), &number_of_attachments, &(pff_error) ) != 1 )
  {
    check_error(pff_error)
    return (-1);
  }
  if (number_of_attachments <= 0)
  {
    check_error(pff_error)
    return (-1);
  }
  for (attachment_iterator = 0; attachment_iterator < number_of_attachments; attachment_iterator++)
  {
     libpff_item_t *attachment			= NULL;
     if (libpff_message_get_attachment(itemInfo->pff_item(), attachment_iterator, &attachment, &(pff_error)) != 1)
     {
       check_error(pff_error)
       continue ;
     }
     if (libpff_attachment_get_type(attachment, &attachment_type, &(pff_error)) != 1)
     {
       check_error(pff_error)
       if (libpff_item_free(&attachment, &(pff_error)) != 1)
         check_error(pff_error)
       continue;    
     }
     if ((attachment_type != LIBPFF_ATTACHMENT_TYPE_DATA)
         && (attachment_type != LIBPFF_ATTACHMENT_TYPE_ITEM)
         && (attachment_type != LIBPFF_ATTACHMENT_TYPE_REFERENCE))
     {
	if (libpff_item_free(&attachment, &(pff_error)) != 1)
          check_error(pff_error)
        continue;
     }
     if (attachment_type == LIBPFF_ATTACHMENT_TYPE_REFERENCE)
     {
       if (libpff_item_free(&attachment, &(pff_error)) != 1)
          check_error(pff_error)
       continue;
     }
     if (attachment_type == LIBPFF_ATTACHMENT_TYPE_DATA)
       if (libpff_attachment_get_utf8_long_filename_size(attachment, &attachment_filename_size, &(pff_error)) != 1)
          check_error(pff_error)

     attachment_filename = new uint8_t[attachment_filename_size];
     if (attachment_filename == NULL)
     {
       if (libpff_item_free(&attachment, &(pff_error)) == 1)
          check_error(pff_error)
       delete[] attachment_filename;
       continue;
     }	
     std::ostringstream attachmentName;
     if (attachment_type == LIBPFF_ATTACHMENT_TYPE_DATA)
     {
       if (libpff_attachment_get_utf8_long_filename(attachment, attachment_filename, attachment_filename_size, NULL) != 1 )
  	 attachmentName << std::string("Attachment") << attachment_iterator + 1;
       else 
         attachmentName << std::string((char*)attachment_filename);
  
     }
     else if (attachment_type == LIBPFF_ATTACHMENT_TYPE_ITEM)
  	 attachmentName << std::string("Attachment") << attachment_iterator + 1;

     if (attachment_type == LIBPFF_ATTACHMENT_TYPE_DATA)
     {
	 result = libpff_attachment_get_data_size(attachment, &attachment_data_size, &(pff_error));
         if (result == -1)
	 {
           check_error(pff_error)
	   libpff_item_free(&attachment, &(pff_error));
	   delete[] attachment_filename;
	   continue;
	 }
         if ((result != 0) && (attachment_data_size > 0 ))
	 {
	   new PffNodeAttachment(attachmentName.str(), parent, this, itemInfo, attachment_data_size, attachment_iterator);
	   delete[] attachment_filename;
	   if (libpff_item_free(&attachment, &(pff_error)) != 1)
             check_error(pff_error)
	 }
     }    
     else if(attachment_type == LIBPFF_ATTACHMENT_TYPE_ITEM)
     {
        libpff_item_t* attached_item = NULL;
	if (libpff_attachment_get_item(attachment, &attached_item, &(pff_error)) == 1)
	{
	  PffNodeFolder* folder = new PffNodeFolder(attachmentName.str(), parent, this);
          
          ItemInfo attachedItemInfo = ItemInfo(attached_item, attachment_iterator, ItemInfo::AttachmentItem, itemInfo);
          this->export_item(&attachedItemInfo, folder); 
          if (libpff_item_free(&attached_item, &(pff_error)) != 1)
            check_error(pff_error)
	}
	else
          check_error(pff_error)
	
	if (libpff_item_free(&attachment, &(pff_error)) != 1)
          check_error(pff_error)
	delete[] attachment_filename;
     }
  }
  return (1);
}

int pff::export_sub_folders(ItemInfo* itemInfo, PffNodeFolder* nodeFolder)
{
  libpff_item_t* sub_folder = NULL; 
  int 		number_of_sub_folders = 0;
  int 		sub_folder_iterator   = 0;
  libpff_error_t* pff_error           = NULL;

  if (libpff_folder_get_number_of_sub_folders(itemInfo->pff_item(), &number_of_sub_folders, &(pff_error)) != 1)
  {
    check_error(pff_error)
    std::string error_name = "error on " + nodeFolder->name();
    this->res[error_name] = new Variant(std::string("Unable to retrieve number of subfolders"));
    return (0);
  }
  for (sub_folder_iterator = 0; sub_folder_iterator < number_of_sub_folders; sub_folder_iterator++)
  {
     if (libpff_folder_get_sub_folder(itemInfo->pff_item(), sub_folder_iterator, &sub_folder, &(pff_error)) != 1)
     {
       check_error(pff_error)
       error_on_item("Unable to retrieve subfolders", sub_folder_iterator, nodeFolder)
       continue ;
     }
     ItemInfo itemInfo = ItemInfo(sub_folder, sub_folder_iterator, ItemInfo::SubFolder);
     if (export_folder(&itemInfo, nodeFolder) != 1)
     {
       error_on_item("Unable to export subfolder", sub_folder_iterator, nodeFolder)
     }
     if (libpff_item_free(&sub_folder, &(pff_error)) != 1)
     {
       check_error(pff_error)
       error_on_item("Unable to free subfolder", sub_folder_iterator, nodeFolder)
     }
  }
  return (1);
}

int pff::export_sub_messages(ItemInfo* itemInfo, PffNodeFolder* nodeFolder)
{
  libpff_item_t *sub_message = NULL; 
  int number_of_sub_messages = 0;
  int sub_message_iterator   = 0;
  libpff_error_t* pff_error           = NULL;

  if (libpff_folder_get_number_of_sub_messages(itemInfo->pff_item(), &number_of_sub_messages, &(pff_error)) != 1)
  {
    std::string error_name = "error on " + nodeFolder->name();
    this->res[error_name] = new Variant(std::string("Unable to retrieve number of submessages"));
    return (0);
  }
  for (sub_message_iterator = 0; sub_message_iterator < number_of_sub_messages; sub_message_iterator++)
  {
     if (libpff_folder_get_sub_message(itemInfo->pff_item(), sub_message_iterator, &sub_message, &(pff_error)) != 1)
     {
       check_error(pff_error)
       error_on_item("Unable to retrieve submessage", sub_message_iterator, nodeFolder) 
       continue ;	
     }
     ItemInfo itemInfo = ItemInfo(sub_message, sub_message_iterator, ItemInfo::SubFolder);
     if (export_item(&itemInfo, nodeFolder) != 1)
     {
       error_on_item("Unable to export submessage", sub_message_iterator, nodeFolder) 
       continue ;
     }
     if (libpff_item_free(&sub_message, &(pff_error)) != 1)
     {
       check_error(pff_error)
       error_on_item("Unable to free submessage", sub_message_iterator, nodeFolder) 
       continue ;
     }
  }

  return (1);
}
