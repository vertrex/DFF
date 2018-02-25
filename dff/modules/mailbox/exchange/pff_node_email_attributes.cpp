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
#include "pff.hpp"
#include "datetime.hpp"

libpff_macro32_s LIBPFF_MESSAGE_FLAG[9] = 
{
    { LIBPFF_MESSAGE_FLAG_UNMODIFIED, "Unmodified" },
    { LIBPFF_MESSAGE_FLAG_SUBMIT, "Submit" },
    { LIBPFF_MESSAGE_FLAG_UNSENT, "Unsent" },
    { LIBPFF_MESSAGE_FLAG_HAS_ATTACHMENTS, "Has attachments" },
    { LIBPFF_MESSAGE_FLAG_FROM_ME, "From me" },
    { LIBPFF_MESSAGE_FLAG_ASSOCIATED, "Associated" },
    { LIBPFF_MESSAGE_FLAG_RESEND, "Resend" },
    { LIBPFF_MESSAGE_FLAG_RN_PENDING, "RN pending" },
    { LIBPFF_MESSAGE_FLAG_NRN_PENDING, "NRN pending" }
};

libpff_macro32_s LIBPFF_RECIPIENT_TYPE[4] = 
{
   { LIBPFF_RECIPIENT_TYPE_ORIGINATOR, "Originator"},
   { LIBPFF_RECIPIENT_TYPE_TO, "To"},
   { LIBPFF_RECIPIENT_TYPE_CC, "CC"},
   { LIBPFF_RECIPIENT_TYPE_BCC, "BCC"}
};


libpff_macro32_s LIBPFF_MESSAGE_IMPORTANCE_TYPE[3] = 
{
    { LIBPFF_MESSAGE_IMPORTANCE_TYPE_LOW, "Low"},
    { LIBPFF_MESSAGE_IMPORTANCE_TYPE_NORMAL, "Normal"},
    { LIBPFF_MESSAGE_IMPORTANCE_TYPE_HIGH, "High"}
}; 

libpff_macro32_s LIBPFF_MESSAGE_PRIORITY_TYPE[3] = 
{
    { (uint32_t)LIBPFF_MESSAGE_PRIORITY_TYPE_NON_URGENT, "Non Urgent"},
    { LIBPFF_MESSAGE_PRIORITY_TYPE_NORMAL, "Normal"},
    { LIBPFF_MESSAGE_PRIORITY_TYPE_URGENT, "Urgent"}
}; 

libpff_macro32_s LIBPFF_MESSAGE_SENSITIVITY_TYPE[4] = 
{
    { LIBPFF_MESSAGE_SENSITIVITY_TYPE_NONE, "None"},
    { LIBPFF_MESSAGE_SENSITIVITY_TYPE_PERSONAL, "Personal"},
    { LIBPFF_MESSAGE_SENSITIVITY_TYPE_PRIVATE, "Private"},
    { LIBPFF_MESSAGE_SENSITIVITY_TYPE_CONFIDENTIAL, "Confidential"}
}; 

Attributes PffNodeEMail::allAttributes(libpff_item_t*	item)
{
  Attributes 		attr;

  Attributes messageHeader;
  if (this->attributesMessageHeader(&messageHeader, item))
    attr["Message headers"] = new Variant(messageHeader);

  Attributes recipients;
  if (this->attributesRecipients(&recipients, item))
    attr["Recipients"] = new Variant(recipients);

  Attributes transportHeaders;
  if (this->attributesTransportHeaders(&transportHeaders, item))
    attr["Transport headers"] = new Variant(transportHeaders);

  Attributes conversationIndex;
  if (this->attributesMessageConversationIndex(&conversationIndex, item))
    attr["Conversation index"] = new Variant(conversationIndex);

  return (attr);
}

Attributes PffNodeEMail::_attributes()
{
  Attributes		attr;
  Item*	                item = NULL;

  if ((item = this->__itemInfo->item(this->__pff()->pff_file())) == NULL)
    return attr;

  attr = this->allAttributes(item->pff_item());
  delete item;

  return attr;
}

void PffNodeEMail::splitTextToAttributes(std::string text, Attributes* attr)
{
 size_t 	splitter = 0;
 size_t		next_splitter = 0;
 size_t 	eol = 0;
 size_t 	next_eol = 0;
 size_t         line = 0;
 size_t 	buff_size = text.length();
 std::string	key;
 std::string 	value;

 while (splitter < buff_size && next_eol + 3 < buff_size && line != std::string::npos)
 {
   splitter = text.find(": ", splitter);
   if (splitter == std::string::npos)
     return ;

   eol = text.rfind("\n", splitter); 
   if (eol == std::string::npos)
   {
     eol = 0; 
     key = text.substr(eol, splitter - eol); 
   }
   else
     key = text.substr(eol + 1, splitter - eol - 1);
   next_splitter = text.find(": ", splitter + 1);
   if (next_splitter == std::string::npos)
     next_splitter = buff_size;

   next_eol = text.rfind("\n", next_splitter);
   if (next_eol == buff_size - 1)
     next_eol -= 2;

   line = text.find("\n", splitter + 1);
   if (next_splitter < line)
   {
     next_splitter = text.find(": ", line);
     if (next_splitter == std::string::npos)
       next_splitter = buff_size;
 
     next_eol = text.rfind("\n", next_splitter);
     if (next_eol == std::string::npos)
     {
       next_eol = buff_size;
     }
   }
   value = text.substr(splitter + 2,  next_eol - splitter - 3); 

   if (value.length() > 256)
     (*attr)[key] = new Variant(std::string("Value too long"));
   else
   {
     (*attr)[key] = new Variant(value);
   }
   splitter = next_eol + 2; 
 }
}

int PffNodeEMail::attributesTransportHeaders(Attributes* attr, libpff_item_t* item)
{
  size_t          message_transport_headers_size  = 0; 
  libpff_error_t* pff_error                       = NULL;
  uint8_t*        entry_string                    = NULL;

  if (libpff_message_get_utf8_transport_headers_size(item, &message_transport_headers_size,
	          				     &pff_error) != 1)
  {
    check_error(pff_error)
    return (0);
  }
  if (message_transport_headers_size <= 0)
    return (0);

  entry_string =  new uint8_t [message_transport_headers_size];

  if (libpff_message_get_utf8_transport_headers(item, entry_string, message_transport_headers_size, &pff_error) != 1 )
  {
    check_error(pff_error)
    delete[] entry_string;
    return (0);
  }
  this->splitTextToAttributes(std::string((char *)entry_string), attr);

  delete[] entry_string;
  return (1);
}


int PffNodeEMail::attributesRecipients(Attributes* attr, libpff_item_t* item)
{
  libpff_error_t*        pff_error                      = NULL;
  libpff_item_t*	recipients			= NULL;
  uint8_t*		entry_value_string          	= NULL;
  int			number_of_recipients		= 0;
  size_t 		entry_value_string_size         = 0;
  size_t 		maximum_entry_value_string_size = 0;
  uint32_t 		entry_value_32bit		= 0;
  int 			recipient_iterator		= 0;

  if (libpff_message_get_recipients(item, &recipients, &pff_error) == 1)
  {
     if (libpff_item_get_number_of_sets(recipients, (uint32_t*) &number_of_recipients, &pff_error) != 1)
     {
        check_error(pff_error)
        if (libpff_item_free(&recipients, &pff_error) != 1)
           check_error(pff_error)
        return (0); 
     }
     if (number_of_recipients > 0)
     {
        for (recipient_iterator = 0; recipient_iterator < number_of_recipients; recipient_iterator++)
	{
	   if (libpff_item_get_entry_value_utf8_string_size(recipients, recipient_iterator, LIBPFF_ENTRY_TYPE_DISPLAY_NAME, &entry_value_string_size, 0, &pff_error) == 1)
	   {
	     if (entry_value_string_size > maximum_entry_value_string_size)
	     {
		maximum_entry_value_string_size = entry_value_string_size;
	     }
  	   }
           else
             check_error(pff_error)
	   if (libpff_recipients_get_utf8_display_name_size(recipients, recipient_iterator, &entry_value_string_size, &pff_error) == 1)
	   {
	      if (entry_value_string_size > maximum_entry_value_string_size)
		maximum_entry_value_string_size = entry_value_string_size;
	   }
           else
             check_error(pff_error)
	   if (libpff_item_get_entry_value_utf8_string_size(recipients, recipient_iterator, LIBPFF_ENTRY_TYPE_ADDRESS_TYPE, &entry_value_string_size, 0, &pff_error) == 1)
	   {
	      if (entry_value_string_size > maximum_entry_value_string_size)
		maximum_entry_value_string_size = entry_value_string_size;
	   }
           else
             check_error(pff_error)
           if (libpff_item_get_entry_value_utf8_string_size(recipients, recipient_iterator, LIBPFF_ENTRY_TYPE_EMAIL_ADDRESS, &entry_value_string_size, 0, &pff_error) == 1)
	   {	
	      if (entry_value_string_size > maximum_entry_value_string_size)
		maximum_entry_value_string_size = entry_value_string_size;
           }
           else
             check_error(pff_error)
	   if (maximum_entry_value_string_size == 0)
		continue ;

	   Attributes	attrRecipient;

	   entry_value_string = (uint8_t*) new uint8_t[maximum_entry_value_string_size];

	   if (libpff_item_get_entry_value_utf8_string(recipients, recipient_iterator, LIBPFF_ENTRY_TYPE_DISPLAY_NAME, entry_value_string, maximum_entry_value_string_size, 0, &pff_error) == 1)
	    attrRecipient["Display Name"] = new Variant(std::string((char *)entry_value_string));
           else
             check_error(pff_error)

	   if (libpff_recipients_get_utf8_display_name(recipients, recipient_iterator, entry_value_string, maximum_entry_value_string_size, &pff_error) == 1)
	     attrRecipient["Recipient display name"] = new Variant(std::string((char*)entry_value_string));
           else
             check_error(pff_error)
              
	   if (libpff_item_get_entry_value_utf8_string(recipients, recipient_iterator, LIBPFF_ENTRY_TYPE_ADDRESS_TYPE, entry_value_string, maximum_entry_value_string_size, 0, &pff_error) == 1)
	     attrRecipient["Address type"] = new Variant((char*) entry_value_string);
            else
               check_error(pff_error)
	   if (libpff_item_get_entry_value_utf8_string(recipients, recipient_iterator, LIBPFF_ENTRY_TYPE_EMAIL_ADDRESS, entry_value_string, maximum_entry_value_string_size, 0, &pff_error) == 1)
	     attrRecipient["Email address"] = new Variant((char*)entry_value_string);
           else
             check_error(pff_error)
	   if (libpff_recipients_get_type(recipients, recipient_iterator, &entry_value_32bit, &pff_error) == 1)
	   {
	      for (uint32_t n = 0; n < 5; n++)
	      {
		 if (n >= 4)
	         {
		   attrRecipient["Recipient type"] = new Variant(std::string("Unknown"));
		 }
		 else if (entry_value_32bit == LIBPFF_RECIPIENT_TYPE[n].type)
		 {
		   attrRecipient["Recipient type"] = new Variant(std::string(LIBPFF_RECIPIENT_TYPE[n].message));
		   break;
		 }
	      }
	   }
           else
             check_error(pff_error)
                
	   std::ostringstream keyRecipient;

	   keyRecipient << "Recipient " << recipient_iterator + 1;
	   (*attr)[keyRecipient.str()] = new Variant(attrRecipient);
	   delete[] entry_value_string;
	}	
     }
     else
     {
       if (libpff_item_free(&recipients, &pff_error) != 1)
         check_error(pff_error)
       return (0);
     }
  }
  else 
  {
    check_error(pff_error)
    return (0);
  }

  if (libpff_item_free(&recipients, &pff_error) != 1)
    check_error(pff_error)
  return (1);   
}

int PffNodeEMail::attributesMessageConversationIndex(Attributes* attr, libpff_item_t* item)
{
  libpff_error_t* pff_error             = NULL;
  uint8_t*	entry_value 		= NULL;
  uint32_t	entry_value_index	= 0;
  size_t   	entry_value_size 	= 0;
  uint64_t 	entry_value_64bit	= 0;
  uint64_t	current_time		= 0;
  int		list_iterator		= 0;
  int		result			= 0;

  result = libpff_message_get_conversation_index_size(item, &entry_value_size, &pff_error);
  if (result == -1 || result == 0 || entry_value_size == 0)
  {
    check_error(pff_error)
    return (0);
  }
  entry_value = (uint8_t *)malloc(sizeof(uint8_t) * entry_value_size);
  if (entry_value == NULL)
    return (0);
  result = libpff_message_get_conversation_index(item, entry_value, entry_value_size, &pff_error);
  if ((result != 1) || (entry_value_size < 22) || (entry_value[0] != 0x01))
  {
    if (result != 1)
      check_error(pff_error)
    free(entry_value);
    return (0);
  }

  Attributes		headerBlock;
  std::ostringstream 	guid;

  entry_value_64bit = bytes_swap64(*((uint64_t*)(entry_value)));
  *((uint8_t*)&entry_value_64bit) = 0;
  *(((uint8_t*)&entry_value_64bit) + 1) = 0;

  current_time = entry_value_64bit;
  DateTime*  value_filetime = new MS64DateTime(entry_value_64bit);
  Variant* variant_filetime = new Variant(value_filetime);
  headerBlock["File time"] = variant_filetime;

  entry_value_64bit = bytes_swap64(*((uint64_t*) (entry_value + 6))); 
  guid << std::hex << entry_value_64bit;
  entry_value_64bit = bytes_swap64(*((uint64_t*) (entry_value + 14)));
  guid << entry_value_64bit;

  headerBlock["GUID"] = new Variant(guid.str());
  (*attr)["Header block"] = new Variant(headerBlock);

  list_iterator = 1;
  for (entry_value_index = 22; entry_value_index < entry_value_size; entry_value_index += 5)
  {
     Attributes		 childBlock;
     std::ostringstream  childBlockId;

     entry_value_64bit = 0;
     entry_value_64bit = *((uint32_t*) (entry_value + entry_value_index));
     entry_value_64bit &= 0x07fffffffUL;
     if ((*(entry_value + entry_value_index) & 0x80) == 0)
       entry_value_64bit <<= 18;
     else
       entry_value_64bit <<= 23;
     current_time += entry_value_64bit;

     childBlock["File time"] = new Variant(new MS64DateTime(current_time));
     childBlock["Random number"] = new Variant((*(entry_value + entry_value_index + 4) & 0xf0) >> 4);
     childBlock["Sequence count"] = new Variant(*(entry_value + entry_value_index + 4) & 0x0f);
     childBlockId << "Child block " << list_iterator; 
     (*attr)[childBlockId.str()] = new Variant(childBlock);

     list_iterator++;
  }
  free(entry_value);
  return (1);
}

int PffNodeEMail::attributesMessageHeader(Attributes* attr, libpff_item_t* item)
{
  std::ostringstream		flags;
  libpff_error_t*               pff_error                       = NULL;
  char*				entry_value_string 		= NULL;
  size_t			entry_value_string_size 	= 0;
  size_t 			maximum_entry_value_string_size	= 0;
  uint64_t 			entry_value_64bit 		= 0;
  uint32_t 			entry_value_32bit 		= 0;
  uint8_t 			entry_value_boolean 		= 0;
  int 				result 				= 0;

  maximum_entry_value_string_size = 24;
  check_maximum_size(libpff_item_get_utf8_display_name_size)
  check_maximum_size(libpff_message_get_utf8_conversation_topic_size)
  check_maximum_size(libpff_message_get_utf8_subject_size)
  check_maximum_size(libpff_message_get_utf8_sender_name_size)
  check_maximum_size(libpff_message_get_utf8_sender_email_address_size)
  if (!(maximum_entry_value_string_size))
    return (0); 

  entry_value_string = (char *) new char[maximum_entry_value_string_size];

  value_time_to_attribute(libpff_message_get_client_submit_time, "Client submit time") 
  value_time_to_attribute(libpff_message_get_delivery_time, "Delivery time")
  value_time_to_attribute(libpff_message_get_creation_time, "Creation time")
  value_time_to_attribute(libpff_message_get_modification_time, "Modification time")
  value_uint32_to_attribute(libpff_message_get_size, "Message size")  

  if (libpff_message_get_flags(item, &entry_value_32bit, &pff_error) == 1)
  {
     if ((entry_value_32bit & LIBPFF_MESSAGE_FLAG_READ) == LIBPFF_MESSAGE_FLAG_READ)
       (*attr)["Is readed"] = new Variant(std::string("Yes"));
     else
       (*attr)["Is readed"] = new Variant(std::string("No"));
     for (uint32_t n = 0; n < 9; n ++)
     {
	if ((entry_value_32bit & LIBPFF_MESSAGE_FLAG[n].type) == LIBPFF_MESSAGE_FLAG[n].type)
	{
	   if (flags.str().size())
	     flags << ", ";
	   flags << LIBPFF_MESSAGE_FLAG[n].message;
	}
     }	
     if (flags.str().size())
	  (*attr)["Flags"] = new Variant(flags.str());
  }
  else
    check_error(pff_error)

  value_string_to_attribute(libpff_item_get_utf8_display_name, "Display name")
  value_string_to_attribute(libpff_message_get_utf8_conversation_topic, "Conversation topic") 
  value_string_to_attribute(libpff_message_get_utf8_subject, "Subject")
  value_string_to_attribute(libpff_message_get_utf8_sender_name, "Sender name")
  value_string_to_attribute(libpff_message_get_utf8_sender_email_address, "Sender email address")

  if (libpff_message_get_importance(item, &entry_value_32bit, &pff_error) == 1)
  {
     for (uint32_t n = 0; n < 3; n++)
       if (entry_value_32bit == LIBPFF_MESSAGE_IMPORTANCE_TYPE[n].type)
       {
	 (*attr)["Importance"] = new Variant(std::string(LIBPFF_MESSAGE_IMPORTANCE_TYPE[n].message)); 
	 break;
       }
  }
  else
    check_error(pff_error)

  if (libpff_message_get_priority(item, &entry_value_32bit, &pff_error) == 1)
  {
     for (uint32_t n = 0; n < 3; n++)
       if (entry_value_32bit == LIBPFF_MESSAGE_PRIORITY_TYPE[n].type)
       {
	 (*attr)["Priority"] = new Variant(std::string(LIBPFF_MESSAGE_PRIORITY_TYPE[n].message)); 
	 break;
       }
  }
  else
    check_error(pff_error)

  if (libpff_message_get_sensitivity(item, &entry_value_32bit, &pff_error) == 1)
  {
     for (uint32_t n = 0; n < 4; n++)
       if (entry_value_32bit == LIBPFF_MESSAGE_SENSITIVITY_TYPE[n].type)
       {
	 (*attr)["Sensitivity"] = new Variant(std::string(LIBPFF_MESSAGE_SENSITIVITY_TYPE[n].message));
	 break;
       }
  }
  else
    check_error(pff_error)

  if (libpff_message_get_is_reminder(item, &entry_value_boolean, &pff_error) == 1)
  {
    if (!(entry_value_boolean))
      (*attr)["Is a reminder"] = new Variant(std::string("no"));
    else
      (*attr)["Is a reminder"] = new Variant(std::string("yes"));
  }
  else
    check_error(pff_error)
  
  value_time_to_attribute(libpff_message_get_reminder_time, "Reminder time")
  value_time_to_attribute(libpff_message_get_reminder_signal_time, "Reminder signal time")

  if (libpff_message_get_is_private(item, &entry_value_boolean, &pff_error) == 1)
  {
    if (!(entry_value_boolean))
      (*attr)["Is private"] = new Variant(std::string("no"));
    else
      (*attr)["Is private"] = new Variant(std::string("yes"));	 
  }
  else
    check_error(pff_error)

  delete[] entry_value_string;
  return (1);
}
