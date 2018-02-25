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

#ifndef __PFF_NODE_HH__
#define __PFF_NODE_HH__

#include "pff.hpp"

#include "node.hpp"

using namespace DFF;

class pff;
class ItemInfo;

class PffNodeFolder : public Node
{
public:
  EXPORT                        PffNodeFolder(std::string name, Node* parent, pff* fsobj);
  EXPORT                        ~PffNodeFolder();
  std::string		        icon(void);
};

class PffNodeData : public Node
{
protected:
  ItemInfo*                     __itemInfo;
  pff*                          __pff();
public:
  EXPORT 		        PffNodeData(std::string name, Node* parent, pff* fsobj);
  EXPORT 		        PffNodeData(std::string name, Node* parent, pff* fsobj, ItemInfo* itemInfo);
  EXPORT                        ~PffNodeData();
  virtual fdinfo*       	vopen();
  virtual int32_t 	        vread(fdinfo* fi, void *buff, unsigned int size);
  virtual int32_t 	        vclose(fdinfo* fi);
  virtual uint64_t      	vseek(fdinfo* fi, uint64_t offset, int whence);
};

class PffNodeEMail : public PffNodeData
{
private:
  int			        attributesMessageHeader(Attributes* attr, libpff_item_t* item);
  int 			        attributesMessageConversationIndex(Attributes* attr, libpff_item_t* item);
  int			        attributesRecipients(Attributes* attr, libpff_item_t* item);
  int			        attributesTransportHeaders(Attributes* attr, libpff_item_t* item);
  void 			        splitTextToAttributes(std::string text, Attributes* attr);
public:
  EXPORT 		        PffNodeEMail(std::string name, Node* parent, pff* fsobj);
  EXPORT 		        PffNodeEMail(std::string name, Node* parent, pff* fsobj, ItemInfo* itemInfo);
  EXPORT virtual Attributes     _attributes(void);
  Attributes			allAttributes(libpff_item_t* item);	
  fdinfo*       		vopen(void);
  int32_t 	       	 	vread(fdinfo* fi, void *buff, unsigned int size);
  int32_t 	        	vclose(fdinfo* fi);
  uint64_t		      	vseek(fdinfo* fi, uint64_t offset, int whence);
  virtual uint8_t *	        dataBuffer(void);
  std::string			icon(void);
};

class PffNodeEmailTransportHeaders : public PffNodeEMail
{
public:
  EXPORT		        PffNodeEmailTransportHeaders(std::string, Node*, pff*, ItemInfo* itemInfo);
  EXPORT uint8_t *	        dataBuffer(void);
};

class PffNodeEmailMessageText : public PffNodeEMail
{
public:
  EXPORT			PffNodeEmailMessageText(std::string , Node*, pff*, ItemInfo* itemInfo);
  EXPORT uint8_t*		dataBuffer(void);
};

class PffNodeEmailMessageHTML : public PffNodeEMail
{
public:
  EXPORT			PffNodeEmailMessageHTML(std::string , Node*, pff*, ItemInfo* itemInfo);
  EXPORT uint8_t*		dataBuffer(void);
};

class PffNodeEmailMessageRTF : public PffNodeEMail
{
public:
  EXPORT			PffNodeEmailMessageRTF(std::string , Node*, pff*, ItemInfo* itemInfo);
  EXPORT uint8_t*		dataBuffer(void);
};

class PffNodeAttachment : public PffNodeEMail 
{
private:
  int				attachment_iterator;
public:
  EXPORT 		        PffNodeAttachment(std::string name, Node* parent, pff* fsobj, ItemInfo* itemInfo, size64_t, int attachment_iterator);
  EXPORT uint8_t*		dataBuffer(void);
  EXPORT std::string		icon(void);
};

class PffNodeAppointment : public PffNodeEMail
{
public:
  EXPORT	PffNodeAppointment(std::string name, Node *parent, pff* fsobj, ItemInfo* itemInfo);
  EXPORT virtual Attributes     _attributes(void);
  EXPORT void  	                attributesAppointment(Attributes* attr, libpff_item_t*);
  EXPORT std::string		icon(void);
};


class PffNodeContact : public PffNodeEmailMessageText
{
public:
  EXPORT PffNodeContact(std::string name, Node* parent, pff* fsobj, ItemInfo* itemInfo);
  EXPORT virtual Attributes 	_attributes(void);
  EXPORT void			attributesContact(Attributes* attr, libpff_item_t*);
  EXPORT std::string		icon(void);
};

class PffNodeTask : public PffNodeEmailMessageText
{
public:
  EXPORT PffNodeTask(std::string name, Node* parent, pff* fsobj, ItemInfo* itemInfo);
  EXPORT virtual Attributes   	_attributes(void);
  EXPORT void		      	attributesTask(Attributes* attr, libpff_item_t*); 
  EXPORT std::string		icon(void);
};

class PffNodeMeeting : public PffNodeEmailMessageText
{
public:
  EXPORT PffNodeMeeting(std::string name, Node* parent, pff* fsobj, ItemInfo* itemInfo);
  EXPORT  std::string		icon(void); 
};

class PffNodeNote : public PffNodeEmailMessageText
{
public:
  EXPORT PffNodeNote(std::string name, Node* parent, pff* fsobj, ItemInfo* itemInfo);
  EXPORT std::string	icon(void);
};

class PffNodeUnallocatedBlocks : public Node
{
private:
 pff*                           __pff();
 Node*			        root;
 int			        block_type;
public:
 EXPORT			        PffNodeUnallocatedBlocks(std::string name, Node* parent, pff* fsobj, Node* root, int block_type);
 virtual void		        fileMapping(FileMapping* fm);
};

#endif
