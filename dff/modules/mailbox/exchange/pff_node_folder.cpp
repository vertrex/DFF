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


PffNodeFolder::PffNodeFolder(std::string name, Node* parent, pff* nfsobj) : Node(name, 0, parent, nfsobj)
{
  this->setDir();
}

PffNodeFolder::~PffNodeFolder()
{
}

std::string	PffNodeFolder::icon()
{
  if (this->name().find("Mailbox") != std::string::npos)
    return (":mailbox");
  if (this->name().find("Tasks") != std::string::npos)
    return (":tasks");
  if (this->name().find("Notes") != std::string::npos)
    return (":notes");
  if (this->name().find("Calendar") != std::string::npos)
    return (":appointment");
  if (this->name().find("Contacts") != std::string::npos)
    return (":contact");
  if (this->name().find("Sent") != std::string::npos)
    return (":folder_sent_mail");
  if (this->name().find("Outbox") != std::string::npos)
    return (":folder_outbox");
  if (this->name().find("Deleted") != std::string::npos)
    return (":mail_delete");
  if (this->name().find("Inbox") != std::string::npos)
    return (":folder_inbox");
  return (":folder_128.png");
}
