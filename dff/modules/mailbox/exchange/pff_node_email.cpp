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
#include "fdmanager.hpp"

PffNodeEMail::PffNodeEMail(std::string name, Node* parent, pff* fsobj) : PffNodeData(name, parent, fsobj)
{
}

PffNodeEMail::PffNodeEMail(std::string name, Node* parent, pff* fsobj, ItemInfo* itemInfo) : PffNodeData(name, parent, fsobj, itemInfo)
{
}

std::string	PffNodeEMail::icon(void)
{
  return (":mail_generic");
}


uint8_t*	PffNodeEMail::dataBuffer(void)
{
  return (NULL);
}

fdinfo* PffNodeEMail::vopen(void)
{
   fdinfo*	fi;
   uint8_t*	buff;

   if ((buff = this->dataBuffer()) == NULL)
     return (NULL);

   fi = new fdinfo;
   fi->id = new Variant((void*)buff);
   fi->node = this;
   fi->offset = 0;

   return (fi);
}

int32_t  PffNodeEMail::vread(fdinfo* fi, void *buff, unsigned int size)
{
  uint8_t*	rbuff;
 
  rbuff = (uint8_t*)fi->id->value<void* >();

  if (fi->offset > this->size())
  {
    return (0);
  }
  if ((fi)->offset + size > this->size())
    size = this->size() - fi->offset;
  memcpy(buff, rbuff + (uint32_t)fi->offset, size);
  fi->offset += size;
 
  return (size);
}

uint64_t	PffNodeEMail::vseek(fdinfo* fi, uint64_t offset, int whence)
{
  if (whence == 0)
  {
    if (offset <= this->size())
    {
      fi->offset = offset;
      return (fi->offset);
    }
  }
  else if (whence == 1)
  {
    if (fi->offset + offset <= this->size())
    {
      fi->offset += offset;
      return (fi->offset);
    }
  }
  else if (whence == 2)
  {
    fi->offset = this->size();
    return (fi->offset);
  }

  return ((uint64_t) -1);
}


int32_t PffNodeEMail::vclose(fdinfo *fi)
{
  uint8_t*	rbuff;

  rbuff = (uint8_t*)fi->id->value<void* >();
  delete[] rbuff;

  return (0);
}
