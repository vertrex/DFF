/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *
 * See http://www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 *
 * Author(s):
 *  Romain Bertholon <rbe@digital-forensic.org>
 *
 */

#include <sstream>
#include "include/CustomAttrib.h"

CustomAttrib::CustomAttrib()
{
}

CustomAttrib::~CustomAttrib()
{
}

void    CustomAttrib::setTime(Inode * _inode)
{
  setTime((time_t)_inode->access_time());
  setTime((time_t)_inode->change_time());
  setTime((time_t)_inode->modif_time());
  setTime((time_t)0);

#ifndef WIN32
  if (_inode->delete_time())
    {
      time_t tmp = _inode->delete_time();
      this->smap.insert(std::make_pair("Deletion time:", ctime(&tmp)));
    }
#endif
}

void    CustomAttrib::setTime(time_t timestamp)
{
#ifndef WIN32
  //tm  * t;

  //time_t tmp = timestamp;

  //t = gmtime(&tmp);
  //XXX not set anywhere
  //new DateTime(t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
  //t->tm_hour, t->tm_min, t->tm_sec, 0);
#endif
}

void    CustomAttrib::setAttr(Inode * _inode)
{
  this->imap.insert(std::make_pair("Link number", _inode->link_coun()));
  this->imap.insert(std::make_pair("NFS generation number",
				   _inode->generation_number_nfs()));
  this->imap.insert(std::make_pair("Extended attribute header",
				   _inode->file_acl_ext_attr()));
  this->imap.insert(std::make_pair("Fragment block",
				   _inode->fragment_addr()));
  this->imap.insert(std::make_pair("Fragment index",
				   _inode->fragment_index()));
  this->imap.insert(std::make_pair("Fragment size",
				   _inode->fragment_size()));
  this->imap.insert(std::make_pair("Sector count",
				   _inode->sector_count()));
}

void    CustomAttrib::setSetUidGid(Inode * _inode)
{
  this->smap.insert(std::make_pair("Set UID / GID ?",
				   _inode->set_uid_gid(_inode->file_mode())));
}

void    CustomAttrib::setMode(Inode * _inode)
{
  InodeUtils      i_utils(NULL, NULL);
  this->smap.insert(std::make_pair("Permissions",
				   i_utils.mode(_inode->file_mode())));
}

bool   CustomAttrib::setMode(uint16_t mask, Inode * _inode)
{
  if (!(mask & _inode->file_mode()))
    return true;
  return false;
}

void    CustomAttrib::setUidGid(Inode * _inode)
{
  this->smap.insert(std::make_pair("UID / GID",
	   _inode->uid_gid(_inode->lower_uid(), _inode->lower_gid())));
}
