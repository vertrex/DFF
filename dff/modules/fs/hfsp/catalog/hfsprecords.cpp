/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2014 ArxSys
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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */


#include "hfsprecords.hpp"


HfspCatalogEntry::HfspCatalogEntry() : __key(NULL), __data(NULL)
{
}


HfspCatalogEntry::~HfspCatalogEntry()
{
  if (this->__key != NULL)
    delete this->__key;
  if (this->__data != NULL)
    delete this->__data;
}


void		HfspCatalogEntry::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  CatalogEntry::process(origin, offset, size);
  this->__createContext();
  this->__key->process(origin, offset, this->keyDataLength());
  this->__data->process(origin, offset+this->dataOffset(), this->dataLength());
}


void		HfspCatalogEntry::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  CatalogEntry::process(buffer, size);
  this->__createContext();
  this->__key->process(buffer, this->keyDataLength());
  this->__data->process(buffer+this->dataOffset(), this->dataLength());
}


std::string	HfspCatalogEntry::name()
{
  std::string		ret;
  HfspCatalogThread*	thd;

  thd = NULL;
  if (this->type() == CatalogEntry::FolderRecord || this->type() == CatalogEntry::FileRecord)
    ret = this->__key->name();
  else if ((thd = dynamic_cast<HfspCatalogThread* >(this->__data)) != NULL)
    ret = thd->name();
  return ret;
}


uint32_t	HfspCatalogEntry::parentId()
{
  if (this->type() == CatalogEntry::FolderRecord || this->type() == CatalogEntry::FileRecord)
    return this->__key->parentId();
  else
    return this->__data->id();
}


uint32_t	HfspCatalogEntry::id()
{
  if (this->type() == CatalogEntry::FolderRecord || this->type() == CatalogEntry::FileRecord)
    return this->__data->id();
  else
    return this->__key->parentId();
}


CatalogKey*	HfspCatalogEntry::catalogKey()
{
  return this->__key;
}


CatalogData*	HfspCatalogEntry::catalogData()
{
  return this->__data;
}


Attributes	HfspCatalogEntry::attributes()
{
  Attributes	attrs;

  if (this->__data != NULL)
    attrs = this->__data->attributes();
  return attrs;
}


void		HfspCatalogEntry::__createContext() throw (std::string)
{
  if (this->__key != NULL)
    {
      delete this->__key;
      this->__key = NULL;
    }
  this->__key = new HfspCatalogKey();
  if (this->__data != NULL)
    {
      delete this->__data;
      this->__data = NULL;
    }
  if (this->type() == CatalogEntry::FileRecord)
    this->__data = new HfspCatalogFile();
  else if (this->type() == CatalogEntry::FolderRecord)
    this->__data = new HfspCatalogFolder();
  else if (this->type() == CatalogEntry::FileThread)
    this->__data = new HfspCatalogThread();
  else if (this->type() == CatalogEntry::FolderThread)
    this->__data = new HfspCatalogThread();
  else
    throw std::string("Wrong Hfsp Catalog Data type");
}


HfspCatalogKey::HfspCatalogKey() : __ckey()
{
}


HfspCatalogKey::~HfspCatalogKey()
{
}


void		HfspCatalogKey::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  std::stringstream	err;

  CatalogKey::process(origin, offset, size);
  if (this->_buffer == NULL)
    throw std::string("HfspCatalogKey : buffer is null");
  if (this->_size < sizeof(hfsp_catalog_key))
    {
      err << "HfspCatalogKey : size is too small got: " << this->_size << " bytes instead of " << sizeof(hfsp_catalog_key) << std::endl;
      //this->hexdump(1, 1);
      throw std::string(err.str());
    }
  memcpy(&this->__ckey, this->_buffer, sizeof(hfsp_catalog_key));
}
 

void		HfspCatalogKey::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  std::stringstream	err;

  CatalogKey::process(buffer, size);
  if (this->_buffer == NULL)
    throw std::string("HfspCatalogKey : buffer is null");
  if (this->_size < sizeof(hfsp_catalog_key))
    {
      err << "HfspCatalogKey : size is too small got: " << this->_size << " bytes instead of " << sizeof(hfsp_catalog_key) << std::endl;
      //this->hexdump(1, 1);
      throw std::string(err.str());
    }
  memcpy(&this->__ckey, this->_buffer, sizeof(hfsp_catalog_key));
}


std::string	HfspCatalogKey::name()
{
  uint16_t	namelen;
  std::string	utf8;
  uint64_t	zero;
  

  namelen = bswap16(this->__ckey.unistrlen) * 2;
  zero = 0;
  if (((this->_buffer != NULL) && (this->_size >= namelen+8)))
    {
      utf8 = "";
      UnicodeString us((char*)(this->_buffer+8), namelen, "UTF-16BE");
      //XXX ugly but necessary condition to match HFS Private Data which starts with
      // 4 utf-16 null char...
      // https://developer.apple.com/legacy/library/technotes/tn/tn1150.html#HardLinks
      if (this->parentId() == 2 && namelen > 8 && memcmp(&zero, this->_buffer+8, 8) == 0)
	us.remove(0, 4);
      std::string ret = us.trim().toUTF8String(utf8);
    }
  return utf8;
}


uint32_t	HfspCatalogKey::parentId()
{
  return bswap32(this->__ckey.parentId);
}


HfspCatalogFile::HfspCatalogFile() : __cfile()
{
}


HfspCatalogFile::~HfspCatalogFile()
{
}


void		HfspCatalogFile::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  std::stringstream	err;

  CatalogFile::process(origin, offset, size);
  if (this->_buffer == NULL) 
    throw std::string("HfspCatalogFile : buffer is null");
  if (this->_size < sizeof(hfsp_catalog_file))
    {
      err << "HfspCatalogFile : size is too small got: " << this->_size << " bytes instead of " << sizeof(hfsp_catalog_file) << std::endl;
      //this->hexdump(1, 1);
      throw std::string(err.str());
    }
  memcpy(&this->__cfile, this->_buffer, sizeof(hfsp_catalog_file));
}


void		HfspCatalogFile::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  std::stringstream	err;

  CatalogFile::process(buffer, size);
  if (this->_buffer == NULL) 
    throw std::string("HfspCatalogFile : buffer is null");
  if (this->_size < sizeof(hfsp_catalog_file))
    {
      err << "HfspCatalogFile : size is too small got: " << this->_size << " bytes instead of " << sizeof(hfsp_catalog_file) << std::endl;
      //this->hexdump(1, 1);
      throw std::string(err.str());
    }
  memcpy(&this->__cfile, this->_buffer, sizeof(hfsp_catalog_file));
}


uint8_t		HfspCatalogFile::type()
{
  return CatalogEntry::FileRecord;
}


uint32_t	HfspCatalogFile::id()
{
  return bswap32(this->__cfile.id);
}


uint64_t	HfspCatalogFile::logicalSize()
{
  return bswap64(this->__cfile.data.logicalSize);
}


ExtentsList	HfspCatalogFile::dataExtents(uint64_t bsize)
{
  int		i;
  Extent*	extent;
  ExtentsList	extents;

  for (i = 0; i != 8; ++i)
    {
      if (this->__cfile.data.extents[i].blockCount > 0)
	{
	  extent = new Extent(this->__cfile.data.extents[i], bsize);
	  extents.push_back(extent);
	}
    }
  return extents;
}


ExtentsList	HfspCatalogFile::resourceExtents(uint64_t bsize)
{
  int		i;
  Extent*	extent;
  ExtentsList	extents;

  for (i = 0; i != 8; ++i)
    {
      if (this->__cfile.resource.extents[i].blockCount > 0)
	{
	  extent = new Extent(this->__cfile.resource.extents[i], bsize);
	  extents.push_back(extent);
	}
    }
  return extents;
}


Attributes	HfspCatalogFile::attributes()
{
  Attributes		attrs;
  Attributes		aperms;
  HfspPermissions*	perms;

  attrs["created"] = new Variant(this->_timestampToDateTime(this->__cfile.createDate));
  attrs["content modified"] = new Variant(this->_timestampToDateTime(this->__cfile.contentModDate));
  attrs["attribute modified"] = new Variant(this->_timestampToDateTime(this->__cfile.attributeModDate));
  attrs["accessed"] = new Variant(this->_timestampToDateTime(this->__cfile.accessDate));
  attrs["backup"] = new Variant(this->_timestampToDateTime(this->__cfile.backupDate));
  perms = new HfspPermissions();
  perms->process(this->__cfile.permissions);
  aperms = perms->attributes();
  attrs["Permissions"] = new Variant(aperms);
  delete perms;
  return attrs;
}


HfspCatalogFolder::HfspCatalogFolder() : __cfolder()
{
}


HfspCatalogFolder::~HfspCatalogFolder()
{
}


void		HfspCatalogFolder::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  std::stringstream	err;

  CatalogFolder::process(origin, offset, size);
  if (this->_buffer == NULL) 
    throw std::string("HfspCatalogFolder : buffer is null");
  if (this->_size < sizeof(hfsp_catalog_folder))
    {
      err << "HfspCatalogFolder : size is too small got: " << this->_size << " bytes instead of " << sizeof(hfsp_catalog_folder) << std::endl;
      //this->hexdump(1, 1);
      throw std::string(err.str());
    }
  memcpy(&this->__cfolder, this->_buffer, sizeof(hfsp_catalog_folder));
}


void		HfspCatalogFolder::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  std::stringstream	err;

  CatalogFolder::process(buffer, size);
  if (this->_buffer == NULL) 
    throw std::string("HfspCatalogFolder : buffer is null");
  if (this->_size < sizeof(hfsp_catalog_folder))
    {
      err << "HfspCatalogFolder : size is too small got: " << this->_size << " bytes instead of " << sizeof(hfsp_catalog_folder) << std::endl;
      //this->hexdump(1, 1);
      throw std::string(err.str());
    }
  memcpy(&this->__cfolder, this->_buffer, sizeof(hfsp_catalog_folder));
}


uint8_t		HfspCatalogFolder::type()
{
  return CatalogEntry::FolderRecord;
}


uint32_t	HfspCatalogFolder::id()
{
  return bswap32(this->__cfolder.id);
}


Attributes	HfspCatalogFolder::attributes()
{
  Attributes		attrs;
  Attributes		aperms;
  HfspPermissions*	perms;

  attrs["created"] = new Variant(this->_timestampToDateTime(this->__cfolder.createDate));
  attrs["content modified"] = new Variant(this->_timestampToDateTime(this->__cfolder.contentModDate));
  attrs["attribute modified"] = new Variant(this->_timestampToDateTime(this->__cfolder.attributeModDate));
  attrs["accessed"] = new Variant(this->_timestampToDateTime(this->__cfolder.accessDate));
  attrs["backup"] = new Variant(this->_timestampToDateTime(this->__cfolder.backupDate));
  perms = new HfspPermissions();
  perms->process(this->__cfolder.permissions);
  aperms = perms->attributes(); 
  attrs["Permissions"] = new Variant(aperms);
  delete perms;
  return attrs;
}


HfspCatalogThread::HfspCatalogThread()
{
}
 

HfspCatalogThread::~HfspCatalogThread()
{
}


void		HfspCatalogThread::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  CatalogThread::process(origin, offset, size);
}


void		HfspCatalogThread::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  CatalogThread::process(buffer, size);
}


uint8_t		HfspCatalogThread::type()
{
  return 0;
}


uint32_t	HfspCatalogThread::id()
{
  return 0;
}



std::string	HfspCatalogThread::name()
{
  std::string	ret;

  return ret;
}


Attributes	HfspCatalogThread::attributes()
{
  Attributes	attrs;

  return attrs;
}
