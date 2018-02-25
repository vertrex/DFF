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


#include "hfsrecords.hpp"


HfsCatalogEntry::HfsCatalogEntry() : __key(NULL), __data(NULL)
{
}


HfsCatalogEntry::~HfsCatalogEntry()
{
  delete this->__key;
  delete this->__data;
}


void		HfsCatalogEntry::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  CatalogEntry::process(origin, offset, size);
  this->__createContext();
  this->__key->process(origin, offset, this->keyDataLength());
  this->__data->process(origin, offset+this->dataOffset(), this->dataLength());
}


void		HfsCatalogEntry::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  CatalogEntry::process(buffer, size);
  this->__createContext();
  this->__key->process(buffer, this->keyDataLength());
  this->__data->process(buffer+this->dataOffset(), this->dataLength());
}


std::string	HfsCatalogEntry::name()
{
  std::string		ret;
  HfsCatalogThread*	thd;

  thd = NULL;
  if (this->type() == CatalogEntry::FolderRecord || this->type() == CatalogEntry::FileRecord)
    ret = this->__key->name();
  else if ((thd = dynamic_cast<HfsCatalogThread* >(this->__data)) != NULL)
    ret = thd->name();
  return ret;
}


uint32_t	HfsCatalogEntry::parentId()
{
  if (this->type() == CatalogEntry::FolderRecord || this->type() == CatalogEntry::FileRecord)
    return this->__key->parentId();
  else
    return this->__data->id();
}


uint32_t	HfsCatalogEntry::id()
{
  if (this->type() == CatalogEntry::FolderRecord || this->type() == CatalogEntry::FileRecord)
    return this->__data->id();
  else
    return this->__key->parentId();
}


CatalogKey*	HfsCatalogEntry::catalogKey()
{
  return this->__key;
}


CatalogData*	HfsCatalogEntry::catalogData()
{
  return this->__data;
}


Attributes	HfsCatalogEntry::attributes()
{
  Attributes	attrs;

  if (this->__data != NULL)
    attrs = this->__data->attributes();
  return attrs;
}


void		HfsCatalogEntry::__createContext() throw (std::string)
{
  if (this->__key == NULL)
    this->__key = new HfsCatalogKey();
  delete this->__data;
  if (this->type() == CatalogEntry::FileRecord)
    this->__data = new HfsCatalogFile();
  else if (this->type() == CatalogEntry::FolderRecord)
    this->__data = new HfsCatalogFolder();
  else if (this->type() == CatalogEntry::FileThread)
    this->__data = new HfsCatalogThread();
  else if (this->type() == CatalogEntry::FolderThread)
    this->__data = new HfsCatalogThread();
  else
    throw std::string("Wrong Hfs Catalog Data type");
}


HfsCatalogKey::HfsCatalogKey() : __ckey()
{
}


HfsCatalogKey::~HfsCatalogKey()
{
}


void		HfsCatalogKey::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  std::stringstream	err;

  CatalogKey::process(origin, offset, size);
  if (this->_buffer == NULL)
    throw std::string("HfsCatalogKey : buffer is null");
  if (this->_size < sizeof(hfs_catalog_key))
    {
      err << "HfsCatalogKey : size is too small got: " << this->_size << " bytes instead of " << sizeof(hfs_catalog_key) << std::endl;
      //this->hexdump(1, 1);
      throw std::string(err.str());
    }
  memcpy(&this->__ckey, this->_buffer, sizeof(hfs_catalog_key));
}
 

void		HfsCatalogKey::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  std::stringstream	err;

  CatalogKey::process(buffer, size);
  if (this->_buffer == NULL)
    throw std::string("HfsCatalogKey : buffer is null");
  if (this->_size < sizeof(hfs_catalog_key))
    {
      err << "HfsCatalogKey : size is too small got: " << this->_size << " bytes instead of " << sizeof(hfs_catalog_key) << std::endl;
      //this->hexdump(1, 1);
      throw std::string(err.str());
    }
  memcpy(&this->__ckey, this->_buffer, sizeof(hfs_catalog_key));
}


std::string	HfsCatalogKey::name()
{
  uint8_t	namelen;
  std::string	utf8;
  
  namelen = this->__ckey.nameLength;
  if ((this->_buffer != NULL) && (this->_size >= namelen+7))
    {
      utf8 = "";
      UnicodeString us((char*)(this->_buffer+7), namelen);
      std::string ret = us.trim().toUTF8String(utf8);
    }
  return utf8;
}


uint32_t	HfsCatalogKey::parentId()
{
  return bswap32(this->__ckey.parentId);
}


HfsCatalogFile::HfsCatalogFile() : __cfile()
{
}


HfsCatalogFile::~HfsCatalogFile()
{
}


void		HfsCatalogFile::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  std::stringstream	err;

  CatalogFile::process(origin, offset, size);
  if (this->_buffer == NULL) 
    throw std::string("HfsCatalogFile : buffer is null");
  if (this->_size < sizeof(hfs_catalog_file))
    {
      err << "HfsCatalogFile : size is too small got: " << this->_size << " bytes instead of " << sizeof(hfs_catalog_file) << std::endl;
      //this->hexdump(1, 1);
      throw std::string(err.str());
    }
  memcpy(&this->__cfile, this->_buffer, sizeof(hfs_catalog_file));
}


void		HfsCatalogFile::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  std::stringstream	err;

  CatalogFile::process(buffer, size);
  if (this->_buffer == NULL) 
    throw std::string("HfsCatalogKey : buffer is null");
  if (this->_size < sizeof(hfs_catalog_file))
    {
      err << "HfsCatalogFile : size is too small got: " << this->_size << " bytes instead of " << sizeof(hfs_catalog_file) << std::endl;
      //this->hexdump(1, 1);
      throw std::string(err.str());
    }
  memcpy(&this->__cfile, this->_buffer, sizeof(hfs_catalog_file));
}


uint8_t		HfsCatalogFile::type()
{
  return CatalogEntry::FileRecord;
}


uint32_t	HfsCatalogFile::id()
{
  return bswap32(this->__cfile.id);
}


uint64_t	HfsCatalogFile::logicalSize()
{
  return (uint64_t)bswap32(this->__cfile.dataLogicalSize);
}


ExtentsList	HfsCatalogFile::dataExtents(uint64_t bsize)
{
  Extent*	extent;
  ExtentsList	extents;

  extent = new Extent(this->__cfile.dataExtents, bsize);
  extents.push_back(extent);
  return extents;
}


ExtentsList	HfsCatalogFile::resourceExtents(uint64_t bsize)
{
  Extent*	extent;
  ExtentsList	extents;

  extent = new Extent(this->__cfile.resourceExtents, bsize);
  extents.push_back(extent);
  return extents;
}


Attributes	HfsCatalogFile::attributes()
{
  Attributes		attrs;

  attrs["created"] = new Variant(this->_timestampToDateTime(this->__cfile.createDate));
  attrs["modified"] = new Variant(this->_timestampToDateTime(this->__cfile.modifyDate));
  attrs["backup"] = new Variant(this->_timestampToDateTime(this->__cfile.backupDate));
  return attrs;
}


HfsCatalogFolder::HfsCatalogFolder() : __cfolder()
{
}


HfsCatalogFolder::~HfsCatalogFolder()
{
}


void		HfsCatalogFolder::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  std::stringstream	err;

  CatalogFolder::process(origin, offset, size);
  if (this->_buffer == NULL) 
    throw std::string("HfsCatalogFolder : buffer is null");
  if (this->_size < sizeof(hfs_catalog_folder))
    {
      err << "HfsCatalogFolder : size is too small got: " << this->_size << " bytes instead of " << sizeof(hfs_catalog_folder) << std::endl;
      this->hexdump(1, 1);
      throw std::string(err.str());
    }
  memcpy(&this->__cfolder, this->_buffer, sizeof(hfs_catalog_folder));
}


void		HfsCatalogFolder::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  std::stringstream	err;

  CatalogFolder::process(buffer, size);
  if (this->_buffer == NULL) 
    throw std::string("HfsCatalogFolder : buffer is null");
  if (this->_size < sizeof(hfs_catalog_folder))
    {
      err << "HfsCatalogFolder : size is too small got: " << this->_size << " bytes instead of " << sizeof(hfs_catalog_folder) << std::endl;
      this->hexdump(1, 1);
      throw std::string(err.str());
    }
  memcpy(&this->__cfolder, this->_buffer, sizeof(hfs_catalog_folder));
}


uint8_t		HfsCatalogFolder::type()
{
  return CatalogEntry::FolderRecord;
}


uint32_t	HfsCatalogFolder::id()
{
  return bswap32(this->__cfolder.id);
}



Attributes	HfsCatalogFolder::attributes()
{
  Attributes		attrs;

  attrs["created"] = new Variant(this->_timestampToDateTime(this->__cfolder.createDate));
  attrs["modified"] = new Variant(this->_timestampToDateTime(this->__cfolder.modifyDate));
  attrs["backup"] = new Variant(this->_timestampToDateTime(this->__cfolder.backupDate));
  return attrs;
}


HfsCatalogThread::HfsCatalogThread()
{
}
 

HfsCatalogThread::~HfsCatalogThread()
{
}


void		HfsCatalogThread::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  CatalogThread::process(origin, offset, size);
}


void		HfsCatalogThread::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  CatalogThread::process(buffer, size);
}


uint8_t		HfsCatalogThread::type()
{
  return CatalogEntry::FolderThread;
}


uint32_t	HfsCatalogThread::id()
{
  return 0;
}


std::string		HfsCatalogThread::name()
{
  std::string		_name;

  return _name;
}


Attributes	HfsCatalogThread::attributes()
{
  Attributes	attrs;

  return attrs;
}
