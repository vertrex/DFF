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


#ifndef __HFS_RECORDS_HPP__
#define __HFS_RECORDS_HPP__


#include "catalogrecords.hpp"


PACK_START
typedef struct s_hfs_catalog_key
{
  uint8_t	keyLength;
  uint8_t	reserved;
  uint32_t	parentId;
  uint8_t	nameLength;
}		hfs_catalog_key;
PACK_END


PACK_START
typedef struct s_hfs_catalog_folder
{
  int16_t	recordType;
  uint16_t	flags;
  uint16_t	valence;
  uint32_t	id;
  uint32_t	createDate;
  uint32_t	modifyDate;
  uint32_t	backupDate;
  folder_info	userInfo;
  efolder_info	finderInfo;
  uint32_t	reserved[4];
}		hfs_catalog_folder;
PACK_END


PACK_START
typedef struct s_hfs_catalog_file
{
  int16_t	recordType;
  uint8_t	flags;
  int8_t	type;
  file_info	userInfo;
  uint32_t	id;
  uint16_t	dataStartBlock;
  int32_t	dataLogicalSize;
  int32_t	dataPhysicalSize;
  uint16_t	rsrcStartBlock;
  int32_t	rsrcLogicalSize;
  int32_t	rsrcPhysicalSize;
  uint32_t	createDate;
  uint32_t	modifyDate;
  uint32_t	backupDate;
  efolder_info	finderInfo;
  uint16_t	clumpSize;
  hfs_extent	dataExtents;
  hfs_extent	resourceExtents;
  uint32_t	reserved;
}		hfs_catalog_file;
PACK_END


class HfsCatalogEntry : public CatalogEntry
{
private:
  class HfsCatalogKey*	__key;
  class CatalogData*	__data;
  void			__createContext() throw (std::string);
public:
  HfsCatalogEntry();
  ~HfsCatalogEntry();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual void		process(uint8_t* buffer, uint16_t size) throw (std::string);  
  virtual std::string	name();
  virtual uint32_t	parentId();
  virtual uint32_t	id();
  virtual CatalogKey*	catalogKey();
  virtual CatalogData*	catalogData();
  virtual Attributes	attributes();
};


class HfsCatalogKey : public CatalogKey
{
private:
  hfs_catalog_key	__ckey;
public:
  HfsCatalogKey();
  ~HfsCatalogKey();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual void		process(uint8_t* buffer, uint16_t size) throw (std::string);
  virtual std::string	name();
  virtual uint32_t	parentId();
};


class HfsCatalogFile : public CatalogFile
{
private:
  hfs_catalog_file	__cfile;
public:
  HfsCatalogFile();
  ~HfsCatalogFile();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual void		process(uint8_t* buffer, uint16_t size) throw (std::string);
  virtual uint8_t	type();
  virtual uint32_t	id();
  virtual uint64_t	logicalSize();
  virtual ExtentsList	dataExtents(uint64_t bsize);
  virtual ExtentsList	resourceExtents(uint64_t bsize);
  virtual Attributes	attributes();
};


class HfsCatalogFolder : public CatalogFolder
{
private:
  hfs_catalog_folder	__cfolder;
public:
  HfsCatalogFolder();
  ~HfsCatalogFolder();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual void		process(uint8_t* buffer, uint16_t size) throw (std::string);
  virtual uint8_t	type();
  virtual uint32_t	id();
  virtual Attributes	attributes();
};


class HfsCatalogThread : public CatalogThread
{
public:
  HfsCatalogThread();
  ~HfsCatalogThread();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual void		process(uint8_t* buffer, uint16_t size) throw (std::string);
  virtual uint8_t	type();
  virtual uint32_t	id();
  virtual std::string	name();
  virtual Attributes	attributes();
};


#endif
