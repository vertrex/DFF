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

#ifndef __HFSP_RECORDS_HPP__
#define __HFSP_RECORDS_HPP__


#include "catalogrecords.hpp"
#include "permissions.hpp"


PACK_START
typedef struct s_hfsp_catalog_key
{
  uint16_t	keyLength;
  uint32_t	parentId;
  uint16_t	unistrlen;  
}		hfsp_catalog_key;
PACK_END


PACK_START
typedef struct s_hfsp_catalog_folder
{
  int16_t	recordType;
  uint16_t	flags;
  uint32_t	valence;
  uint32_t	id;
  uint32_t	createDate;
  uint32_t	contentModDate;
  uint32_t	attributeModDate;
  uint32_t	accessDate;
  uint32_t	backupDate;
  perms		permissions;
  folder_info	userInfo;
  efolder_info	finderInfo;
  uint32_t	textEncoding;
  uint32_t	folderCount;
}		hfsp_catalog_folder;
PACK_END


PACK_START
typedef struct s_hfsp_catalog_file
{
  int16_t	recordType;
  uint16_t	flags;
  uint32_t	reserved;
  uint32_t	id;
  uint32_t	createDate;
  uint32_t	contentModDate;
  uint32_t	attributeModDate;
  uint32_t	accessDate;
  uint32_t	backupDate;
  perms		permissions;
  folder_info	userInfo;
  efolder_info	finderInfo;
  uint32_t	textEncoding;
  uint32_t	reserved2;
  fork_data	data;
  fork_data	resource;
}		hfsp_catalog_file;
PACK_END


class HfspCatalogEntry : public CatalogEntry
{
private:
  class HfspCatalogKey*	__key;
  class CatalogData*	__data;
  void			__createContext() throw (std::string);
public:
  HfspCatalogEntry();
  ~HfspCatalogEntry();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual void		process(uint8_t* buffer, uint16_t size) throw (std::string);  
  virtual std::string	name();
  virtual uint32_t	parentId();
  virtual uint32_t	id();
  virtual CatalogKey*	catalogKey();
  virtual CatalogData*	catalogData();
  virtual Attributes	attributes();
};


class HfspCatalogKey : public CatalogKey
{
private:
  hfsp_catalog_key	__ckey;
  uint16_t		__nameDataLength();
  uint16_t		__nameLength();
public:
  HfspCatalogKey();
  ~HfspCatalogKey();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual void		process(uint8_t* buffer, uint16_t size) throw (std::string);
  virtual std::string	name();
  virtual uint32_t	parentId();
};


class HfspCatalogFile : public CatalogFile
{
private:
  hfsp_catalog_file	__cfile;
public:
  HfspCatalogFile();
  ~HfspCatalogFile();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual void		process(uint8_t* buffer, uint16_t size) throw (std::string);
  virtual uint8_t	type();
  virtual uint32_t	id();
  virtual uint64_t	logicalSize();
  virtual ExtentsList	dataExtents(uint64_t bsize);
  virtual ExtentsList	resourceExtents(uint64_t bsize);
  virtual Attributes	attributes();
};


class HfspCatalogFolder : public CatalogFolder
{
private:
  hfsp_catalog_folder	__cfolder;
public:
  HfspCatalogFolder();
  ~HfspCatalogFolder();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual void		process(uint8_t* buffer, uint16_t size) throw (std::string);
  virtual uint8_t	type();
  virtual uint32_t	id();
  virtual Attributes	attributes();
};


class HfspCatalogThread : public CatalogThread
{
public:
  HfspCatalogThread();
  ~HfspCatalogThread();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual void		process(uint8_t* buffer, uint16_t size) throw (std::string);
  virtual uint8_t	type();
  virtual uint32_t	id();
  virtual std::string	name();
  virtual Attributes	attributes();
};


#endif
