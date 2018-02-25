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

#ifndef __CATALOG_RECORDS_HPP__
#define __CATALOG_RECORDS_HPP__

#include <stdint.h>
#include <unicode/unistr.h>

#include "export.hpp"
#include "node.hpp"
#include "vfile.hpp"

#include "bufferreader.hpp"
#include "endian.hpp"
#include "finder.hpp"
#include "extents/fork.hpp"
#include "catalogtree.hpp"
#include "hfshandlers.hpp"


class HfsFileSystemHandler;
class CatalogKey;
class CatalogData;
class ForkData;

class CatalogEntry  : public KeyedRecord
{
private:
  int16_t		__type;
public:
  typedef enum
    {
      InvalidRecord	= 0xFF,
      FolderRecord	= 0x01,
      FileRecord	= 0x02,
      FolderThread	= 0x04,
      FileThread	= 0x08,
    } Type;
  CatalogEntry();
  virtual ~CatalogEntry();
  int16_t		type();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual void		process(uint8_t* buffer, uint16_t size) throw (std::string);
  virtual std::string	name() = 0;
  virtual uint32_t	parentId() = 0;
  virtual uint32_t	id() = 0;
  virtual CatalogData*	catalogData() = 0;
  virtual CatalogKey*	catalogKey() = 0;
  virtual Attributes	attributes() = 0;
};


class CatalogKey : public BufferReader
{
public:
  CatalogKey();
  virtual ~CatalogKey();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual void		process(uint8_t* buffer, uint16_t size) throw (std::string);
  virtual std::string	name() = 0;
  virtual uint32_t	parentId() = 0;
};


class CatalogData : public BufferReader
{
protected:
  DateTime*		_timestampToDateTime(uint32_t timestamp);
public:
  CatalogData();
  virtual ~CatalogData();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual void		process(uint8_t* buffer, uint16_t size) throw (std::string);
  virtual uint8_t	type() = 0;
  virtual uint32_t	id() = 0;
  virtual Attributes	attributes() = 0;
};


class CatalogFile : public CatalogData
{
public:
  CatalogFile();
  virtual ~CatalogFile();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual void		process(uint8_t* buffer, uint16_t size) throw (std::string);
  virtual uint64_t	logicalSize() = 0;
  virtual ExtentsList	dataExtents(uint64_t bsize) = 0;
  virtual ExtentsList	resourceExtents(uint64_t bsize) = 0;
  virtual Attributes	attributes() = 0;
};


class CatalogFolder : public CatalogData
{
public:
  CatalogFolder();
  virtual ~CatalogFolder();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual void		process(uint8_t* buffer, uint16_t size) throw (std::string);
  virtual Attributes	attributes() = 0;
};


class CatalogThread : public CatalogData
{
public:
  CatalogThread();
  virtual ~CatalogThread();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual void		process(uint8_t* buffer, uint16_t size) throw (std::string);
  virtual std::string	name() = 0;
};


class HfsNode : public Node
{
protected:
  uint16_t		_entrySize;
  uint64_t		_offset;
  HfsFileSystemHandler*	_handler;
  bool			_readToBuffer(void* buffer, uint64_t offset, uint16_t size);
public:
  HfsNode(std::string name, HfsFileSystemHandler* handler, uint64_t offset, uint16_t size);
  virtual ~HfsNode();
  uint32_t		fsId();
  uint32_t		parentId();
  uint16_t		entrySize();
  uint64_t		offset();
};


class HfsFile : public HfsNode
{
public:
  HfsFile(std::string name, HfsFileSystemHandler* handler, uint64_t offset, uint16_t size);
  ~HfsFile();
  ForkData*		forkData();
  void			fileMapping(FileMapping* fm);
  Attributes		_attributes();
};


class HfsFolder : public HfsNode
{
public:
  HfsFolder(std::string name, HfsFileSystemHandler* handler, uint64_t offset, uint16_t size);
  ~HfsFolder();
  Attributes	_attributes();
};


#endif
