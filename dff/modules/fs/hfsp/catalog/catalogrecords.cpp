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

#include "catalogrecords.hpp"
#include "hfsrecords.hpp"
#include "hfsprecords.hpp"
#include "hfshandlers.hpp"

#include "exceptions.hpp"

CatalogEntry::CatalogEntry() : __type(-1)
{
}


CatalogEntry::~CatalogEntry()
{
}


int16_t		CatalogEntry::type()
{
  uint8_t*	data;

  data = NULL;
  if (this->__type == -1)
    {
      this->__type = CatalogEntry::InvalidRecord;
      if ((data = this->data()) != NULL)
	{
	  memcpy(&this->__type, data, 2);
	  if ((this->__type & 0xff00) != 0)
	    this->__type = bswap16(this->__type);
	}
      if (data != NULL)
	free(data);
    }
  return this->__type;
}


void		CatalogEntry::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  KeyedRecord::process(origin, offset, size);
}


void		CatalogEntry::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  KeyedRecord::process(buffer, size);
}


CatalogKey::CatalogKey()
{
}


CatalogKey::~CatalogKey()
{
}


void		CatalogKey::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  BufferReader::process(origin, offset, size);
}


void		CatalogKey::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  BufferReader::process(buffer, size);
}


CatalogData::CatalogData()
{
}


CatalogData::~CatalogData()
{
}


void		CatalogData::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  BufferReader::process(origin, offset, size);
}


void		CatalogData::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  BufferReader::process(buffer, size);
}


DateTime*	CatalogData::_timestampToDateTime(uint32_t timestamp)
{
  uint32_t	date;

  date = bswap32(timestamp);
  return new HFSDateTime(date);
}


CatalogFile::CatalogFile()
{
}


CatalogFile::~CatalogFile()
{
}


void		CatalogFile::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  CatalogData::process(origin, offset, size);
}


void		CatalogFile::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  CatalogData::process(buffer, size);
}


CatalogFolder::CatalogFolder()
{
}


CatalogFolder::~CatalogFolder()
{
}


void		CatalogFolder::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  CatalogData::process(origin, offset, size);
}


void		CatalogFolder::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  CatalogData::process(buffer, size);
}


CatalogThread::CatalogThread()
{
}


CatalogThread::~CatalogThread()
{
}


void		CatalogThread::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  CatalogData::process(origin, offset, size);
}


void		CatalogThread::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  CatalogData::process(buffer, size);
}


HfsNode::HfsNode(std::string name, HfsFileSystemHandler* handler, uint64_t offset, uint16_t size) : Node(name, 0, NULL, handler->fsObject()),  _entrySize(size), _offset(offset), _handler(handler)
{
}


HfsNode::~HfsNode()
{
}


uint32_t		HfsNode::fsId()
{
  CatalogEntry*	entry;
  uint32_t	id;

  id = 0;
  if ((entry = this->_handler->catalogTree()->catalogEntry(this->_offset, this->_entrySize)) != NULL)
    {
      id = entry->id();
      delete entry;
    }
  return id;
}


uint32_t		HfsNode::parentId()
{
  CatalogEntry*	entry;
  uint32_t	pid;

  pid = 0;
  if ((entry = this->_handler->catalogTree()->catalogEntry(this->_offset, this->_entrySize)) != NULL)
    {
      pid = entry->parentId();
      delete entry;
    }
  return pid;
}


uint16_t		HfsNode::entrySize()
{
  return this->_entrySize;
}


uint64_t		HfsNode::offset()
{
  return this->_offset;
}


bool		HfsNode::_readToBuffer(void* buffer, uint64_t offset, uint16_t size)
{
  bool		success;
  VFile*	vfile;
  
  vfile = NULL;
  success = true;
  try
    {
      vfile = this->_handler->catalogNode()->open();
      vfile->seek(offset);
      if (vfile->read(buffer, size) != size)
	success = false;
    }
  catch (std::string& err)
    {
      success = false;
    }
  catch (vfsError& err)
    {
      success = false;
    }
  if (vfile != NULL)
    {
      vfile->close();
      delete vfile;
    }
  return success;
}


HfsFile::HfsFile(std::string name, HfsFileSystemHandler* handler, uint64_t offset, uint16_t size) : HfsNode(name, handler, offset, size)
{
  ForkData*	fork;

  fork = this->forkData();
  this->setSize(fork->logicalSize());
  delete fork;
}


HfsFile::~HfsFile() 
{
}


Attributes	HfsFile::_attributes()
{
  CatalogEntry*	entry;
  Attributes	common;
  Attributes	internals;

  entry = this->_handler->catalogTree()->catalogEntry(this->_offset, this->_entrySize);
  common = entry->attributes();
  internals["offset"] = new Variant(this->_offset);
  internals["id"] = new Variant(entry->id());
  internals["parent id"] = new Variant(entry->parentId());
  common["Advanced"] = new Variant(internals);
  delete entry;
  return common;
}


ForkData*	HfsFile::forkData()
{
  ExtentsList		extents;
  ExtentsList::iterator	it;
  ForkData*		fdata;
  CatalogEntry*		entry;
  CatalogFile*		cfile;

  if ((entry = this->_handler->catalogTree()->catalogEntry(this->_offset, this->_entrySize)) == NULL)
    return NULL;
  if ((cfile = dynamic_cast<CatalogFile* >(entry->catalogData())) == NULL)
    return NULL;
  extents = cfile->dataExtents(this->_handler->blockSize());
  fdata = new ForkData(entry->id(), this->_handler->extentsTree());
  fdata->process(extents, cfile->logicalSize(), ForkData::Data);
  delete entry;
  return fdata;
}

void            HfsFile::fileMapping(FileMapping* fm)
{
  ExtentsList           extents;
  ExtentsList::iterator it;
  ForkData*		fork;
  uint64_t              coffset;

  coffset = 0;
  if ((fork = this->forkData()) == NULL)
    return;
  extents = fork->extents();
  for (it = extents.begin(); it != extents.end(); it++)
    {
      if (coffset + (*it)->size() < fork->logicalSize())
        {
          fm->push(coffset, (*it)->size(), this->_handler->origin(), (*it)->startOffset());
          coffset += (*it)->size();
        }
      else
        {
          fm->push(coffset, fork->logicalSize() - coffset, this->_handler->origin(), (*it)->startOffset());
          coffset += fork->logicalSize() - coffset;
        }
    }
  delete fork;
}


HfsFolder::HfsFolder(std::string name, HfsFileSystemHandler* handler, uint64_t offset, uint16_t size) : HfsNode(name, handler, offset, size)
{
}


HfsFolder::~HfsFolder()
{
}


Attributes	HfsFolder::_attributes()
{
  CatalogEntry*	entry;
  Attributes	common;
  Attributes	internals;

  entry = this->_handler->catalogTree()->catalogEntry(this->_offset, this->_entrySize);
  common = entry->attributes();
  internals["offset"] = new Variant(this->_offset);
  internals["id"] = new Variant(entry->id());
  internals["parent id"] = new Variant(entry->parentId());
  common["Advanced"] = new Variant(internals);
  delete entry;
  return common;
}
