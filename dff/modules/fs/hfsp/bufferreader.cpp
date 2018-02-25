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


#include "bufferreader.hpp"
#include <iostream>
#include <sstream>

#include "exceptions.hpp"

BufferReader::BufferReader() : __allocated(false), _origin(NULL), _offset(0), _size(0), _buffer(NULL)
{
}

BufferReader::~BufferReader()
{
  this->__clean();
}


void		BufferReader::setContext(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  if (origin != NULL)
    this->_origin = origin;
  else
    throw std::string("[BufferReader] Provided node does not exist");
  if (offset < this->_origin->size())
    this->_offset = offset;
  else
    throw std::string("[BufferReader] Provided offset is greater than size of provided node");
  if ((size > 0) && (size < (this->_origin->size() - offset)))
    this->_size = size;
  else
    throw std::string("[BufferReader] Provided size is either zero or greater than readable size");
}


Node*		BufferReader::origin()
{
  return this->_origin;
}


uint64_t	BufferReader::offset()
{
  return this->_offset;
}


uint16_t	BufferReader::size()
{
  return this->_size;
}


void		BufferReader::process(uint8_t *buffer, uint16_t size) throw (std::string)
{
  this->__clean();
  if (size == 0)
    throw std::string("Size setted to zero. cannot process anything");
  this->_buffer = buffer;
  this->__allocated = false;
  this->_origin = NULL;
  this->_offset = 0;
  this->_size = size;
}


void		BufferReader::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  this->__clean();
  this->setContext(origin, offset, size);
  this->__readBuffer();
}


void		BufferReader::hexdump(uint8_t groupby, uint16_t encoding)
{
  std::stringstream	info;
  int			line;
  int			lines;
  int			remains;
  
  if (this->_buffer != NULL)
    {
      lines = this->_size / 16;
      remains = this->_size % 16;
      info << std::setw(64) << std::setfill('*') << " " << std::endl;
      info << std::setw(38) << std::setfill(' ') << "Hexdump" << std::endl;
      if (this->_origin != NULL)
	info << "source: " << this->_origin->absolute() << std::endl;
      info << "offset: " << this->_offset << std::endl;
      info << "size: " << this->_size << std::endl;
      std::cout << info.str();
      for (line = 0; line != lines; ++line)
	this->__dumpline(line*16, this->_buffer+(line*16), 16, groupby);
      if (remains > 0)
	this->__dumpline(lines*16, this->_buffer+(lines*16), remains, groupby);
      info.str("");
      info << std::setw(64) << std::setfill('*') << ' ' << std::endl;
      std::cout << info.str();
    }
}


void		BufferReader::__dumpline(uint32_t rva, uint8_t* line, uint8_t length, uint8_t groupby)
{
  uint8_t		idx;
  uint8_t		gb;
  uint8_t		c;
  std::stringstream	shex;
  std::stringstream	senc;

  if (length <= 16 && groupby > 0 && groupby <= 16 && groupby % 2)
    {
      gb = 0;
      for (idx = 0; idx != length; ++idx)
	{
	  c = *(line+idx);
	  if (gb == groupby)
	    {
	      shex << " ";
	      gb = 0;
	    }
	  shex << std::setw(2) << std::setfill('0') << std::hex << static_cast<unsigned int>(c);
	  if (c > 32 && c < 127)
	    senc << c;
	  else
	    senc << '.';
	  ++gb;
	}
      if (length < 16)
	shex << std::setw((16*2+16/groupby-1)-shex.str().size()) << std::setfill(' ') << " ";
      std::cout << shex.str() << " | " << senc.str() << std::endl;
      shex.str("");
      senc.str("");
    }
}


void		BufferReader::__clean()
{
  this->_origin = NULL;
  this->_offset = 0;
  this->_size = 0;
  if (this->__allocated && this->_buffer != NULL)
    free(this->_buffer);
  this->__allocated = false;
}


void		BufferReader::__readBuffer() throw (std::string)
{
  std::string	error;
  VFile*	vfile;
  
  vfile = NULL;
  if ((this->_buffer = (uint8_t*)malloc(sizeof(uint8_t)*this->_size)) == NULL)
    throw std::string("Cannot allocate node");
  this->__allocated = true;
  try
    {
      vfile = this->_origin->open();
      vfile->seek(this->_offset);
      if (vfile->read(this->_buffer, this->_size) != this->_size)
	error = std::string("Cannot read btree node");
    }
  catch (std::string& err)
    {
      error = err;
    }
  catch (vfsError& err)
    {
      error = err.error;
    }
  if (vfile != NULL)
    {
      vfile->close();
      delete vfile;
    }
  if (!error.empty())
    {
      if (this->_buffer != NULL)
	free(this->_buffer);
      this->_buffer = NULL;
      this->__allocated = false;
      throw error;
    }
}
