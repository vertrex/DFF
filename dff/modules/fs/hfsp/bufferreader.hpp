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

#ifndef __BUFFER_READER_HPP__
#define __BUFFER_READER_HPP__

#include <stdint.h>

#include "export.hpp"
#include "node.hpp"
#include "vfile.hpp"

using namespace DFF;

class BufferReader
{
private:
  bool		__allocated;
protected:
  Node*		_origin;
  uint64_t	_offset;
  uint16_t	_size;
  uint8_t*	_buffer;
  void		__clean();
  void		__readBuffer() throw (std::string);
  void		__dumpline(uint32_t rva, uint8_t* line, uint8_t length, uint8_t groupby);
public:
  BufferReader();
  virtual ~BufferReader();
  void		setContext(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  Node*		origin();
  uint64_t	offset();
  uint16_t	size();
  virtual void	process(uint8_t *buffer, uint16_t size) throw (std::string);
  virtual void	process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  void		hexdump(uint8_t groupby, uint16_t encoding);
};

#endif
