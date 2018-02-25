/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
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

#ifndef __GPT_HPP__
#define __GPT_HPP__

#include "ipart.hpp"
#include "exceptions.hpp"
#include "vfile.hpp"
#include "node.hpp"
#include "partnode.hpp"
#include <unicode/unistr.h>
#include "export.hpp"

#include <list>

#define GPT_MAGIC	0x4546492050415254L //EFI PART

#define SYSTEM		1ULL
#define EFI_IGNORE	2ULL
#define GPT_BOOTABLE	4ULL
#define GPT_RDONLY	1ULL << 60
#define GPT_HIDDEN	1ULL << 62
#define NOAUTOMNT	1ULL << 63

PACK_START
typedef struct
{
  uint8_t	_signature[8]; // generally EFI PART
  uint8_t	_revision[4];
  uint32_t	_hsize;
  uint32_t	_crc;
  uint32_t	_reserved;
  uint64_t	_current_lba;
  uint64_t	_backup_lba;
  uint64_t	_first_usable_lba;
  uint64_t	_last_usable_lba;
  uint8_t	_disk_guid[16];
  uint64_t	_entries_lba;
  uint32_t	_entries_count;
  uint32_t	_entry_size;
  uint32_t	_entries_crc;
  //last field is reserved but not provided
  //in this structure because of different
  //sector size

  uint64_t	signature(){return (uint64_t)_signature;}
  uint32_t	headerSize();
  uint32_t	headerCrc();
  uint64_t	currentLba();
  uint64_t	backupLba();
  uint64_t	firstUsableLba() {return _first_usable_lba;};
  uint64_t	lastUsableLba() {return _last_usable_lba;};
  std::string	diskGuid()
  {
    std::stringstream	res;
    int	i;
  
    for (i = 0; i != 16; ++i)
      {
	res << std::setw(2) << std::setfill('0') << std::hex << static_cast<unsigned int>(_disk_guid[i]);
	if (i == 3 || i == 5 || i == 7 || i == 9)
	  res << "-";
      }
    return res.str();
  }
  uint64_t	entriesLba() {return _entries_lba;}
  uint32_t	entriesCount() {return _entries_count;}
  uint32_t	entrySize() {return _entry_size;}
  uint32_t	entriesCrc();
  Attributes	attributes();
}		gpt_header;
PACK_END


PACK_START
typedef struct
{
  uint8_t	_type_guid[16];
  uint8_t	_part_guid[16];
  uint64_t	_first_lba;
  uint64_t	_last_lba;
  uint8_t	_flags[8];
  char		_name[72];
  
  std::string	typeGuid()
  {
    std::stringstream	res;
    int	i;
  
    for (i = 0; i != 16; ++i)
      {
	res << std::setw(2) << std::setfill('0') << std::hex << static_cast<unsigned int>(_type_guid[i]);
	if (i == 3 || i == 5 || i == 7 || i == 9)
	  res << "-";
      }
    return res.str();
  }
  std::string	partGuid()
  {
    std::stringstream	res;
    int	i;
  
    for (i = 0; i != 16; ++i)
      {
	res << std::setw(2) << std::setfill('0') << std::hex << static_cast<unsigned int>(_part_guid[i]);
	if (i == 3 || i == 5 || i == 7 || i == 9)
	  res << "-";
      }
    return res.str();
  }
  uint64_t	firstLba() {return _first_lba;}
  uint64_t	lastLba() {return _last_lba;}
  uint64_t	size() {return  lastLba() - firstLba() + 1;}
  std::string	name()
  {
    UnicodeString	us;
    std::string		utf8;
    int			i;
    
    utf8 = "";
    if (*_name != '\0')
      {
	i = 70;
	while (i != 0 && ((uint16_t)(*(_name+i)) == 0))
	  i-=2;
	us = UnicodeString(_name, i+2, "UTF-16LE");
	us.toUTF8String(utf8);
      }
    return utf8;
  }
  Attributes	attributes();
}		gpt_entry;
PACK_END

typedef struct	s_gptmeta
{
  uint64_t	eoffset;
  uint32_t	epos;
  gpt_entry*	entry;
}		gpt_meta;

class GptPartition : public PartInterface
{
private:
  uint32_t				__hidden;
  std::map<uint64_t, gpt_meta*>		__allocated;
  std::map<uint64_t, uint64_t>		__unallocated;
  VFile*				__vfile;
  gpt_header				__header;
  void					__readHeader() throw (vfsError);
  void					__readEntries() throw (vfsError);
  void					__makeUnallocated();
  std::string				__guidMapping(std::string guid);
public:
  GptPartition();
  virtual ~GptPartition();
  virtual bool				process(Node* origin, uint64_t offset, uint32_t sectsize, bool force) throw (vfsError);
  virtual void				makeNodes(Node* root, fso* fsobj);
  virtual Attributes			entryAttributes(uint64_t entry, uint8_t type);
  virtual void				mapping(FileMapping* fm, uint64_t entry, uint8_t type);
  virtual Attributes			result();
  virtual uint32_t			entriesCount();
  virtual uint64_t			lba(uint32_t which);
};

#endif
