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

#ifndef __DOS_HPP__
#define __DOS_HPP__

// API includes
#include "exceptions.hpp"
#include "fso.hpp"
#include "vfile.hpp"
#include "node.hpp"

// Module includes
#include "partnode.hpp"
#include "ipart.hpp"

// std includes
#include <vector>
#include <deque>

#define IS_EXTENDED(t) ((((t) == 0x05) || ((t) == 0x0F) || ((t) == 0x85)) ? 1 : 0)
#define GPT_PROTECTIVE	0xee

typedef struct		
{
  uint8_t		status;//0x80 = bootable, 0x00 = non-bootable, other = invalid
  uint8_t		start_head;
  uint8_t	        start_sector; //sector in bit 5-0, bits 9-8 of cylinders are in bits 7-6...
  uint8_t		start_cylinder; // bits 7-0
  uint8_t		type;
  uint8_t		end_head;
  uint8_t		end_sector; //sector in bit 5-0, bits 9-8 of cylinders are in bits 7-6...
  uint8_t		end_cylinder; //bits 7-0
  uint32_t		lba;
  uint32_t		total_blocks;
}		        dos_pte;


/*
"code" field is usually empty in extended boot record but could contain
another boot loader or something volontary hidden...  
this field could also contain IBM Boot Manager starting at 0x18A.

Normally, there are only two partition entries in extended boot records
followed by 32 bytes of NULL bytes. It could be used to hide data or even
2 other partition entries.
*/
typedef struct
{
  uint8_t	code[440];
  union
  {
    struct
    {
      uint8_t	disk_signature[4];
      uint8_t	padding[2];
    }mbr;
    struct
    {
      uint8_t	code[6];
    }ebr;
  } a;
  uint8_t	partitions[64];
  short		signature; //0xAA55
}		dos_partition_record;

typedef struct
{
  dos_pte*	pte;
  uint64_t	entry_offset;
  uint8_t	type;
  uint32_t	slot;
  uint32_t	sslot;
}		metadatum;


typedef std::map<uint64_t, metadatum* >	metamap;
typedef metamap::iterator		metaiterator;

class DosPartition : public PartInterface
{
private:
  uint32_t				__logical;
  uint32_t				__primary;
  uint32_t				__extended;
  uint32_t				__hidden;
  uint32_t				__slot;
  std::map<uint64_t, metadatum*>	__allocated;
  std::map<uint64_t, metadatum*>	__unallocated;
  VFile*				__vfile;
  uint64_t				__ebr_base;
  bool					__protective;
  dos_pte*				__toPte(uint8_t* buff);
  void					__makeUnallocated();
  void					__makeResults();
  Attributes				__entryAttributes(metaiterator mit);
  void					__readMbr() throw (vfsError);
  void					__readEbr(uint64_t cur, uint64_t shift=0) throw (vfsError);
public:
  DosPartition();
  virtual ~DosPartition();
  virtual bool				isProtective();
  virtual bool				process(Node* origin, uint64_t offset, uint32_t sectsize, bool force) throw (vfsError);
  virtual void				makeNodes(Node* root, fso* fsobj);
  virtual Attributes			result();
  virtual Attributes			entryAttributes(uint64_t entry, uint8_t type);
  virtual void				mapping(FileMapping* fm, uint64_t entry, uint8_t type);
  virtual uint32_t			entriesCount();
  virtual uint64_t			lba(uint32_t which);
};

#endif
