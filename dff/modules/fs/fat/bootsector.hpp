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

#ifndef __BOOTSECTOR_HPP__
#define __BOOTSECTOR_HPP__

#include <list>
#include <string>
#include <stdint.h>

#include "vfile.hpp"
#include "fso.hpp"
#include "node.hpp"
#include "filemapping.hpp"
#include "variant.hpp"

using namespace DFF;

typedef struct
{
  uint8_t	f1[3];
  char		oemname[8];
  uint8_t	ssize[2];       /* sector size in bytes */
  uint8_t	csize;          /* cluster size in sectors */
  uint8_t	reserved[2];    /* number of reserved sectors for boot sectors */
  uint8_t	numfat;         /* Number of FATs */
  uint8_t	numroot[2];     /* Number of Root dentries */
  uint8_t	sectors16[2];   /* number of sectors in FS */
  uint8_t	f2[1];
  uint8_t	sectperfat16[2];        /* size of FAT */
  uint8_t	f3[4];
  uint8_t	prevsect[4];    /* number of sectors before FS partition */
  uint8_t	sectors32[4];   /* 32-bit value of number of FS sectors */

  /* The following are different for fat12/fat16 and fat32 */
  union
  {
    struct
    {
      uint8_t	f5[3];
      uint8_t	vol_id[4];
      uint8_t	vol_lab[11];
      uint8_t	fs_type[8];
      uint8_t	f6[448];
    } f16;
    struct
    {
      uint8_t	sectperfat32[4];
      uint8_t	ext_flag[2];
      uint8_t	fs_ver[2];
      uint8_t	rootclust[4];   /* cluster where root directory is stored */
      uint8_t	fsinfo[2];      /* TSK_FS_INFO Location */
      uint8_t	bs_backup[2];   /* sector of backup of boot sector */
      uint8_t	f5[12];
      uint8_t	drvnum;
      uint8_t	f6[2];
      uint8_t	vol_id[4];
      uint8_t	vol_lab[11];
      uint8_t	fs_type[8];
      uint8_t	f7[420];
    } f32;
  } a;

  uint8_t	magic[2];       /* MAGIC for all versions */

} bootsector;

typedef struct
{
  char		oemname[8];
  uint16_t	ssize;
  uint8_t	csize;
  uint16_t	reserved;
  uint8_t	numfat;
  uint16_t	numroot;
  uint32_t	prevsect;
  uint32_t	vol_id;
  uint8_t	vol_lab[11];
  uint8_t	fs_type[8];

  //Only for Fat32
  uint16_t	ext_flag;
  uint16_t	fs_ver;
  uint32_t	rootclust;
  uint16_t	fsinfo;
  uint16_t	bs_backup;
  uint8_t	drvnum;
  
  //total sector count
  uint32_t	totaldatasector;
  uint32_t	totalsector;
  uint32_t	sectperfat;
  uint32_t	totalcluster;
  
  //precomputed values based on bytes per sector and cluster size
  uint32_t	rootdirsector;
  uint64_t	firstfatoffset;
  uint64_t	rootdiroffset;
  uint32_t	rootdirsize;
  uint64_t	dataoffset;
  uint32_t	datasector;
  uint32_t	fatsize;
  uint64_t	totalsize;
  uint64_t	totaldatasize;

  //fat type based on computation
  uint8_t	fattype;
}		fsctx;

#define BADSSIZE	0x01
#define BADCSIZE	0x02
#define BADTOTALSECTOR	0x04
#define BADRESERVED	0x08
#define BADNUMFAT	0x10
#define BADSECTPERFAT	0x20
#define BADNUMROOT	0x40
//#define BAD		0x70

#define ERRFATTYPEMASK	0x7F


class BootSector: public fsctx
{
private:
  uint8_t	err;
  std::string	errlog;
  bootsector	__bs;
  Attributes	__attrs;

  void		fillSectorSize();
  void		fillClusterSize();
  void		fillTotalSector();
  void		fillReserved();
  void		fillSectorPerFat();
  void		fillNumberOfFat();
  void		fillNumRoot();
  void		fillFatType();
  void		fillExtended();
  void		fillCtx();
//   bool		checkBootSectorFields();
//   bool		fillBaseParameters();
//   bool		fillExtendedParameters();
public:
  BootSector();
  ~BootSector();
  void		process(Node* node, fso* fsobj) throw (std::string);
};


class BootSectorNode : public Node
{
private:
  Attributes	__attrs;
  uint64_t	__offset;
  Node*		__origin;
public:
  BootSectorNode(std::string name, uint64_t size, Node* parent, fso* fsobj);
  ~BootSectorNode();
  void				setContext(Node* origin, Attributes attrs, uint64_t offset);
  virtual void			fileMapping(FileMapping* fm);
  virtual Attributes		_attributes();
  virtual const std::string	dataType();
};


class ReservedSectors: public Node
{
private:
  fso*	__fsobj;
  uint64_t	__sreserved;
  uint64_t	__ssize;
  Node*		__origin;
public:
  ReservedSectors(std::string name, uint64_t size, Node* parent, fso* fsobj);
  ~ReservedSectors();
  void				setContext(uint64_t reserved, uint64_t ssize, Node* origin);
  virtual void			fileMapping(FileMapping* fm);
  virtual Attributes		_attributes(void);
  virtual const std::string	dataType();
};


class FileSystemSlack: public Node
{
private:
  uint64_t __totalsize;
  uint16_t __ssize;
  Node*	   __origin;
public:
  FileSystemSlack(std::string name, uint64_t size, Node* parent, fso* fs);
  ~FileSystemSlack();
  void				setContext(uint64_t totalsize, uint16_t ssize, Node* origin);
  virtual void			fileMapping(FileMapping* fm);
  virtual Attributes		_attributes(void);
  virtual const std::string	dataType();
};

#endif
