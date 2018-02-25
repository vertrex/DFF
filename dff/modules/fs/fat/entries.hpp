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

#ifndef __LFNENTRY_HPP__
#define __LFNENTRY_HPP__

#include "node.hpp"
#include "vfile.hpp"

#define	ATTR_NORMAL	0x00
#define ATTR_READ_ONLY  0x01
#define ATTR_HIDDEN     0x02
#define ATTR_SYSTEM     0x04
#define ATTR_VOLUME	0x08
#define ATTR_DIRECTORY  0x10
#define ATTR_ARCHIVE    0x20
#define ATTR_LFN	0x0f
#define ATTR_ALL	0x3f

#define FATFS_LFN_SEQ_FIRST     0x40

#define FATFS_CASE_LOWER_BASE   0x08    /* base is lower case */
#define FATFS_CASE_LOWER_EXT    0x10    /* extension is lower case */
#define FATFS_CASE_LOWER_ALL    0x18    /* both are lower */

#define FATFS_IS_83_NAME(c)             \
  ((((c) < 0x20) ||			\
    ((c) == 0x22) ||			\
    (((c) >= 0x2a) && ((c) <= 0x2c)) || \
    ((c) == 0x2e) ||			\
    ((c) == 0x2f) ||			\
    (((c) >= 0x3a) && ((c) <= 0x3f)) || \
    (((c) >= 0x5b) && ((c) <= 0x5d)) || \
    ((c) == 0x7c)) == 0)

#define FATFS_IS_83_EXT(c)              \
  (FATFS_IS_83_NAME((c)) && ((c) < 0x7f))

using namespace DFF;

typedef struct s_dosentry
{
  uint8_t	name[8];
  uint8_t	ext[3];
  uint8_t	attributes;
  uint8_t	ntres;
  uint8_t	ctimetenth;
  uint16_t	ctime;
  uint16_t	cdate;
  uint16_t	adate;
  uint16_t	clusthigh;
  uint16_t	mtime;
  uint16_t	mdate;
  uint16_t	clustlow;
  uint32_t	size;
}		dosentry;

typedef struct s_lfnentry
{
  uint8_t	order;
  uint8_t	first[10];
  uint8_t	attributes;
  uint8_t	reserved;
  uint8_t	checksum;
  uint8_t	second[12];
  uint16_t	cluster;
  uint8_t	third[4];
}		lfnentry;

typedef struct	s_ctx
{
  bool		valid;
  std::string	dosname;
  std::string	lfnname;
  uint32_t	lfncount;
  uint8_t	checksum;
  bool		dir;
  bool		deleted;
  bool		volume;
  uint32_t	size;
  uint32_t	cluster;
  uint64_t	lfnmetaoffset;
  uint64_t	dosmetaoffset;
}		ctx;

typedef struct	s_decodedentry
{
  std::string	dosname;
  std::string	longfilename;
  bool		dir;
  bool		readonly;
  bool		hidden;
  bool		system;
  bool		archive;
  bool		deleted;
  bool		orphaned;
  DateTime*	mtime;
  DateTime*	atime;
  DateTime*	ctime;
  uint32_t	cluster;
  uint32_t	size;
  uint64_t	lfnstart;
  uint64_t	dosstart;
}		decodedentry;

class EntryConverter
{
private:
public:
  EntryConverter();
  virtual	~EntryConverter();
};

// class LfnEntry
// {
// public:
//   LfnEntry();
//   ~LfnEntry();
  
// };

class EntriesManager
{
private:
  ctx*				c;
  uint8_t			fattype;
//   uint64_t			lfnmetaoffset;
//   uint64_t			dosmetaoffset;
  //std::vector<lfnentry*>	lfns;
//   std::string			lfnname;
//   std::string			dosname;
  bool				isChecksumValid(uint8_t* buff);
  bool				isDosEntry(uint8_t* buff);
  bool				isDosName(uint8_t* buff);
  void				updateLfnName(lfnentry* lfn);
  void				setDosName(dosentry* dos);

  lfnentry*			toLfn(uint8_t* entry);
  //lfnentry*			LfnFromOffset(uint64_t offset);
  //dosentry*			DosFromOffset(uint64_t* offset);
  //void				convert(uint8_t* entry, uint64_t offset);
  void				initCtx();
public:
  EntriesManager(uint8_t fattype);
  ~EntriesManager();
  //void				setContext(Node* origin);
  std::string			formatDosname(dosentry* dos);
  dosentry*			toDos(uint8_t* entry);
  bool				push(uint8_t* buff, uint64_t offset);
  ctx*				fetchCtx();

  //compmeta*			fetchCompleteMeta();
  //explicitedentry*	explicitedEntry(uint64_t offset);
};

// typedef struct 
// {
//   uint8_t name[8];
//   uint8_t ext[3];
//   uint8_t attrib;
//   uint8_t lowercase;
//   uint8_t ctimeten;       /* create times */
//   uint8_t ctime[2];
//   uint8_t cdate[2];
//   uint8_t adate[2];       /* access time */
//   uint8_t highclust[2];
//   uint8_t wtime[2];       /* last write time */
//   uint8_t wdate[2];
//   uint8_t startclust[2];
//   uint8_t size[4];
// } dosentry;

// typedef struct
// {
//   uint8_t	name[8];
//   uint8_t	ext[3];
//   uint8_t	attrib;
//   uint8_t	lowercase;
//   uint8_t	ctimeten;       /* create times */
//   uint16_t	ctime;
//   uint16_t	cdate;
//   uint16_t	adate;       /* access time */
//   uint16_t	highclust;
//   uint16_t	wtime;       /* last write time */
//   uint16_t	wdate;
//   uint16_t	startclust;
//   uint32_t	size;
// }		dectx;

// class Dos
// {
// private:
//   bool		sanitizeEntry(dectx* ctx);
//   dectx*	createDentryCtx(Node* n);
// public:
//   Dos();
//   ~Dos();
// };

// class Entry: public Dos, LongFileName
// {
// public:
//   Entry();
//   ~Entry();
// };

#endif
