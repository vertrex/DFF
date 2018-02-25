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

#include "bootsector.hpp"

BootSector::BootSector() : err(0), errlog(std::string("")), __bs(bootsector()), __attrs(Attributes())
{
}

BootSector::~BootSector()
{
}

void	BootSector::process(Node *origin, fso* fsobj) throw (std::string)
{
  uint32_t		bread;
  BootSectorNode*	bsnode;
  ReservedSectors*	reserved;
  FileSystemSlack*	fsslack;
  VFile*		vfile;

  if (origin == NULL || fsobj == NULL)
    return;
  try
    {
      vfile = origin->open();
      bread = vfile->read(&(this->__bs), sizeof(bootsector));
      vfile->close();
    }
  catch(...)
    {
      vfile->close();
      throw(std::string("BootSector: Error while reading file"));
    }
  if (bread == 512)
    {
      this->fillCtx();
      bsnode = new BootSectorNode("MBR", 512, NULL, fsobj);
      bsnode->setContext(origin, this->__attrs, 0);
      fsobj->registerTree(origin, bsnode);
      if (this->reserved != 0)
	{
	  reserved = new ReservedSectors("reserved sectors", (uint64_t)(this->reserved) * (uint64_t)this->ssize, NULL, fsobj);
	  reserved->setContext((uint64_t)this->reserved, (uint64_t)this->ssize, origin);
	  fsobj->registerTree(origin, reserved);
	}
      if (this->totalsize < origin->size())
	{
	  fsslack = new FileSystemSlack("file system slack", origin->size() - this->totalsize, NULL, fsobj);
	  fsslack->setContext(totalsize, ssize, origin);
	  fsobj->registerTree(origin, fsslack);
	}
    }
  else
    throw(std::string("Not enough bytes read to decode boot sector"));
}

void	BootSector::fillSectorSize()
{
  this->ssize = *((uint16_t*)this->__bs.ssize);
  if ((this->ssize != 512) &&
      (this->ssize != 1024) &&
      (this->ssize != 2048) &&
      (this->ssize != 4096))
    {
      this->errlog += "invalid sector size field\n";
      this->err |= BADSSIZE;
    }
}

void	BootSector::fillClusterSize()
{
  this->csize = this->__bs.csize;
  if ((this->csize != 0x01) &&
      (this->csize != 0x02) &&
      (this->csize != 0x04) &&
      (this->csize != 0x08) &&
      (this->csize != 0x10) &&
      (this->csize != 0x20) &&
      (this->csize != 0x40) && 
      (this->csize != 0x80))
    {
      this->errlog += "invalid cluster size field\n";
      this->err |= BADCSIZE;
    }
}

void   BootSector::fillTotalSector()
{
  uint16_t	sectors16;
  uint32_t	sectors32;

  sectors16 = *((uint16_t*)this->__bs.sectors16);
  sectors32 = *((uint32_t*)this->__bs.sectors32);
  if (sectors16 != 0)
    this->totalsector = (uint32_t)sectors16;
  else if (sectors32 != 0)
    this->totalsector = sectors32;
  else
    {
      this->errlog += "total sector field not defined\n";
      this->err |= BADTOTALSECTOR;
    }
//   if (this->totalsector * this->ssize > this->node->size())
//     this->warnlog.push_back("total sector size ");
}

void	BootSector::fillReserved()
{
  this->reserved = *((uint16_t*)this->__bs.reserved);
  if (((this->err & BADTOTALSECTOR) != BADTOTALSECTOR) && (this->reserved > this->totalsector))
    {
      this->errlog += "number of reserved sector(s) exceeds total number of sectors\n";
      this->err |= BADRESERVED;
    }
}

//if numfat setted to 0, search for FAT pattern
void	BootSector::fillSectorPerFat()
{
  uint16_t	sectperfat16;
  uint32_t	sectperfat32;

  this->sectperfat = 0;
  sectperfat16 = *((uint16_t*)this->__bs.sectperfat16);
  sectperfat32 = *((uint32_t*)this->__bs.a.f32.sectperfat32);
  if (sectperfat16 != 0)
    this->sectperfat = (uint32_t)sectperfat16;
  else if (sectperfat32 != 0)
    this->sectperfat = sectperfat32;
  else
    {
      this->errlog += "total sector per fat not defined\n";
      this->err |= BADSECTPERFAT;
    }
  if (((this->err & BADTOTALSECTOR) != BADTOTALSECTOR) && (this->sectperfat > this->totalsector))
    {
      this->errlog += "total number of sector(s) per fat exceeds total number of sectors\n";
      this->err |= BADSECTPERFAT;
    }
}

void	BootSector::fillNumberOfFat()
{
  this->numfat = this->__bs.numfat;
  if (this->numfat == 0)
    {
      this->errlog += "number of fat not defined\n";
      this->err |= BADNUMFAT;
    }
  if (((this->err & BADTOTALSECTOR) != BADTOTALSECTOR) && 
      ((this->err & BADSECTPERFAT) != BADSECTPERFAT) &&
      ((this->numfat * this->sectperfat) > this->totalsector))
    {
      this->errlog += "total number of sector allocated for FAT(s) exceeds total number of sectors\n";
      this->err |= BADNUMFAT;
    }
}

void	BootSector::fillNumRoot()
{
  this->numroot = *((uint16_t*)this->__bs.numroot);
}

void		BootSector::fillFatType()
{
  this->rootdirsector = ((this->numroot * 32) + (this->ssize - 1)) / this->ssize;
  this->rootdirsize = (this->numroot * 32);
  this->datasector = this->reserved + (this->numfat * this->sectperfat) + this->rootdirsector;
  this->totaldatasector = this->totalsector - (this->reserved + (this->numfat * this->sectperfat) + this->rootdirsector);
  this->totalcluster = this->totaldatasector / this->csize;
  this->firstfatoffset = (int32_t)this->reserved * (uint32_t)this->ssize;

  if(this->totalcluster < 4085)
    this->fattype = 12;
  else if(this->totalcluster < 65525)
    this->fattype = 16;
  else
    this->fattype = 32;
}

void	BootSector::fillExtended()
{
  this->totalsize = (uint64_t)this->totalsector * this->ssize;
  this->totaldatasize = (uint64_t)this->totaldatasector * this->ssize;
  if (this->fattype == 32)
    {
      this->vol_id = *((uint32_t*)this->__bs.a.f32.vol_id);
      memcpy(this->vol_lab, this->__bs.a.f32.vol_lab, 11);
      memcpy(this->fs_type, this->__bs.a.f32.fs_type, 8);
      this->rootclust = *((uint32_t*)this->__bs.a.f32.rootclust);
      this->ext_flag = *((uint16_t*)this->__bs.a.f32.ext_flag);
      this->fs_ver = *((uint16_t*)this->__bs.a.f32.fs_ver);
      this->fsinfo = *((uint16_t*)this->__bs.a.f32.fsinfo);
      this->bs_backup = *((uint16_t*)this->__bs.a.f32.bs_backup);
      this->drvnum = this->__bs.a.f32.drvnum;
      this->rootdiroffset = ((this->rootclust - 2) * this->csize) + this->datasector * this->ssize;
      this->dataoffset = this->reserved * this->ssize + this->fatsize * this->numfat;
    }
  else
    {
      this->vol_id = *((uint32_t*)this->__bs.a.f16.vol_id);
      memcpy(this->vol_lab, this->__bs.a.f16.vol_lab, 11);
      memcpy(this->fs_type, this->__bs.a.f16.fs_type, 8);
      this->rootdiroffset = this->firstfatoffset + this->fatsize * this->numfat;
      this->dataoffset = this->firstfatoffset + this->fatsize * this->numfat + rootdirsector * this->ssize;
    }
}

void	BootSector::fillCtx()
{
  memcpy(this->oemname, this->__bs.oemname, 8);
  this->fillSectorSize();
  this->fillClusterSize();
  this->fillTotalSector();
  this->fillReserved();
  this->fillSectorPerFat();
  this->fillNumberOfFat();
  this->fillNumRoot();
  this->prevsect = *((uint32_t*)this->__bs.prevsect);
  if (this->err != 0)
    {
      throw(std::string("bad bootsector"));
    }
  else
    {
      this->fatsize = this->sectperfat * this->ssize;
      this->fillFatType();
      this->fillExtended();
      this->__attrs["fat type"] = Variant_p(new Variant(this->fattype));
      this->__attrs["oemname"] = Variant_p(new Variant(this->oemname));
      this->__attrs["sector size"] = Variant_p(new Variant(this->ssize));
      this->__attrs["sectors per cluster"] = Variant_p(new Variant(this->csize));
      this->__attrs["reserved cluster"] = Variant_p(new Variant(this->reserved));
      this->__attrs["number of fat"] = Variant_p(new Variant(this->numfat));
      this->__attrs["number of entries in root directory"] = Variant_p(new Variant(this->numroot));
      this->__attrs["number of sectors before FS partition"] = Variant_p(new Variant(this->prevsect));
      this->__attrs["volume id"] = Variant_p(new Variant(this->vol_id));
      this->__attrs["volume label"] = Variant_p(new Variant(this->vol_lab));
      this->__attrs["FS type"] = Variant_p(new Variant(this->fs_type));
      this->__attrs["root cluster"] = Variant_p(new Variant(this->rootclust));
      this->__attrs["total sectors for data"] = Variant_p(new Variant(this->totaldatasector));
      this->__attrs["total sectors"] = Variant_p(new Variant(this->totalsector));
      this->__attrs["sectors per fat"] = Variant_p(new Variant(this->sectperfat));
      this->__attrs["total clusters"] = Variant_p(new Variant(this->totalcluster));
      this->__attrs["first sector of root directory"] = Variant_p(new Variant(this->rootdirsector));
      this->__attrs["offset of first fat"] = Variant_p(new Variant(this->firstfatoffset));
      this->__attrs["offset of root directory"] = Variant_p(new Variant(this->rootdiroffset));
      this->__attrs["size of root directory"] = Variant_p(new Variant(this->rootdirsize));
      this->__attrs["start offset of data"] = Variant_p(new Variant(this->dataoffset));
      this->__attrs["first sector of data"] = Variant_p(new Variant(this->datasector));
      this->__attrs["size of fat"] = Variant_p(new Variant(this->fatsize));
      this->__attrs["total size"] = Variant_p(new Variant(this->totalsize));
      this->__attrs["total data size"] = Variant_p(new Variant(this->totaldatasize));
    }
}

BootSectorNode::BootSectorNode(std::string name, uint64_t size, Node* parent, fso* fsobj)  : Node(name, size, parent, fsobj), __attrs(Attributes()), __offset(0), __origin(NULL)
{
}


BootSectorNode::~BootSectorNode()
{
}

void	BootSectorNode::setContext(Node* origin, Attributes attrs, uint64_t offset)
{
  this->__origin = origin;
  this->__attrs = attrs;
  this->__offset = offset;
}

void	BootSectorNode::fileMapping(FileMapping* fm)
{
  fm->push(0, 512, this->__origin, this->__offset);
}

Attributes	BootSectorNode::_attributes()
{
  return this->__attrs;
}

const std::string	BootSectorNode::dataType()
{
  return std::string("fat/bootsector");
}


ReservedSectors::ReservedSectors(std::string name, uint64_t size, Node* parent, fso* fsobj) : Node(name, size, parent, fsobj), __fsobj(NULL), __sreserved(0), __ssize(0), __origin(0)
{
}

ReservedSectors::~ReservedSectors()
{
}

void		ReservedSectors::setContext(uint64_t reserved, uint64_t ssize, Node* origin)
{
  this->__sreserved = reserved;
  this->__ssize = ssize;
  this->__origin = origin;
}

const std::string	ReservedSectors::dataType()
{
  return std::string("fat/reserved-sectors");
}

void		ReservedSectors::fileMapping(FileMapping* fm)
{
  fm->push(0, this->__sreserved * this->__ssize, this->__origin, 0);
}

Attributes	ReservedSectors::_attributes(void)
{
  Attributes	attrs;

  attrs["starting sector"] = Variant_p(new Variant(1));
  attrs["total sectors"] = Variant_p(new Variant(this->__sreserved));
  return attrs;
}


FileSystemSlack::FileSystemSlack(std::string name, uint64_t size, Node* parent, fso* fsobj) : Node(name, size, parent, fsobj), __totalsize(0), __ssize(0), __origin(NULL)
{
}

FileSystemSlack::~FileSystemSlack()
{
}

void		FileSystemSlack::setContext(uint64_t totalsize, uint16_t ssize, Node* origin)
{
  this->__totalsize = totalsize;
  this->__ssize = ssize;
  this->__origin = origin;
}

void		FileSystemSlack::fileMapping(FileMapping* fm)
{
  uint64_t	offset;
  uint64_t	size;

  offset = this->__totalsize;
  size = this->__origin->size() - offset;
  fm->push(0, size, this->__origin, offset);
}

Attributes	FileSystemSlack::_attributes(void)
{
  Attributes	attrs;
  uint64_t	esect;
  uint64_t	tsect;
  uint64_t	ssect;
  
  esect = this->__origin->size() / this->__ssize;
  tsect = (this->__origin->size() - this->__totalsize) / this->__ssize;
  ssect = esect - tsect;
  attrs["ending sector"] = Variant_p(new Variant(esect));
  attrs["total sectors"] = Variant_p(new Variant(tsect));
  attrs["starting sector"] = Variant_p(new Variant(ssect));
  return attrs;
}


const std::string	FileSystemSlack::dataType()
{
  return std::string("fat/slackspace");
}
