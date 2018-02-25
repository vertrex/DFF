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

#include "entries.hpp"

EntriesManager::EntriesManager(uint8_t fattype)
{
  this->fattype = fattype;
  this->c = NULL;
}

EntriesManager::~EntriesManager()
{
}

// void		EntriesManager::setContext(Node* origin)
// {
// }

// void		EntriesManager::setContext(uint8_t fattype)
// {
//   this->fattype = fattype;
// }

lfnentry*	EntriesManager::toLfn(uint8_t* entry)
{
  lfnentry*	lfn;

  lfn = new lfnentry;
  lfn->order = entry[0];
  memcpy(lfn->first, entry+1, 10);
  lfn->attributes = entry[11];
  lfn->reserved = entry[12];
  lfn->checksum = entry[13];
  memcpy(lfn->second, entry+14, 12);
  memcpy(&(lfn->cluster), entry+26, 2);
  memcpy(lfn->third, entry+28, 4);
  return lfn;
}

dosentry*	EntriesManager::toDos(uint8_t* entry)
{
  dosentry*	dos;

  dos = new dosentry;
  memcpy(dos->name, entry, 8);
  memcpy(dos->ext, entry+8, 3);
  dos->attributes = entry[11];
  dos->ntres = entry[12];
  dos->ctimetenth = entry[13];
  memcpy(&(dos->ctime), entry+14, 2);
  memcpy(&(dos->cdate), entry+16, 2);
  memcpy(&(dos->adate), entry+18, 2);
  memcpy(&(dos->clusthigh), entry+20, 2);
  memcpy(&(dos->mtime), entry+22, 2);
  memcpy(&(dos->mdate), entry+24, 2);
  memcpy(&(dos->clustlow), entry+26, 2);
  memcpy(&(dos->size), entry+28, 4);
  return dos;
}

void	EntriesManager::updateLfnName(lfnentry* lfn)
{
  int	i;
  std::string	name;
  uint16_t	*ptr;

  i = 0;
  name = "";
  
  ptr = (uint16_t*)lfn->first;
  i = 0;
  while (i != 5 && *ptr != 0 && *ptr != 0xFFFF)
    {
      ptr++;
      i++;
    }
  if (i != 0)
    name.append((char*)lfn->first, i*2);

  ptr = (uint16_t*)lfn->second;
  i = 0;
  while (i != 6 && *ptr != 0  && *ptr != 0xFFFF)
    {
      ptr++;
      i++;
    }
  if (i != 0)
    name.append((char*)lfn->second, i*2);

  ptr = (uint16_t*)lfn->third;
  i = 0;
  while (i != 2 && *ptr != 0  && *ptr != 0xFFFF)
    {
      ptr++;
      i++;
    }
  if (i != 0)
    name.append((char*)lfn->third, i*2);

  this->c->lfnname = name + this->c->lfnname;
}

bool	EntriesManager::isDosName(uint8_t* buff)
{
  int	i;

  if ((buff[0] != 0xE5) && (buff[0] != '.') && (FATFS_IS_83_NAME(buff[0]) == 0))
    return false;
  if (buff[0] == 0x20)
    return false;
  if ((memcmp(buff, "\x2E\x20\x20\x20\x20\x20\x20\x20", 8) == 0) ||
      (memcmp(buff, "\x2E\x2E\x20\x20\x20\x20\x20\x20", 8) == 0))
    return false;
  else
    {
      for (i = 2; i != 8; i++)
	if (FATFS_IS_83_NAME(buff[i]) == 0)
	  return false;
      for (i = 0; i != 3; i++)
	if (FATFS_IS_83_EXT(buff[8+i]) == 0)
	  return false;
    }
  return true;
}

bool	EntriesManager::isDosEntry(uint8_t* buff)
{
  if (*(buff+11) & ATTR_VOLUME)
    {
      if ((*(buff+11) & ATTR_DIRECTORY) ||
	  (*(buff+11) & ATTR_READ_ONLY) ||
	  (*(buff+11) & ATTR_ARCHIVE))
	return false;
    }
  return this->isDosName(buff);
}

std::string			EntriesManager::formatDosname(dosentry* dos)
{
  std::string	name;
  int		i;

  name = "";
  i = 0;
  if (dos->name[0] == 0xe5)
    {
      name += "_";
      i = 1;
    }
  while ((i != 8) && (dos->name[i] != '\x20'))
    {
      if (((dos->ntres & FATFS_CASE_LOWER_BASE) == FATFS_CASE_LOWER_BASE) &&
	  (dos->name[i] >= 'A') && (dos->name[i] <= 'Z'))
	name += dos->name[i] + 32;
      else
	name += dos->name[i];
      i++;
    }
  i = 0;
  while ((i != 3) && (dos->ext[i] != '\x20'))
    {
      if (i == 0)
	name += ".";
      if (((dos->ntres & FATFS_CASE_LOWER_EXT) == FATFS_CASE_LOWER_EXT) &&
	  (dos->ext[i] >= 'A') && (dos->ext[i] <= 'Z'))
	name += dos->ext[i] + 32;
      else
	name += dos->ext[i];
      i++;
    }
  return name;
}

void	EntriesManager::setDosName(dosentry* dos)
{
  this->c->dosname = this->formatDosname(dos);
}

bool	EntriesManager::isChecksumValid(uint8_t* buff)
{
  uint8_t	sum;
  int		i;

  sum = 0;
  if (this->c->lfnmetaoffset != 0)
    {
      for (i = 11; i != 0 ; i--)
	sum = ((sum & 1) ? 0x80 : 0) + (sum >> 1) + *buff++;
      if (sum == this->c->checksum)
	return true;
      else
	return false;
    }
  else
    return true;
}

bool	EntriesManager::push(uint8_t* buff, uint64_t offset)
{
  lfnentry*	lfn;
  dosentry*	dos;

  if (this->c == NULL)
    this->initCtx();
  if (*(buff+11) > 0x3F)
    return false;
  if (((*(buff+11)) & ATTR_LFN) == ATTR_LFN)
    {
      if ((*(buff) > (FATFS_LFN_SEQ_FIRST | 0x0f))
	  && ((*buff) != 0xE5))
	return false;
      else
	{
	  lfn = this->toLfn(buff);
	  if (this->c->lfnmetaoffset == 0)
	    {
	      this->c->checksum = *(buff+13);
	      this->c->lfnmetaoffset = offset;
	    }
// 	  else if (this->c->checksum == *(buff+13))
	  this->updateLfnName(lfn);
// 	  else
// 	    {
// 	      //printf("bad checksum between: 0x%llx / 0x%llx -- prev checksum: %d -- current checksum: %d\n", this->c->lfnmetaoffset, offset, this->c->checksum, *(buff+13));
// 	      this->c->checksum = 0;
// 	      this->c->lfnmetaoffset = 0;
// 	      this->c->lfnname = "";
// 	    }
	  delete lfn;
	  return false;
	}
    }
  else
    {
      if (this->isDosEntry(buff))
	{
	  // if (this->isChecksumValid(buff))
	  //   {
 	  //     this->c->lfnmetaoffset = 0;
 	  //     this->c->lfnname = "";
 	  //   }
	  this->c->dosmetaoffset = offset;
	  dos = this->toDos(buff);
	  this->setDosName(dos);
	  if ((dos->attributes & ATTR_VOLUME) == ATTR_VOLUME)
	    this->c->volume = true;
	  if ((dos->attributes & ATTR_DIRECTORY) == ATTR_DIRECTORY)
	    {
// 	      if (dos->size != 0)
// 		this->c->valid = false;
	      this->c->dir = true;
	    }
	  if (dos->name[0] == 0xE5)
	    this->c->deleted = true;
	  this->c->size = dos->size;
	  if ((this->fattype == 12) || (this->fattype == 16))
	    this->c->cluster = dos->clustlow;
	  else
	    {
	      this->c->cluster = dos->clustlow;
	      this->c->cluster |= (dos->clusthigh << 16);
	    }
	  delete dos;
	  return true;
	}
      else
	return false;
    }
}

void	EntriesManager::initCtx()
{
  this->c = new ctx;
  this->c->valid = true;
  this->c->dosname = "";
  this->c->lfnname = "";
  this->c->dir = false;
  this->c->deleted = false;
  this->c->volume = false;
  this->c->size = 0;
  this->c->cluster = 0;
  this->c->lfnmetaoffset = 0;
  this->c->dosmetaoffset = 0;
}

// void	EntriesManager::convert()
// {
// }

ctx*	EntriesManager::fetchCtx()
{
  ctx*	ret;
  
  ret = this->c;
  this->c = NULL;
  return ret;
}
