/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 *
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
 *  Romain Bertholon <rbe@digital-forensic.org>
 *
 */

#include <iostream>
#include <stdlib.h>
#include <string.h>

#include "exceptions.hpp"
#include "vfile.hpp"

#include "includes/DirEntry.h"

DirEntry::DirEntry()
{
    _name = NULL;
}

DirEntry::~DirEntry()
{
}

dir_entry_v2 *	DirEntry::getDir()
{
    return _dir;
}

uint8_t * DirEntry::allocName()
{
    _name = (uint8_t *)operator new ((name_length_v2() + 1)
                                   * sizeof(uint8_t));
    if (!_name)
        throw DFF::vfsError("DirEntry::allocName() : "
                       "cannot alocate enough memory.\n");
    return _name;
}

void    DirEntry::read(uint64_t content_addr, DFF::VFile * vfile)
{
  vfile->seek(content_addr);
  vfile->read(getDir(), sizeof(dir_entry_v2));
  allocName();
  vfile->read(getName(), name_length_v2());
  getName()[name_length_v2()] = '\0';
}

uint64_t    DirEntry::next()
{
    uint32_t real_size;

    real_size = sizeof(dir_entry_v2) + this->name_length_v2();
    real_size += (4 - (real_size % 4));

    return real_size;
}

uint8_t * DirEntry::getName()
{
    return _name;
}

uint32_t	DirEntry::inode_value() const
{
    return _dir->inode_value;
}

uint16_t	DirEntry::entry_length() const
{
    return _dir->entry_length;
}

uint8_t DirEntry::name_length_v2() const
{
    return _dir->name_length;
}

uint16_t DirEntry::name_length_v1() const
{
  return ((dir_entry_v1 *)_dir)->name_length;
}

uint8_t	DirEntry::file_type_v2() const
{
    return _dir->file_type;
}

void	DirEntry::setDir(dir_entry_v2 * dir)
{
  _dir = dir;
}

void	DirEntry::setName(uint8_t * name)
{
  _name = name;
}
