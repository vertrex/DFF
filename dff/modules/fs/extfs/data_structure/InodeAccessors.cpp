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

#include "includes/Inode.h"

void    Inode::setVFile(VFile * vfile)
{
    _vfile = vfile;
}

const inodes_t*	Inode::getInode() const
{
    return &_inode;
}

uint16	Inode::file_mode() const
{
    return _inode.file_mode;
}

uint16	Inode::lower_uid() const
{
    return _inode.lower_uid;
}

uint32	Inode::lower_size() const
{
    return _inode.lower_size;
}

uint32	Inode::access_time() const
{
    return _inode.access_time;
}

uint32	Inode::change_time() const
{
    return _inode.change_time;
}

uint32	Inode::modif_time() const
{
    return _inode.modif_time;
}

uint32	Inode::delete_time() const
{
    return _inode.delete_time;
}

uint16	Inode::lower_gid() const
{
    return _inode.lower_gid;
}

uint16	Inode::link_coun() const
{
    return _inode.sector_count;
}

uint32	Inode::sector_count() const
{
    return _inode.sector_count;
}

uint32	Inode::flags() const
{
    return _inode.flags;
}

uint32	Inode::unused1() const
{
    return _inode.unused1;
}

const uint32*	Inode::block_pointers() const
{
    return _inode.block_pointers;
}

uint32	Inode::simple_indirect_block_pointer() const
{
    return _inode.simple_indirect_block_pointer;
}

uint32	Inode::double_indirect_block_pointer() const
{
    return _inode.double_indirect_block_pointer;
}

uint32	Inode::triple_indirect_block_pointer() const
{
    return _inode.triple_indirect_block_pointer;
}

uint32	Inode::generation_number_nfs() const
{
    return _inode.generation_number_nfs;
}

uint32	Inode::file_acl_ext_attr() const
{
    return _inode.file_acl_ext_attr;
}

uint32	Inode::upper_size_dir_acl() const
{
    return _inode.upper_size_dir_acl;
}

uint32	Inode::fragment_addr() const
{
    return _inode.fragment_addr;
}

uchar	Inode::fragment_index() const
{
    return _inode.fragment_index;
}

uchar	Inode::fragment_size() const
{
    return _inode.fragment_size;
}

uint16	Inode::unused2() const
{
    return _inode.unused2;
}

uint16	Inode::upper_uid() const
{
    return _inode.upper_uid;
}

uint16	Inode::upper_gid() const
{
    return _inode.upper_gid;
}

uint32	Inode::unused3() const
{
    return _inode.unused3;
}
