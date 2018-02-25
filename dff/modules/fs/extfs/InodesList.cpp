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
#include <sstream>

#include "include/InodesList.h"
#include "include/InodeStat.h"
#include "data_structure/includes/Inode.h"

InodesList::InodesList(SuperBlock * SB, VFile * vfile)
{
  _begin = 0;
  _end = 0;
  _SB = SB;
  _vfile = vfile;
}

InodesList::~InodesList()
{
}

void    InodesList::list(const std::string & opt, uint32_t nb_inodes)
  throw (vfsError)
{
  size_t  pos;

  if ((pos = opt.find("-")) != std::string::npos)
    {
      std::string		tmp = opt.substr(pos + 1, opt.size() - 1);
      std::istringstream	iss(tmp);
      iss >> _end;
    }

  std::stringstream  iss;
  if (pos == std::string::npos)
    iss << opt;
  else
    iss << opt.substr(0, pos);
  iss >> _begin;
  if (_end && (_begin > _end))
    throw vfsError("InodesList::list() : last inode number > first.");
  if (!check_inode_range(nb_inodes))
    throw vfsError("InodesList::list() : inodes out of range.");
}

bool  InodesList::check_inode_range(uint32_t nb_inodes)
{
  bool    ok;

  ok = (_begin > nb_inodes);
  if (_end)
    ok = (_end > nb_inodes);
  return !ok;
}

void    InodesList::display(Extfs * extfs)
{
  for (uint32_t it = _begin; it <= _end; ++it)
    infos(extfs, it);
  if (!_end)
    infos(extfs, _begin);
}

void    InodesList::infos(Extfs * extfs, uint32_t inode_nb)
{
  std::auto_ptr<Inode>    i (new Inode(extfs, _SB, extfs->GD()));
  inodes_t	inode;
  i->setInode(&inode);

  std::string	alloc; 
  uint64_t	size;
  bool		large_files;
  InodeStat	i_stat(_SB, extfs);

  // read inode and gt its allocation status.
  i->read(i->getInodeByNumber(inode_nb), &inode);
  alloc = i->allocationStatus(inode_nb, extfs->vfile());

  std::cout << inode_nb << " | " << alloc;
  std::cout << " | " << i->type(i->file_mode()) << i->mode(i->file_mode());

  // access time
  if (i->access_time())
    disp_time("A", i->access_time());

  // modification time
  if ( i->modif_time())
    disp_time("M", i->modif_time());

  // change time
  if ( i->change_time())
    disp_time("C", i->change_time());

  // deletion time
  if (i->delete_time())
    disp_time("D", i->delete_time());
 
  std::cout << " | UID / GID : " 
	    << i->uid_gid(i->lower_uid(), i->lower_gid());

  large_files =	_SB->useRoFeatures(SuperBlock::_LARGE_FILE, 
				   _SB->ro_features_flags());
  size = i->getSize(i->lower_size(), i->upper_size_dir_acl(),
		    large_files);
  if (size)
    std::cout << " | " << size << "B";
  if (i->file_acl_ext_attr())
    std::cout << " | Ext attr : " << i->file_acl_ext_attr();
  std::cout << std::endl;
}

void	InodesList::disp_time(const std::string & name, const uint32_t t)
{
  #ifndef WIN32
  if (t)
    {
	
      time_t		ti = t;
	  
      std::string	t_str = ctime(&ti);

      t_str[t_str.size() - 1] = 0;
      std::cout << " | " << name << " : " << t_str;
	  
    }
  #endif
}
