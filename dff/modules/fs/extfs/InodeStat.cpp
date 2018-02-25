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

#include <sstream>
#include <memory>

#include "include/InodeStat.h"
#include "include/utils/InodeUtils.h"
#include "include/CustomAttrib.h"

InodeStat::InodeStat(SuperBlock * SB, Extfs * extfs)
{
  _SB = SB;
  _extfs = extfs;
}

InodeStat::~InodeStat()
{
}

void		InodeStat::stat(std::string opt)
{
  size_t	pos;
  uint32_t	inode_nb;

  while ((pos = opt.rfind(",")) != std::string::npos)
    {
      std::string tmp =   opt.substr(pos + 1, opt.size());
      opt = opt.substr(0, pos);

      std::istringstream  iss(tmp);
      iss >> inode_nb;

      stat(inode_nb);
    }
  std::istringstream iss2(opt);
  iss2 >> inode_nb;
  stat(inode_nb);
}

void    InodeStat::stat(uint32_t inode_nb)
{
  std::auto_ptr<GroupDescriptor> GD (new GroupDescriptor(_SB, _SB->block_size()));
  CustomAttrib *  attr = new CustomAttrib;
  std::auto_ptr<Inode> inode(new Inode(_extfs, _SB, GD.get()));
  std::map<std::string, const char *> times;
  uint64_t inode_addr = 0;
  inodes_t inode_struct;

  GD->init(_SB->block_size(), _extfs->vfile(), _SB->group_number());
  try
    {
      inode->setInode(&inode_struct);
      _extfs->v_seek_read((inode_addr = inode->getInodeByNumber(inode_nb)),
			  (void *)inode->inode(), sizeof(inodes_t));
    }
  catch(vfsError & e)
    {
      std::cerr << "InodeStat::stat(uint32_t) : vfsError exception caught : "
		<< e.error << std::endl;
      return ;
    }
  attr->imap.insert(std::make_pair("Inode number", inode_nb));
  attr->imap.insert(std::make_pair("Address", inode_addr));
  attr->imap.insert(std::make_pair("Size (in Bytes)",
				   inode->getSize(inode->lower_size(),
				   inode->upper_size_dir_acl(), true)));
  if (inode->flags() & 0x80000)
    attr->smap.insert(std::make_pair("Inode uses extents", "yes"));
  else
    attr->smap.insert(std::make_pair("Inode uses extents", "no"));
  attr->imap.insert(std::make_pair("Group", inode->groupNumber(inode_nb)));
  attr->smap.insert(std::make_pair("mode", inode->type_mode(inode->file_mode())));
  attr->setAttr(inode.get());
  attr->setSetUidGid(inode.get());
  attr->setUidGid(inode.get());
  attr->setTime(inode.get());
  
  std::cout << "Inode nb " << inode_nb << std::endl; 
  display(attr->imap);
  display(attr->smap);

  if (inode->file_acl_ext_attr())
    {
      std::auto_ptr<ExtendedAttr>
	ext_attr(new ExtendedAttr(inode->file_acl_ext_attr(),
				  _SB->block_size()));
      ext_attr->init(_extfs);
      disp_xattr(ext_attr.get());
      disp_acl(ext_attr.get());
    }
    block_list(inode.get());
    std::cout << std::endl;
}

template <typename T>
void    InodeStat::display(const std::map<std::string, T > & attr)
{
  typename std::map<std::string, T >::const_iterator it;

  for (it = attr.begin(); it != attr.end(); it++)
    std::cout << "\t" << (*it).first << " : " 
	      << (*it).second << std::endl;
}

void	InodeStat::disp_xattr(ExtendedAttr * xattr)
{
  std::map<xattr_name_entries *,
    std::pair<std::string, std::string> >::const_iterator user;

  user = xattr->getUserXAttr().begin();
  std::cout << "\tUser attr :"  << std::endl;
  for (; user != xattr->getUserXAttr().end(); user++)
    std::cout << "\t\tuser." << (*user).second.first << "="
	      << (*user).second.second << std::endl;
  std::cout << std::endl;
}

void	InodeStat::disp_acl(ExtendedAttr * xattr)
{
  std::map<xattr_name_entries *,
    std::list<posix_acl_entries * > >::const_iterator acl;

  std::cout << "\tACL :" << std::endl;
  acl = xattr->getPosixACL().begin();
  for (; acl != xattr->getPosixACL().end(); acl++)
    {
      std::list<posix_acl_entries *>::const_iterator acl_l 
	= (*acl).second.begin();
      while (acl_l != (*acl).second.end())
	{
	  std::cout << "\t\t";
	  if (xattr->acl_size((*acl_l)->type) == sizeof(posix_acl_entries))
	    {
	      std::cout << "id : " << (*acl_l)->user_group_id;
	      std::cout << xattr->aclPermissions((*acl_l)->permissions)
			<< std::endl;	  
	    }
	  acl_l++;
	}
    }
}

void		InodeStat::block_list(Inode * inode)
{
  uint32_t	block_number;
  uint32_t	tmp = _SB->block_size() / 4;
  uint32_t	tab = 0;

  if (inode->flags() & 0x80000) // extents, do nothing for now
    ;
  else
    for(uint32_t i = 0; i <= (tmp * tmp); ++i)
      {
	block_number = inode->goToBlock(i);
	if (i == 0)
	  {
	    std::cout << "\nDirect blocks :" << std::endl;
	    tab = 1;
	  }
	else if (i == 12)
	  {
	    std::cout << "\nSingle indirect blocks :" << std::endl;
	    tab = 1;
	  }
	else if ((i - 12) == tmp)
	  {
	    std::cout << "\nDouble indirect blocks :" << std::endl;
	    tab = 1;
	  }
	else if ((i - 12 - tmp) == (tmp * tmp))
	  {
	    std::cout << "\nTriple indirect blocks :" << std::endl;
	    tab = 1;
	  }

	if (block_number)
	  {
	    std::cout << "\t" << block_number;
	    if (!(tab % 8))
	      std::cout << std::endl;
	    tab++;
	  }
      }
}
