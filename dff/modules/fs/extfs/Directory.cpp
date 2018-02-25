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
 * DFF for assistance; the proje`ct provides a web site, mailing lists
 * and IRC channels for your use.
 *
 * Author(s):
 *  Romain Bertholon <rbe@digital-forensic.org>
 *
 */

//#define DIREC_DEBUG

#include <list>
#include <sstream>

#include "include/utils/InodeUtils.h"
#include "include/Directory.h"
#include "include/FileNameRecovery.h"
#include "include/MfsoAttrib.h"
#include "include/ExtfsRawDataNode.h"
#include "include/ExtfsSlackNode.hpp"

Directory::Directory(Extfs * extfs, const SuperBlock * SB,
		     GroupDescriptor * GD) : Inode(extfs, SB, GD)
{
  __i_list = new TwoThreeTree;
}

Directory::Directory(const Directory * dir)
  : Inode(dir)
{
  _recovery = dir->recovery();
  __i_list = dir->i_list();
}

Directory::~Directory()
{
}

void	Directory::dir_init()
{
  Journal * journal = NULL;

  _recovery = NULL;
  journal = new Journal(_extfs, _SB, _GD);
  if (_SB->useCompatibleFeatures(SuperBlock::_COMP_HAS_JOURNAL,
				 _SB->compatible_feature_flags()))
    if (journal->init() == false)
      {
	delete journal;
	journal = NULL;
      }
  _recovery = new FileNameRecovery(journal);
}

uint8_t		Directory::searchDirEntries(uint64_t content_addr,
					    uint64_t end_addr,
					    Node * parent)
{
  DirEntry *	dir_e = new DirEntry;
  inodes_t *	inter = new (inodes_t);
  uint8_t *	tab = (uint8_t *)operator new(end_addr - content_addr);
  std::string	name;
  uint64_t	inode_addr;
  uint8_t	valid = 0;
  ExtfsNode *	node;

  _extfs->v_seek_read(content_addr, tab, _SB->block_size());

  for (end_addr -= content_addr, content_addr = 0;
       (content_addr + 12) < end_addr; ) // a dirent is at least 12 bytes big
    {
      dir_e->setDir((dir_entry_v2 *)(tab + content_addr));

      // if the entry is valid and the name not empty
      if (((valid = _recovery->valid_entry(dir_e) == 0))
	  && !(name = _recovery->setDirName(dir_e, tab, content_addr)).empty())
        {
	  
#ifdef DIREC_DEBUG
	  if (!parent->path().empty())
	    std::cout << parent->path() << "/";
	  std::cout << parent->name() << " " << name << std::endl;

	  std::cout << "\tinode_nb : " << dir_e->inode_value() << std::endl;
	  std::cout << "\tinode addr : " << inode_addr << std::endl;
	  std::cout << "\tcontent addr : " << content_addr << " end_addr : "
		    << end_addr << std::endl;
	  std::cout << "\tentry len : " << dir_e->entry_length() << std::endl;
	  std::cout << "\tnext : " << dir_e->next() << std::endl;
#endif

	  inode_addr = getInodeByNumber(dir_e->inode_value());
	  read(inode_addr, inter);

	  if (this->is_fucked_up())
	    {
	      std::ostringstream oss;
	      oss << dir_e->inode_value();

	      new ExtfsRawDataNode(oss.str(),
		 _SB->inodes_struct_size(),
		 _extfs->suspiscious_inodes(), _extfs,
		 inode_addr + _SB->offset() - __BOOT_CODE_SIZE);
	    }

	  if (!__i_list->find(dir_e->inode_value()))
	    __i_list->insert(dir_e->inode_value());
	  else
	    {
	      if ((inter->file_mode & __IFMT) == __IFDIR)
		node = createNewNode(0, parent, name, inter);
	      else
		node = createNewNode(inode_addr, parent, name, inter);
	      if (node)
		{
		  node->set_i_nb(dir_e->inode_value());
		  if ((dir_e->entry_length() != dir_e->next()))
		    valid = _recovery->deletedFileNames(tab,  content_addr + dir_e->next(),
							parent, this, dir_e);
		}
              if (dir_e->entry_length() == 0) //avoid infinite loop XXX doesn't check end of buff
                break;
	      content_addr += dir_e->entry_length();
	      continue ;
	    }

	  std::ostringstream	oss;
	  oss << _extfs->nb_parsed_inode() << " / " << _extfs->alloc_inode();
	  _extfs->for_aiur();
	  _extfs->stateinfo = ("parsed " + oss.str() + " files");
	  
	  node = createNewNode(inode_addr, parent, name, inter);
	  if (node)
	    {
	      node->set_i_nb(dir_e->inode_value());
	      if (((inter->file_mode & __IFMT) == __IFDIR)
		  && (dir_e->file_type_v2() == DirEntry::_DIRECTORY))
		{
		  Directory * new_dir = new Directory(this);
		  new_dir->dirContent(node, inter, inode_addr, dir_e->inode_value());
		  node->setDir();
		  delete new_dir;
		}

	      if ((dir_e->entry_length() != dir_e->next()))
		valid = _recovery->deletedFileNames(tab,  content_addr + dir_e->next(),
						    parent, this, dir_e);
	    }
          if (dir_e->entry_length() == 0) //avoid infinite loop XXX doesn't check end of buff
             break;
	  content_addr += dir_e->entry_length();
	}
      else
	{
	  if ((dir_e->entry_length() != dir_e->next()))
	    valid = _recovery->deletedFileNames(tab,  content_addr + dir_e->next(),
						parent, this, dir_e);
          if (dir_e->entry_length() == 0) //avoid infinite loop XXX doesn't check end of buff
             break;
	  content_addr += dir_e->entry_length();
	}
    }
  delete inter;
  delete dir_e;
  delete tab;
  if (valid == 2)
    return false;
  return true;
}

ExtfsNode *  Directory::createNewNode(uint64_t inode_addr, Node * parent,
				      const std::string & name, inodes_t * inter)
{
  return _extfs->createVfsNode(parent, name, inode_addr, inter);
}

void    Directory::clean()
{
  delete _recovery;
  __i_list->clear();
  delete __i_list;
}

void    Directory::dirContent(Node * parent, inodes_t * inode, uint64_t a,
			      uint32_t i_nb)
{
  uint32_t	block_number;
  uint64_t	addr, i_addr = __inode_addr;
  bool		valid_dir = true;

  if (a)
    i_addr = a;
  if ((inode->file_mode & __IFMT) != __IFDIR) // we are not in a dir
    return ;

  setInode(inode);
  init();

  // skip the hash tree blocks if any
  if ((_SB->compatible_feature_flags()
       & SuperBlockStructure::_COMP_DIR_HASH_INDEX) // compatible feature
      && (flags() & 0x1000)) // hash indexed dir
    if (!_current_block)
      nextBlock();

  block_number = nextBlock();
  while (block_number) // get all directory inode blocks
    {
      addr = ((uint64_t)block_number) * ((uint64_t)_SB->block_size());
      valid_dir = searchDirEntries(addr, addr + _SB->block_size(), parent);
      this->_calculated_size += _SB->block_size();
      uint32_t nblock = nextBlock();
      if (nblock == block_number)
        break;
      block_number = nblock; 
    }

  if (!valid_dir) /*if one or several invalid dirents were found,
		       mark the inode as suspiscious */
    {
	std::ostringstream	oss;

	oss << i_nb;
	new ExtfsNode(oss.str(), this->lower_size(),
	_extfs->suspiscious_dir(),
	_extfs, i_addr, false, _extfs->addBlockPointers);
    }
}

FileNameRecovery *    Directory::recovery() const
{
  return _recovery;
}

TwoThreeTree *	Directory::i_list() const
{
  return __i_list;
}
