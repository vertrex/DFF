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

#include <string.h>
#include <sstream>
#include <memory>

#include "extfs.hpp"
#include "include/Option.h"
#include "include/ExtfsNode.h"
#include "include/ExtfsRawDataNode.h"
#include "include/ExtfsSymLinkNode.h"
#include "data_structure/includes/Inode.h"
#include "include/FileNameRecovery.h"
#include "include/OrphansInodes.h"
#include "include/ExtfsSlackNode.hpp"
#include "include/fsck.h"

Extfs::Extfs()
  : mfso("extfs"), __root_dir(NULL), __node(NULL), __vfile(NULL),
    __first_node(NULL), __fs_node(NULL), __metadata_node(NULL),
    __first_inodes_nodes(NULL)
{
  __SB = NULL;
  __orphans_i = NULL;
  __fsck = false;
  __slack = false;

  //XXX if "extfs" shadow a parameters
  attributeHandler = new BlockPointerAttributes("extfs-extended");
}

Extfs::~Extfs()
{
  delete __SB;
  delete __GD;
  delete __root_dir;
}

void    Extfs::start(std::map<std::string, Variant_p > args)
{
  try
    {
      launch(args);
    }
  catch (envError & e)
    {
      std::cerr << "Extfs::start() : envError Exception caught : \n\t ->"
		<< e.error << std::endl;
    }
  catch (vfsError & e)
    {
      std::cerr << "Extfs::start() :  vfsError exeption caught :"
		<< std::endl << "\t -> " << e.error << std::endl;

    }
  catch (std::exception & e)
    {
      std::cerr << "Extfs::start() : std::exception caught :\n\t -> "
		<< e.what() << std::endl;
    }
  catch (...)
    {
      std::cerr << "Extfs::start() : unknown exception caught."
		<< std::endl;
    }
}

void		Extfs::launch(std::map<std::string, Variant_p > args)
{
  bool		sb_check = false;
  uint64_t	sb_force_addr;
  bool		run_driver = true;
  uint64_t	root_i_nb = ROOT_INODE;

  std::map<std::string, Variant_p >::iterator it;

  // get arguments, initialize and run.
  if ((it = args.find("file")) != args.end())
    this->__node = it->second->value<Node*>();
  else
    throw (std::string("Extfs::launch(): no parent provided"));

  if ((it = args.find("SB_addr")) != args.end())
    sb_force_addr = it->second->value<uint64_t>();
   else
    sb_force_addr = 1024;

  // initialization
  this->init(sb_check, sb_force_addr);

  Option * opt = new Option(args, __SB, __vfile, __GD);
  opt->parse(this);

  // parsing file system ?
  if ((it = args.find("dont_parse_fs")) != args.end())
    run_driver = false;

  if ((it = args.find("blockpointers")) != args.end())
    this->addBlockPointers = it->second->value<bool>();
  else
    this->addBlockPointers = false;

  if (run_driver)
    {
      bool		orphans = false;
      std::string	root_inode("");

      if ((it = args.find("i_orphans")) != args.end())
	orphans = true;

      if ((it = args.find("slack")) != args.end())
	this->__slack = true;

      if ((it = args.find("fsck")) != args.end())
	this->__fsck = true;

      if ((it = args.find("root_inode")) != args.end())
	root_i_nb = it->second->value<uint64_t>();
      else
	root_i_nb = ROOT_INODE;

      run(root_i_nb);

      /*
	parse orphans inode (i.e. inodes which are not part of the file system
	content)
      */
      if (orphans)
	__orphan_inodes();
      __root_dir->clean();

      this->registerTree(__node, __first_node);
    }
}

void	Extfs::init(bool sb_check, uint64_t sb_force_addr)
{
  __SB = new SuperBlock;
  __vfile = __node->open();
  __SB->init(__vfile, sb_check, sb_force_addr);
  __GD = new GroupDescriptor(__SB, __SB->block_size());
  __GD->init(__SB->block_size(), __vfile, __SB->group_number());
  __alloc_inode = __SB->inodesNumber() - __SB->u_inodes_number();
  __nb_parsed_inode = 0;
}

void	Extfs::run(uint64_t root_i_nb)
{
  uint64_t	addr;
  inodes_t	inode;

  __root_dir = new Directory(this, __SB, __GD);
  addr = __root_dir->getInodeByNumber(root_i_nb);
  __root_dir->setInode(&inode);
  __root_dir->dir_init();
  __root_dir->i_list()->insert(root_i_nb);
  __root_dir->read(addr, &inode);
  __first_node = new ExtfsNode("Extfs", 0, NULL, this, 0, true,
			       this->addBlockPointers);
  __fs_node = new ExtfsNode("File system", 0, __first_node, this, addr, false,
			    this->addBlockPointers);
  __fs_node->set_i_nb(root_i_nb);
  __metadata_node = new ExtfsNode("Metadata", 0, __first_node, this, 0, false,
				  this->addBlockPointers);
  __suspiscious_i = new ExtfsNode("Suspiscious inodes", 0, __first_node,
				  this, 0, false, this->addBlockPointers);
  __suspiscious_dir = new ExtfsNode("Suspiscious directory", 0, __first_node,
				    this, 0, false, this->addBlockPointers);
  __root_dir->dirContent(__fs_node, (inodes_t *)__root_dir->inode(),
			 addr, root_i_nb);
  __add_meta_nodes();
  __reserved_inodes();
  this->stateinfo = "Finished";
}

void	Extfs::v_seek_read(uint64_t addr, void * buf, uint64_t size)
{
  if (__vfile->seek(addr + __SB->offset() - __BOOT_CODE_SIZE) != (addr + __SB->offset() - __BOOT_CODE_SIZE));
  __vfile->read(buf, size);
}
 
class ExtfsNode *	Extfs::createVfsNode(Node * parent, std::string name,
					     uint64_t id, inodes_t * inode)
{
  uint64_t	size = 0;
  ExtfsNode *	node = NULL;

  if (!inode || !parent)
    return NULL;

  if (!id)
    node = new ExtfsNode(name, 0, parent, this, 0, false, false);
  else if ((inode->file_mode & __IFMT) == __IFLNK)
    {
      size = inode->lower_size;
      
      node = new ExtfsNode(name, 0, parent, this, id, false,
			   this->addBlockPointers);
    }
  else if (id && ((inode->file_mode & __IFMT) == __IFREG))
    {
      size = inode->lower_size;
      node = new ExtfsNode(name, size, parent, this, id, false,
			   this->addBlockPointers);
      node->setFile();

      if (this->__fsck)
	{
	  Fsck	fsck(inode, this->__vfile, id);
	  fsck.run(this, name);
	}
      if (this->__slack)
	createSlack(node, id);
    }
  else
    node = new ExtfsNode(name, size, parent, this, id, false,
			 this->addBlockPointers);
  return node;
}

void	Extfs::createSlack(Node * node, uint64_t addr)
{
  new ExtfsSlackNode(node->name() + ".slack", 0,
		     node->parent(), this, addr);
}

Node *	Extfs::node() const
{
  return __node;
}

class GroupDescriptor *	Extfs::GD() const
{
  return __GD;
}

class SuperBlock *	Extfs::SB() const
{
  return __SB;
}

class VFile *	Extfs::vfile() const
{
  return __vfile;
}

ExtfsNode *	Extfs::orphans() const
{
  return __orphans_i;
}

ExtfsNode *	Extfs::suspiscious_inodes() const
{
  return __suspiscious_i;
}

ExtfsNode *	Extfs::suspiscious_dir() const
{
  return __suspiscious_dir;
}

void		Extfs::__reserved_inodes()
{
  Inode *	inode = new Inode(this, __SB, __GD);
  inodes_t *	inode_s = new inodes_t;	

  __first_inodes_nodes = new ExtfsNode("Reserved inodes", 0, __first_node,
				       this, 0, false, this->addBlockPointers);
  inode->setInode(inode_s);
  for (unsigned int i = 1; i < __SB->f_non_r_inodes(); ++i)
    if ((i != ROOT_INODE) && (i != __SB->journal_inode()))
      {
	uint64_t		addr;
	ExtfsNode *		node;
	std::ostringstream	oss;

	addr = inode->getInodeByNumber(i);
	inode->read(addr, inode_s);
	oss << i;
	node = createVfsNode(__first_inodes_nodes, oss.str(), addr,
			     (inodes_t *)inode->inode());
	node->set_i_nb(i);
      }
}

void			Extfs::__add_meta_nodes()
{
  ExtfsNode *		node;
  uint64_t		gd_size;
  uint64_t		addr;

  if (__SB->journal_inode()) // create a journal node (if there is a journal)
    {
      addr = __root_dir->getInodeByNumber(__SB->journal_inode());
      node = createVfsNode(__metadata_node, "Journal", addr,
       (inodes_t *)__root_dir->recovery()->getJournal()->inode());
       node->set_i_nb(__SB->journal_inode());
    }
  new ExtfsRawDataNode("Boot code area", 1024, __metadata_node,
		       this, __SB->offset() - __BOOT_CODE_SIZE);
  new ExtfsRawDataNode("Superblock", 1024, __metadata_node, this,
		       1024 + __SB->offset() - __BOOT_CODE_SIZE);
  gd_size = __SB->group_number() * __GD->GD_size();
  gd_size += (__SB->block_size() - gd_size % __SB->block_size());
  new ExtfsRawDataNode("Group descriptor table", gd_size,
		       __metadata_node, this,
		       __GD->groupDescriptorAddr());
}

void	Extfs::__orphan_inodes()
{
  OrphansInodes *	orphans_i = new OrphansInodes(__root_dir->i_list());
  this->__orphans_i = new ExtfsNode("Orphans inodes", 0, __first_node, this, 0,
				    false, this->addBlockPointers);
  orphans_i->load(this);
}
