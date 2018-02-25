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
#include "datetime.hpp"
#include "vfile.hpp"
#include "filemapping.hpp"

#include "include/ExtfsNode.h"
#include "data_structure/includes/Inode.h"
#include "data_structure/includes/Ext4Extents.h"
#include "include/MfsoAttrib.h"
#include "include/CustomResults.h"

void	BlockPointerAttributes::__extents_block(Inode * inode, DFF::Attributes * attr)
{
  Ext4Extents	extents(NULL);
  std::list<std::pair<uint16_t, uint64_t> >   ext_list;
  std::list<std::pair<uint16_t, uint64_t> >::const_iterator it;
  std::map<std::string, Variant_p > m;
  std::list< Variant_p >	blk_l;

  extents.push_extended_blocks(inode);
  ext_list = extents.extents_list();
  it = ext_list.begin();
  while (it != ext_list.end())
    {
      std::ostringstream oss;

      oss << (*it).second;
      oss << " -> ";
      oss << (*it).first + (*it).second - 1;
      blk_l.push_back(Variant_p(new Variant(oss.str())));
      it++;
    }
  if (!blk_l.empty())
    (*attr)["Extent blocks"] = Variant_p(new Variant(blk_l));
}

void		BlockPointerAttributes::__block_pointers(Inode * inode, DFF::Attributes * attr)
{
  uint32_t	block_number;
  uint32_t	tmp = inode->SB()->block_size() / 4;
  uint32_t	i;
  std::map<std::string, Variant_p >	m;
  std::list<Variant_p >	blk_list;

  if (inode->flags() & 0x80000) // extents, do nothing for now
    __extents_block(inode, attr);
  else
    {
      uint32_t	previous_block = 0, blk = 0;

      for (i = 0; i <= (tmp * tmp); ++i)
	{
	  block_number = inode->goToBlock(i);
	  if (!previous_block)
	    blk = block_number;
	  else if (block_number != (previous_block + 1))
	    {
	      std::ostringstream	oss;

	      oss << blk << " -> " << previous_block;
	      blk_list.push_back(Variant_p(new Variant(oss.str())));
	      blk = previous_block;
	    }	    
	  previous_block = block_number;
	  if ((i == 12) && !blk_list.empty())
	    {
	      m["Direct"] = Variant_p(new Variant(blk_list));
	      blk_list.clear();
	    }
	  else if (((i - 12) == tmp) && !blk_list.empty() )
	    {
	      if (!blk_list.empty())
		{
		  m["Single indirect"] = Variant_p(new Variant(blk_list));
		  blk_list.clear();
		}
	    }
	  else if (((i - 12 - tmp) == (tmp * tmp)) && !blk_list.empty())
	    {
	      if (!blk_list.empty())
		{
		  m["Double indirect"] = Variant_p(new Variant(blk_list));
		  blk_list.clear();
		}
	    }
	}
    }
  (*attr)[std::string("Block pointers")] = Variant_p(new Variant(m));
}

BlockPointerAttributes::BlockPointerAttributes(std::string name) : AttributesHandler(name)
{
}

DFF::Attributes	BlockPointerAttributes::attributes(Node* node) 
{
   DFF::Attributes	attr;

   ExtfsNode*  enode = dynamic_cast<ExtfsNode*>(node);
   Inode * inode = enode->read_inode();

   if (inode->type_mode(inode->file_mode())[0] != 'l') // file is not a symlink
     this->__block_pointers(inode, &attr);
   return (attr);
}



ExtfsNode::ExtfsNode(std::string name, uint64_t size, Node* parent,
		     Extfs * fsobj, uint64_t inode_addr, bool is_root,
		     bool add_attribute_blocks)
  : Node (name, size, parent, fsobj)
{
  this->__inode_addr = inode_addr;
  this->__extfs = fsobj;
  this->__i_nb = 0;
  this->__is_root = is_root;
  if (add_attribute_blocks)
    this->registerAttributes(fsobj->attributeHandler);
}

ExtfsNode::~ExtfsNode()
{
}

void	ExtfsNode::fileMapping(FileMapping* fm)
{
  Inode * inode = read_inode();

  if (!inode)
    return ;
  if (inode->flags() & 0x80000) // Use extent. (should be defined in Inode.h)
    {
      Ext4Extents * ext4 = new Ext4Extents(fm);
      ext4->push_extended_blocks(inode);
      delete ext4;
    }
  else
    push_block_pointers(inode, fm);

  delete inode->inode();
  delete inode;
}

void		ExtfsNode::push_block_pointers(Inode * inode,
					       FileMapping * file_mapping)
{
  uint64_t	blk_addr, offset = 0, size;
  uint64_t	b_size = __extfs->SB()->block_size();
  uint64_t      ooffset = __extfs->SB()->offset() - __BOOT_CODE_SIZE;
  uint32_t	tmp = inode->SB()->block_size() / sizeof(uint32_t);

  size = this->size();
  if (!size)
    return ;
  while ((inode->currentBlock() < ((tmp * tmp * tmp) + (tmp * tmp) + 12)))
    {
      blk_addr = inode->nextBlock();
      if (!blk_addr)
	{
	  if (inode->currentBlock() < 12)
	    continue ;
	  if (inode->currentBlock() < tmp + 12)
	    {
	      if (!(inode->simple_indirect_block_pointer()))
		inode->goToBlock(tmp + 12);
	    }
	  else if (inode->currentBlock() < ((tmp * tmp) + 12))
	    {
	      if (!inode->double_indirect_block_pointer())
		inode->goToBlock((tmp * tmp) + 12);
	    }
	  else if (!inode->triple_indirect_block_pointer())
	    {
	      break ;
	    }
	}
      else if (__extfs->SB()->block_size() < size)
	{
	  size -= b_size;
	  file_mapping->push(offset, b_size, __extfs->node(),
			     blk_addr * __extfs->SB()->block_size() + ooffset);
	  offset += inode->SB()->block_size();
	}
      else
	{
	  file_mapping->push(offset, size, __extfs->node(),
			     blk_addr * __extfs->SB()->block_size() + ooffset);
	  break ;
	}
    }
}

DFF::Attributes 	ExtfsNode::_attributes()
{
  DFF::Attributes	attr;
  Inode	*	inode = this->read_inode();

  if (!inode)
    return (attr);
  if (this->__is_root)
    {
      CustomResults c_res;
      c_res.set(&attr, inode);
    }
  else
    {
      MfsoAttrib * c_attr = new MfsoAttrib;
      c_attr->setAttrs(inode, &attr, this->__i_nb, this->__inode_addr);

      attr["modified"] = Variant_p(new Variant(new DateTime(inode->modif_time())));
      attr["accessed"] = Variant_p(new Variant(new DateTime(inode->access_time())));
      attr["changed"] = Variant_p(new Variant(new DateTime(inode->change_time())));

      if (inode->SB()->inodes_struct_size() > sizeof(inodes_t))
      {
	uint8_t * tab = (uint8_t *)operator new(sizeof(__inode_reminder_t));
	__inode_reminder_t * i_reminder = (__inode_reminder_t *)tab;

	inode->extfs()->vfile()->read(tab, sizeof(__inode_reminder_t));
	attr["creation"] = Variant_p(new Variant(new DateTime(i_reminder->creation_time)));
      }
      delete c_attr;
    }
  delete inode->inode();
  delete inode;
  return (attr);
}


void	ExtfsNode::set_i_nb(uint64_t i_id)
{
  __i_nb = i_id;
}

uint64_t	ExtfsNode::i_nb() const
{
  return __i_nb;
}

Inode *	ExtfsNode::read_inode()
{
  Inode	*	inode = NULL;
  inodes_t *	i = NULL;

  try
    {
      inode = new Inode(this->__extfs, this->__extfs->SB(),
			this->__extfs->GD());
      i = new inodes_t;
      inode->setInode(i);
      inode->read(__inode_addr, i);
      inode->init();
    }
  catch (vfsError & e)
    {
      std::cerr << "Exception caught in ExtfNode::_attributes() : "
		<< e.error << std::endl;
      delete i;
      delete inode;
      return NULL;
    }
  catch(std::exception & e)
    {
      std::cerr << "Not enought memory" << std::endl;
      delete i;
      delete inode;
      return NULL;
    }
  return inode;
}

