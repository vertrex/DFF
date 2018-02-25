/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: *www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 *
 * Author(s):
 *  Solal Jacob <sja@digital-forensic.org>
 */

#include "pff.hpp"
#include "filemapping.hpp"

PffNodeUnallocatedBlocks::PffNodeUnallocatedBlocks(std::string name, Node *parent, pff* fsobj, Node* root, int block_type) : Node(name, 0, parent, fsobj)
{
  libpff_error_t* pff_error        = NULL;
  off64_t offset                   = 0;
  size64_t size                    = 0;
  int number_of_unallocated_blocks = 0;
  int block_iterator               = 0;
  uint64_t  node_size		   = 0;

  this->root = root;
  this->block_type = block_type;

  if (libpff_file_get_number_of_unallocated_blocks(this->__pff()->pff_file(), this->block_type, &number_of_unallocated_blocks, &pff_error) != 1)
  {
     check_error(pff_error)
     return ;
  }
  if (block_type == LIBPFF_UNALLOCATED_BLOCK_TYPE_PAGE)
    fsobj->res["Number of unallocated page blocks"] = new Variant(number_of_unallocated_blocks);
  else
    fsobj->res["Number of unallocated data blocks"] = new Variant(number_of_unallocated_blocks);
  

  if (number_of_unallocated_blocks > 0)
  {
     for (block_iterator = 0; block_iterator < number_of_unallocated_blocks; block_iterator++)
     {
	if (libpff_file_get_unallocated_block(this->__pff()->pff_file(), this->block_type, block_iterator, &offset, &size, &pff_error) == 1)
	{
	  node_size += size;	
	}
        else
          check_error(pff_error)
     }
  } 
  this->setSize(node_size);
}

void	PffNodeUnallocatedBlocks::fileMapping(FileMapping* fm)
{
  libpff_error_t* pff_error        = NULL;
  off64_t offset                   = 0;
  size64_t size                    = 0;
  int number_of_unallocated_blocks = 0;
  int block_iterator               = 0;
  uint64_t voffset		   = 0;
  libpff_file_t* pff_file             = this->__pff()->pff_file();

  if (libpff_file_get_number_of_unallocated_blocks(pff_file, this->block_type, &number_of_unallocated_blocks, &pff_error) != 1)
  {
     check_error(pff_error)
     return ;
  }

  if (number_of_unallocated_blocks > 0)
  {
     for (block_iterator = 0; block_iterator < number_of_unallocated_blocks; block_iterator++)
     {
	if (libpff_file_get_unallocated_block(pff_file, this->block_type, block_iterator, &offset, &size, &pff_error) == 1)
	{
	  fm->push(voffset, size, this->root, offset);
	  voffset += size;	
	}
        else
          check_error(pff_error)
     }
  }
  return ;
}

pff*    PffNodeUnallocatedBlocks::__pff()
{
  return (static_cast<pff* >(this->fsobj()));
}
