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
#include <memory>

#include "vfile.hpp"
#include "node.hpp"
#include "include/FsStat.h"
#include "include/CustomResults.h"

FsStat::FsStat()
{
  _gd_table = NULL;
}

FsStat::~FsStat()
{
  delete _gd_table;
}

void    FsStat::disp(SuperBlock * SB, VFile * vfile)
{
  general(SB);
  features(SB);
  groupInformations(SB, vfile);
}

void    FsStat::general(SuperBlock * SB)
{
  std::cout << "-------- GENERAL INFORMATIONS --------" << std::endl;
  std::cout << "Volume name : " << SB->volume_name() << std::endl;
  std::cout << "Number of blocks : " << SB->blocks_number() << std::endl;
  std::cout << "Groups number : " << SB->group_number() << std::endl;
  std::cout << "Number of inodes : " << SB->inodesNumber() << std::endl;
  std::cout << "Number of free inodes : " << SB->u_inodes_number() << std::endl;
  std::cout << "Inodes per groups : " << SB->inodes_in_group_number() << std::endl;
  std::cout << "Block size : " << SB->block_size() << std::endl;
  std::cout << "Journal inode : " << SB->journal_inode() << std::endl;
  std::cout << "Orphans inode : " << SB->orphan_node_list() << std::endl;
  std::cout << "Descriptor size : " << SB->getSuperBlock()->s_desc_size
	    << std::endl;
  std::cout << std::endl;
}

void    FsStat::features(SuperBlock * SB)
{
  std::cout << " ---- FEATURES ---- " << std::endl;
  compatible_features(SB);
  incompatible_features(SB);
  read_only_features(SB);
  std::cout << std::endl;
}

void    FsStat::compatible_features(SuperBlock * SB)
{
  std::cout << "Compatible features : "
    << CustomResults::getCompatibleFeatures(SB->compatible_feature_flags())
    << std::endl;
}

void    FsStat::incompatible_features(SuperBlock * SB)
{
  std::cout << "Incompatible features : "
    << CustomResults::getIncompatibleFeatures(SB->incompatible_feature_flags())
    << std::endl;
}

void    FsStat::read_only_features(SuperBlock * SB)
{
  std::cout << "Read only features : "
    << CustomResults::getReadOnlyFeatures(SB->ro_features_flags())
    << std::endl;
}

void    FsStat::groupInformations(SuperBlock * SB, VFile * vfile)
{
  _gd_table = getGroupDescriptor(SB->block_size(), vfile, SB->offset());
  bool    sparse = SB->useRoFeatures(SuperBlock::_SPARSE_SUPERBLOCK,
				     SB->ro_features_flags());

  std::cout << "-------- GROUPS --------" << std::endl;
  for (unsigned int i = 0; i < SB->group_number(); ++i)
    {
      std::cout << "Group " << i << std::endl;
      std::pair<uint32_t, uint32_t>   i_range
        = inode_range(SB->inodes_in_group_number(), i);
      std::cout << "Inode range : " << i_range.first << " -> "
		<< i_range.second << std::endl;

      std::pair<uint32_t, uint32_t>   b_range
        = block_range(i, SB->block_in_groups_number(), SB->blocks_number());
      std::cout << "Blocks range : " << b_range.first << " -> "
		<< b_range.second << std::endl;

      sparse_option(sparse, i, SB->block_in_groups_number());

      std::cout << "\tBlock bitmap : " << _gd_table[i].block_bitmap_addr
		<< std::endl;
      std::cout << "\tInode bitmap : " << _gd_table[i].inode_bitmap_addr
		<< std::endl;

      std::pair<uint32_t, uint32_t> it_range = inode_table_range(i, SB);
      std::cout << "\tInode table : " << it_range.first << " -> "
		<< it_range.second << std::endl;

      std::pair<uint32_t, uint32_t> data_range
        = d_range(i, SB->block_in_groups_number(), it_range.second + 1);
      std::cout << "\tData range : " << data_range.first << " -> "
		<< data_range.second << std::endl;

      std::cout << "Directories number : " << _gd_table[i].dir_nbr
		<< std::endl;

      unallocated_inodes(SB->inodes_in_group_number(), i);
      unallocated_blocks(SB->block_in_groups_number(), i,
			 SB->blocks_number());

      std::cout << std::endl;
    }
}

std::pair<uint32_t, uint32_t>
FsStat::inode_range(uint32_t i_nb_gr, uint32_t gr)
{
  uint32_t      begin;

  begin = gr * i_nb_gr;
  return std::make_pair(begin + 1, begin + i_nb_gr);
}

std::pair<uint32_t, uint32_t>
FsStat::block_range(uint32_t gr, uint32_t b_in_gr, uint32_t b_nb)
{
  uint32_t  begin, end;

  begin = gr * b_in_gr;
  end = begin + b_in_gr;
  end = (end > b_nb ? b_nb - 1 : end - 1);
  return std::make_pair(begin, end);
}

group_descr_table_t *   FsStat::getGroupDescriptor(uint32_t block_size,
						   VFile * vfile, uint64_t offset)
{
  group_descr_table_t * gd_table
    = (group_descr_table_t *)operator new(block_size);

  // read the block containing the group descriptor table.
  try
    {
      if (block_size != __BOOT_CODE_SIZE)
	vfile->seek(block_size + offset - __BOOT_CODE_SIZE);
      else
	vfile->seek(block_size + offset);
      vfile->read((void *)gd_table, block_size);
      return gd_table;
    }
  catch (vfsError & e)
    {
      // delete gd_table and throw the exception
      delete gd_table;
      throw ;
    }
}

std::pair<uint32_t, uint32_t>
FsStat::inode_table_range(uint32_t gr, SuperBlock * SB)
{
  uint32_t  begin, end;
  uint32_t  inode_per_block;

  begin = _gd_table[gr].inode_table_block_addr;
  inode_per_block = SB->block_size() / SB->inodes_struct_size();
  end = SB->inodes_in_group_number() / inode_per_block;
  return std::make_pair(begin, begin + end - 1);
}

void    FsStat::sparse_option(bool sparse, uint32_t gr, uint32_t nb_b_b)
{
  if (!sparse || (_gd_table[gr].block_bitmap_addr != (gr * nb_b_b)))
    {
      std::cout << "\tSuperBlock : " << gr * nb_b_b << std::endl;
      std::cout << "\tGroup descriptor : " << gr * nb_b_b + 1 << std::endl;
    }
}

std::pair<uint32_t, uint32_t>
FsStat::d_range(uint32_t gr, uint32_t b_gr_nb, uint32_t begin)
{
  uint32_t  end;

  end = (gr + 1) * b_gr_nb;
  return std::make_pair(begin, end - 1);
}

std::string    FsStat::unallocated_inodes(uint32_t nb_i_gr, uint32_t gr,
					  bool display)
{
  float			proportion;
  std::ostringstream	oss;
  std::string		res;

  proportion = _gd_table[gr].unallocated_inodes_nbr * 100;
  proportion /= (nb_i_gr ? nb_i_gr : 1);
  oss << _gd_table[gr].unallocated_inodes_nbr;
  oss << "(" << (int)proportion << "%)";
  res = oss.str();
  if (display)
    std::cout << res << std::endl;
  return res;
}

std::string    FsStat::unallocated_blocks(uint32_t nb_b_gr, uint32_t gr,
					  uint32_t nb_blocks, bool display)
{
  float		proportion;
  std::string	res;

  if (gr == (nb_blocks / nb_b_gr))
    nb_b_gr = (nb_blocks - gr * nb_b_gr);
  proportion = _gd_table[gr].unallocated_block_nbr * 100;
  proportion /= (nb_b_gr ? nb_b_gr : 1);

  std::ostringstream oss;
  oss << _gd_table[gr].unallocated_block_nbr;
  oss << " (" << (int)proportion << "%)";
  res = oss.str();
  if (display)
    std::cout << res << std::endl;
  return res;
}

void	FsStat::attr_stat(const SuperBlock * SB, VFile * vfile,
			  Attributes * attr)
{
  _gd_table = getGroupDescriptor(SB->block_size(), vfile, SB->offset());
  bool    sparse = SB->useRoFeatures(SuperBlock::_SPARSE_SUPERBLOCK,
				     SB->ro_features_flags());
  std::map<std::string, Variant_p > l;
  std::map<std::string, Variant_p > m;
  std::map<std::string, Variant_p > details;

  for (unsigned int i = 0; i < SB->group_number(); ++i)
    {
      std::ostringstream	oss;
      std::string		key;

      m.clear();
      details.clear();     
      key = __build_range(inode_range(SB->inodes_in_group_number(), i));
      m["Inode range"] = Variant_p(new Variant(key));      
      key = __build_range(block_range(i, SB->block_in_groups_number(),
				      SB->blocks_number()));
      m["Block range"] = Variant_p(new Variant(key));
      m["Directories number"] = Variant_p(new Variant(_gd_table[i].dir_nbr));
      key = unallocated_blocks(SB->block_in_groups_number(), i,
			       SB->blocks_number(), false);
      m["Unallocated blocks"] = Variant_p(new Variant(key));
      key = unallocated_inodes(SB->inodes_in_group_number(), i, false);
      m["Unallocated inodes"] = Variant_p(new Variant(key));
      oss << i;

      std::pair<uint32_t, uint32_t> sb_gd_bkp
	= sb_gd_backups(sparse, i, SB->block_in_groups_number());
      if (sb_gd_bkp.first != sb_gd_bkp.second)
	{
	  details["Superblock"] = Variant_p(new Variant(sb_gd_bkp.first));
	  details["Group descriptor"] = Variant_p(new Variant(sb_gd_bkp.second));
	}
      details["Block bitmap"] = Variant_p(new Variant(_gd_table[i].block_bitmap_addr));
      details["Inode bitmap"] = Variant_p(new Variant(_gd_table[i].inode_bitmap_addr));
  
      std::pair<uint32_t, uint32_t> it_range
	= inode_table_range(i, (SuperBlock *)SB);
      key = __build_range(it_range);
      details["Inode table block range"] = Variant_p(new Variant(key));

      key = __build_range(d_range(i, SB->block_in_groups_number(),
				  it_range.second + 1));
      details["Data blocks range"] = Variant_p(new Variant(key));
      m["Details"] = Variant_p(new Variant(details));
      l[std::string("Group ") + oss.str()] = Variant_p(new Variant(m));
    }
  (*attr)[std::string("File system layout")] = Variant_p(new Variant(l));
}

std::pair<uint32_t, uint32_t> FsStat::sb_gd_backups(bool sparse, 
						    uint32_t gr,
						    uint32_t nb_b_b)
{
  std::pair<uint32_t, uint32_t> p;
  if (!sparse || (_gd_table[gr].block_bitmap_addr != (gr * nb_b_b)))
    p = std::make_pair(gr * nb_b_b, gr * nb_b_b + 1);
  else
    p = std::make_pair(0, 0);
  return p;
}

std::string	FsStat::__build_range(std::pair<uint32_t, uint32_t> p)
{
  std::ostringstream	oss, oss2;
  std::string		key;

  oss << p.first;
  key = oss.str() + std::string(" -> ");
  oss2 << p.second;
  key += oss2.str();
  return key;
}
