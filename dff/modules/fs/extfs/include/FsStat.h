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

#ifndef FSSTAT_H
#define FSSTAT_H

#include <utility>

#include "../data_structure/includes/SuperBlock.h"
#include "../data_structure/includes/GroupDescriptor.h"

class FsStat
{
  /*! \class FsStat
    \brief File system informations.

    This class' purpose is to retrieve and display informations
    about the file system which is under invgestigation.
  */

public:
  /*! \brief Constructor.
    Do nothing.
  */
  FsStat();

  /*! \brief Destructor.
    Do nothing.
  */
  ~FsStat();

  /*! \brief Display informations.

    Display informations on the file system. Can be used with
    the option --fsstat.

    \param SB a pointer to the \c \b SuperBlock instance.
    \param vfile a pointer to the virtual file system.
  */
  void    disp(SuperBlock * SB, VFile * vfile);

  /*! \brief General informations.

    Display general informations about the file system.

    \param SB a pointer to the SuperBlock instance.
  */
  void    general(SuperBlock * SB);

  /*! \brief Features.

    Display the file system features.

    \param SB a pointer to the SuperBlock instance.
  */
  void    features(SuperBlock * SB);

  /*! \brief Compatible features.

    Display the compatible features.

    \param SB a pointer to the SuperBlock instance.
  */
  void    compatible_features(SuperBlock * SB);

  /*! \brief Incompatible features.

    Display the incompatible features.

    \param SB a pointer to the SuperBlock instance.
  */
  void    incompatible_features(SuperBlock * SB);

  /*! \brief Read only features.

    Display the read-only features.

    \param SB a pointer to the SuperBlock instance.
  */
  void    read_only_features(SuperBlock * SB);

  /*! \brief Block groups.

    Display informations about block groups.

    \param SB a pointer to the \c \b SuperBlock instance.
    \param vfile a pointer to the virtual file system.
  */
  void    groupInformations(SuperBlock * SB, VFile * vfile);

  /*! \brief Inodes range.

    Calculate the first and last inode number of the group \b \e gr.

    \param i_nb_gr number of inodes per groups.
    \param gr group number.

    \return a pair containing the first and last inodes number of the
    group.
  */
  std::pair<uint32_t, uint32_t>
  inode_range(uint32_t i_nb_gr, uint32_t gr);

  /*! \brief Blocks range.

    Calculate the first and last block number of the group \b \e gr.

    \param gr the group number.
    \param b_in_gr the number of blocks per group.
    \param b_nb the total number of blocks on the file system.

    \return a pair containing the first and last blocks number of the
    group.
  */
  std::pair<uint32_t, uint32_t>
  block_range(uint32_t gr, uint32_t b_in_gr, uint32_t b_nb);

  /*! \brief Inode range.

    Calculate the first and last inode number of the group \b \e gr

    \param gr the group number
    \param SB a pointer to the SuperBlock instance

    \return a pair containing the first and last inode number of the
    group.
  */
  std::pair<uint32_t, uint32_t>
  inode_table_range(uint32_t gr, SuperBlock * SB);

  /*! \brief Data range.

    Calculate the first and last dat block number of the group \b \e gr

    \param gr the group number
    \param b_gr_nb the number of block per groups.
    \param begin the first data block of the group.

    \return a pair containing the first and last data block number of the
    group.
  */
  std::pair<uint32_t, uint32_t>
  d_range(uint32_t gr, uint32_t b_gr_nb, uint32_t begin);

  /*! \brief Group descriptor.

    Read the group descriptor table.

    \param block_size the size of a block.
    \param vfile a pointer to the virtual file system.
    \param offset the offset of the super block.

    \return a pointer to the group descriptor table.

  */
  group_descr_table_t *   getGroupDescriptor(uint32_t block_size,
					     VFile * vfile, uint64_t offset);

  /*! \brief Sparse superblock.

    \param sparse sparse option, true or false
    \param gr the group number
    \param nb_b_b the number of block.
  */
  void    sparse_option(bool sparse, uint32_t gr, uint32_t nb_b_b);
  std::pair<uint32_t, uint32_t> sb_gd_backups(bool sparse, uint32_t gr,
					      uint32_t nb_b_b);

  /*! \brief Unallocated inodes.

    \param nb_i_gr the number of inodes per groups.
    \param gr the group number.
  */
  std::string    unallocated_inodes(uint32_t nb_i_gr, uint32_t gr,
				    bool display = true);

  /*! \brief Unallocated blocks.

    \param nb_b_gr the number of blocks per groups.
    \param gr the group number.
    \param nb_blocks the number of blocks on the file system.
  */
  std::string   unallocated_blocks(uint32_t nb_b_gr, uint32_t gr,
				   uint32_t nb_blocks, bool display = true);
  void		attr_stat(const SuperBlock * SB, VFile * vfile,
			  Attributes * attr);

private:
  std::string	__build_range(std::pair<uint32_t, uint32_t>);
  group_descr_table_t * _gd_table;
};

#endif // FSSTAT_H
