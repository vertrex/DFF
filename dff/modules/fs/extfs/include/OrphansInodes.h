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

#ifndef ORPHANS_INODES_H_
#define ORPHANS_INODES_H_

#include "vfile.hpp"
#include "TwoThreeTree.hpp"
#include "../data_structure/includes/SuperBlock.h"
#include "../data_structure/includes/GroupDescriptor.h"
#include "../extfs.hpp"

class	OrphansInodes
{
  /*!
    \brief Create nodes for orphaned inodes.

    This class is used to identify orphaned inodes. Orphaned
    inodes are inodes (allocated or not) that have block pointers
    but were not be parsed with the rest of the file system.

    This can happened if the have no parents.
  */

public :
  /*!
    \brief Initialisation
    \param parsed_i_list the list of the already parsed inodes.
  */
  OrphansInodes(TwoThreeTree * parsed_i_list);

  //! Do nothing.
  ~OrphansInodes();


  /*!
    \brief create the nodes for orphaned inodes.

    \param extfs a pointer to the \e \i mfso object of the module.
  */
  void	load(class Extfs * extfs);

private :
  TwoThreeTree *	__i_list;
};

#endif
