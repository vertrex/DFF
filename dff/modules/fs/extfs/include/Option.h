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

#ifndef _OPTION_H_
# define _OPTION_H_

#include "argument.hpp"
#include "vfile.hpp"
#include "data_structure/includes/SuperBlock.h"
#include "data_structure/includes/GroupDescriptor.h"

class	Option
{
  /*!
    \class Option
    \brief Start functionnality depending in input options.
  */

public :
  /*!
    \brief Init.

    \param arg the list of argument under a key -> value form.
    \param SB a pointer to the superblock struct
    \param vfile a pointer to the extfs vfile
    \param GD a pointer to the group descriptor struct
  */
  Option(std::map<std::string, Variant_p > arg, SuperBlock * SB, VFile * vfile, GroupDescriptor * GD);
  ~Option();

  /*!
    \brief get the options and start the functionnnalities.
    \param extfs a pointer to the extfs structure (mfso object)
  */
  void	parse(Extfs * extfs);

private :
  std::map<std::string, Variant_p > arg;
  SuperBlock *	__SB;
  VFile *	__vfile;
  GroupDescriptor *	__GD;
};

#endif
