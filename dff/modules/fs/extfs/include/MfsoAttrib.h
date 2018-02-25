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

#ifndef MFSO_ATTRIB
#define MFSO_ATTRIB

#include "node.hpp"
#include "../data_structure/includes/Inode.h"

typedef std::map<std::string, Variant_p > Attributes;

class	MfsoAttrib
{
public :
  MfsoAttrib();
  ~MfsoAttrib();

  void		setAttrs(Inode * inode, DFF::Attributes * attr, uint64_t i_nb,
			 uint64_t i_addr);
private :
  void		__add_acl(Inode * inode, DFF::Attributes * attr);
  void		__add_xtd_attr(Inode * inode, DFF::Attributes * attr);
  void		__symlink_path(Inode * inode, DFF::Attributes * attr);
};

#endif
