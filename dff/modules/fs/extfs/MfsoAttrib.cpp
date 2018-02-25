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

#include <map>
#include <sstream>

#include "data_structure/includes/ExtendedAttr.h"
#include "data_structure/includes/Ext4Extents.h"
#include "include/MfsoAttrib.h"

#include "datetime.hpp"

MfsoAttrib::MfsoAttrib()
{
}

MfsoAttrib::~MfsoAttrib()
{
}

void	MfsoAttrib::setAttrs(Inode * inode, DFF::Attributes * attr, uint64_t i_nb,
			     uint64_t i_addr)
{
  if (inode->delete_time())
      (*attr)["Deletion time"] =
	Variant_p(new Variant(new DateTime(inode->delete_time())));
  if (!i_nb)
    return ;
  (*attr)["Number"] = Variant_p(new Variant(i_nb));

  std::ostringstream	oss;
  oss << i_addr << " ( 0x" << std::hex << i_addr << ") ";

  (*attr)["Address"] = Variant_p(new Variant(oss.str()));
  (*attr)["Group"] = Variant_p(new Variant(inode->groupNumber(i_nb)));
  (*attr)["UID / GID"] =
    Variant_p(new Variant(inode->uid_gid(inode->lower_uid(), inode->lower_gid())));
  (*attr)["File mode"] =  Variant_p(new Variant(inode->type_mode(inode->file_mode())));
  (*attr)["Set UID / GID ?"] =
    Variant_p(new Variant(inode->set_uid_gid(inode->file_mode())));

  if (inode->flags() & 0x80000)
    (*attr)["Inode uses extents"] = Variant_p(new Variant(std::string("yes")));
  else
    (*attr)["Inode uses extents"] = Variant_p(new Variant(std::string("no")));

  (*attr)["Link number"] = Variant_p(new Variant(inode->link_coun()));
  (*attr)["Sector count"] = Variant_p(new Variant(inode->sector_count()));
  (*attr)["NFS generation number"] =
    Variant_p(new Variant(inode->generation_number_nfs()));
  (*attr)["Fragment block"] =
    Variant_p(new Variant(inode->fragment_addr()));
  (*attr)["Fragment index"] =
    Variant_p(new Variant(inode->fragment_index()));
  (*attr)["Fragment size"] =
    Variant_p(new Variant(inode->fragment_size()));
  if (inode->file_acl_ext_attr())
    {
      __add_xtd_attr(inode, attr);
      __add_acl(inode, attr);
    }
}

void	MfsoAttrib::__add_xtd_attr(Inode * inode, DFF::Attributes * attr)
{
  ExtendedAttr *	xtd_attr;

  (*attr)["Extended attribute header"] =
    Variant_p(new Variant(inode->file_acl_ext_attr()));

  xtd_attr = new ExtendedAttr(inode->file_acl_ext_attr(),
			      inode->SB()->block_size());
  xtd_attr->init(inode->extfs());
  std::map<xattr_name_entries *,
    std::pair<std::string, std::string> >::const_iterator user;

  std::string	xtd = "Inode extended attributes";
  std::map<std::string, class Variant_p >	m;

  user = xtd_attr->getUserXAttr().begin();
  for (; user != xtd_attr->getUserXAttr().end(); user++)
    m["user." + (*user).second.first] = Variant_p(new Variant((*user).second.second));
  (*attr)[xtd] = Variant_p(new Variant(m));
}

void	MfsoAttrib::__add_acl(Inode * inode, DFF::Attributes * attr)
{
  (void)inode; // to avoid a warning
  (*attr)[std::string("Posix ACL")] = Variant_p(new Variant(std::string("Not handled yet. \
			Please use the --istat option.")));
  // TODO
}


void	MfsoAttrib::__symlink_path(Inode * inode, DFF::Attributes * attr)
{
  std::string	path("");
  uint16_t	size;

 // max path length contained directly in the inode
  if ((size = inode->lower_size()) < 60)
    path.insert(0, (char *)&inode->block_pointers()[0], size);
  else
    {
      uint8_t *	tab;
      uint64_t	addr;

      tab = (uint8_t *)operator new(size * sizeof(uint8_t));
      addr = inode->block_pointers()[0] * inode->SB()->block_size();
      inode->extfs()->v_seek_read(addr, tab, size);
      path.insert(0, (char *)tab, size);
      (*attr)["Link block"] = Variant_p(new Variant(inode->block_pointers()[0]));
    }
  (*attr)["Link target"] = Variant_p(new Variant(path));
}


