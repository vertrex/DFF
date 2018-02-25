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

#include <memory>

#include "include/Option.h"
#include "include/FsStat.h"
#include "include/InodeStat.h"
#include "include/InodesList.h"
#include "include/JournalStat.h"
#include "include/BlkList.h"

Option::Option(std::map<std::string, Variant_p > arg, SuperBlock * SB, VFile * vfile,
	       GroupDescriptor * GD)
{
  this->arg = arg;
  __SB = SB;
  __vfile = vfile;
  __GD = GD;
}
Option::~Option()
{
}

void	Option::parse(Extfs * extfs)
{
  std::map<std::string, Variant_p >::iterator	it;
  std::string	blk(""), dir_path(""), istat_opt("");
  std::string	ils(""), jstat("");
  bool		fs_stat = false;

  if ((it = arg.find("jstat")) != arg.end())
    jstat = it->second->value<std::string>();

  if ((it = arg.find("fsstat")) != arg.end())
    fs_stat = it->second->value<bool>();

  if ((it = arg.find("blk")) != arg.end())
    blk = it->second->value<std::string>();

  if ((it = arg.find("ils")) != arg.end())
    ils = it->second->value<std::string>();
      
  if ((it = arg.find("istat")) != arg.end())
    istat_opt = it->second->value<std::string>();

  // stat on file system
  if (fs_stat)
    {
      std::auto_ptr<FsStat>   stat(new FsStat);
      stat->disp(__SB, __vfile);
    }

  // inodes list
  if (!ils.empty())
    {
      std::auto_ptr<InodesList>   i_list(new InodesList(__SB, __vfile));
      i_list->list(ils, __SB->inodesNumber());
      i_list->display(extfs);
    }

  // stat on an inode
  if (!istat_opt.empty())
    {
      std::auto_ptr<InodeStat>   i_stat(new InodeStat(__SB, extfs));
      i_stat->stat(istat_opt);
    }

  // stat on the journal (if there is any)
  if (!jstat.empty())
    {
      std::auto_ptr<JournalStat> j_stat(new JournalStat(extfs, __SB, __GD));
      j_stat->stat();
    }

  // block list
  if (!blk.empty())
    {
      std::auto_ptr<BlkList>	blk_list(new BlkList(__GD, __SB, __vfile));
      blk_list->stat(blk);
    } 
}
