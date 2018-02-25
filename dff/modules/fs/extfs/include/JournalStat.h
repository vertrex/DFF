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

#ifndef JOURNAL_STAT_
#define JOURNAL_STAT_

#include <memory> // auto_ptr<>

#include "Journal.h"

class	JournalStat
{
  /*! \class JournalStat
    \brief Stat on the ext journal

    Only available on ext3 and ext4.
  */

 public:
  //! Constructor. Instanciate a Journal.
  JournalStat(Extfs * extfs, const SuperBlock * SB, GroupDescriptor * GD);

  //! Destructor. Do nothing.
  ~JournalStat();

  /*! \brief Journal informations.
    
    Display informations about the journal.
   */
  void	stat();
  
  /*! \brief Journal list.

    List journal blocks.
   */
  void	jlist();

  /*! \brief Commit blocks.

    Search for commit block in the journal.
    \param j_block a journal block.
    \param j_block_size the size in byte of a journal block.
    \return the number of fs block in the transaction.
   */
  unsigned int	commitBlock(uint8_t * j_block, uint32_t j_block_size);

 private:
  std::auto_ptr<Journal> _journal;
  Extfs *	         _extfs;
  const SuperBlock *	 _SB;
};

#endif /* JOURNAL_STAT_ */
