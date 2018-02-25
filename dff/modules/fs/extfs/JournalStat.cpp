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

#include "include/JournalStat.h"
#include "include/JournalType.h"

JournalStat::JournalStat(Extfs * extfs, const SuperBlock * SB,
			 GroupDescriptor * GD)
{
  _journal = std::auto_ptr<Journal> (new Journal(extfs, SB, GD));
  _extfs = extfs;
  _SB = SB;
}

JournalStat::~JournalStat()
{
}

void	JournalStat::stat()
{
    if (!_journal->init())
    {
      std::cerr << "An error occured while initializing the journal. "
	"Cannot stat." << std::endl;
      return ;
    }

  JournalType<uint32_t>
    j_type(_journal->j_super_block()->header.signature),
    b_type(_journal->j_super_block()->header.block_type);
  
  if (j_type.value() != __J_SIGNATURE)
    {
      std::cerr << "JournalStat error : signature is different from 0x"
		<< std::hex << __J_SIGNATURE << std::endl;
      std::cerr << "sig : " << std::hex << j_type.value() << std::endl;
      return ;
    }

  std::cout << "Journal stat :" << std::endl;
  std::cout << "\tJournal inode : " << _journal->SB()->journal_inode()
	    << std::endl;
  std::cout << "\tSuper block version : " 
	    << (( b_type.value() == Journal::__SB_V2) ? 2 : 1) << std::endl;
  b_type.setValue(_journal->j_super_block()->block_size);
  std::cout << "\tBlock size : " << b_type.value() << std::endl;

  b_type.setValue(_journal->j_super_block()->blocks_number);
  std::cout << "\tNumber of blocks : " << b_type.value() << std::endl;
  
  b_type.setValue(_journal->j_super_block()->block_first_transaction);
  std::cout << "\tBlock first transaction : " << b_type.value() << std::endl;
  jlist();
}

void			JournalStat::jlist()
{
  uint64_t		addr;
  uint8_t *		j_block;
  journal_header *	j_header;

  JournalType<uint32_t>	nb_blocks(_journal->j_super_block()->blocks_number),
    begin(_journal->j_super_block()->block_first_transaction),
    j_block_size(_journal->j_super_block()->block_size);

  j_block = (uint8_t *)operator new (j_block_size.value() * sizeof(uint8_t));
  while ((addr = _journal->browseBlock(begin.value(), nb_blocks.value())))
    {
      _extfs->v_seek_read(addr * _SB->block_size(), (void *)j_block,
			  j_block_size.value());
      j_header = ((journal_header *)j_block);
      JournalType<uint32_t> sig(j_header->signature),
	b_type(j_header->block_type);

      if ((sig.value() == __J_SIGNATURE)
	  && (b_type.value() == Journal::__DESCR_BLOCK))
	{
	  JournalType<uint32_t>	trans(j_header->sequence_number);
	  std::cout <<  _journal->currentBlock() - 1
		    << " : Descriptor block (Seq " << trans.value() 
		    << ")" << std::endl;
	    uint32_t  mini_pouce = commitBlock(j_block + sizeof(journal_header),
					     j_block_size.value());
	    _journal->goToBlock(_journal->currentBlock() + mini_pouce);
	}
      else if ((sig.value() == __J_SIGNATURE)
	  && (b_type.value() == Journal::__COMMIT_BLOCK))
	{
	  JournalType<uint32_t>	trans(j_header->sequence_number);
	  std::cout <<  _journal->currentBlock() - 1
		    << " : Commit block (Seq " << trans.value() 
		    << ")" << std::endl << std::endl;
	}
      else if ((sig.value() == __J_SIGNATURE)
	  && (b_type.value() == Journal::__REVOKE_BLOCK))
	{
	  JournalType<uint32_t>	trans(j_header->sequence_number);
	  std::cout <<  _journal->currentBlock() - 1
		    << " : Revoke block (Seq " << trans.value() 
		    << ")" << std::endl;
	}
      else
	std::cout <<  _journal->currentBlock() - 1
		  << " : Unknown block. " << std::endl;
    }
}

unsigned int
JournalStat::commitBlock(uint8_t * j_block, uint32_t j_block_size)
{
  journal_block_entries * j_block_descr;
  JournalType<uint32_t>	fs_block, flags;
  unsigned int		count = 0;
  unsigned int		nb = 0;
  

  for (uint32_t offset = 0; offset < (j_block_size - sizeof(journal_header));
       ++count)
    {
      j_block_descr = ((journal_block_entries *)(j_block + offset));
      fs_block.setValue(j_block_descr->file_system_block);
      flags.setValue(j_block_descr->entry_flags);
      if (fs_block.value())
	{
	  std::cout << _journal->currentBlock() + count
		    << ": " << "Fs block\t" << fs_block.value() << std::endl;
	  nb++;
	}
      offset += sizeof(journal_block_entries);
      if (!(flags.value() & 0x02))
	  offset += (4 * sizeof(uint32_t));      
    }
  return nb;
}
