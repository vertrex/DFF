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

#ifndef INODESLIST_H
#define INODESLIST_H

#include <string>

#include "../data_structure/includes/SuperBlock.h"
#include "../extfs.hpp"

class InodesList
{
  /*! \class InodesList
      \brief Detailed inodes list.
      
      This class purpose is to find and display informations about a list of inodes.
      The option \b \e --ils must be used follow by a range of inode.
      
      Examples:
      \verbatim
      --ils 1-10
      --ils 42
      \endverbatim
      
      An example of result:
      \verbatim
      42 | Allocated | ?--------- | A : Thu Jan 22 16:05:27 2009 | UID / GID : 0/0
      \endverbatim
   */

 public:
  //!Constructor.
  InodesList(SuperBlock * SB, VFile * vfile);

  //! Destructor. Do nothing.
  ~InodesList();

  /*! \brief Parse the option.
    
      This method determine the first and last inode number passed to the command
      \b \e ils and initialize _begin and _end.

      \param opt the option passed to the command --ils
      \param nb_inodes the total nimber of inodes on the file system.

      \throw vfsError if one of the inode number specified on the command line is
      out of range.
   */
  void	list(const std::string & opt, uint32_t nb_inodes) throw (vfsError);

  /*! \brief Inodes range.
    
      \param nb_inodes the total number of inodes on the file system.
      
      \return false when the inodes number are out of range, true otherwise.
   */
  bool	check_inode_range(uint32_t nb_inodes);

  /*! \brief Inodes informations.
    
      This method call infos() which display the informations for each inodes
      number between _begin and _end. _begin and _end are included in the range.
      
      \param extfs a pointer to the Extfs instance.
   */
  void	display(Extfs * extfs);

  /*! \brief Display informations.
    
      Display a line of informations about inode \c \e inode_nb.
      
      \param extfs a pointer to the Extfs instance.
      \param inode_nb the number of the inode we want to analize.
   */
  void	infos(Extfs * extfs, uint32_t inode_nb);

  /*! \brief Display a date.
    
      Display a human readable date according to a UNIX time stamp.
      
      \param name
      \param t the timestamp.
   */
  void	disp_time(const std::string & name, const uint32_t t);  

 private:
  uint32_t          _begin;
  uint32_t          _end;
  SuperBlock *    _SB;
  VFile *         _vfile;
};

#endif // INODESLIST_H
