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

#ifndef CUSTOMRESULTS_H
#define CUSTOMRESULTS_H

#include "../data_structure/includes/SuperBlock.h"
#include "../data_structure/includes/Inode.h"

class CustomResults
{
public:
  CustomResults();

  //! Destructor. Do nothing.
  ~CustomResults();

  /*! \brief Set extfs results.

    This method fill in the extfs results with the superblock fields value
    so the dff user can easilly access them.

    \param SB a pointer to the \c \b SuperBlock instance.
  */
  void            set(DFF::Attributes * attr, Inode * inode);

  /*! \brief File system flags.

    Build a human-readable string of the file system flags (field
    \c \b fs_state).

    \return a string containing the state.
  */
  std::string   getFlags(uint16_t flags);
  Variant *	getFlags(const SuperBlock * SB);

  /*! \brief Error handling.

    Build a human-readable string of the file system error handling
    method (field error_handling_method).

    \param error_handling the error handling method

    \return the error handling method.
  */
  std::string     getErrorHandling(uint16_t error_handling);

  /*! \brief Creator OS.

    \param os the os who created the file system.

    \return the name of the OS who created the file sytem.
  */
  std::string     getOs(uint32_t os);

  /*! \brief Compatible features.

    \param c_f_flags the compatible fearures flag.

    \return the list of the compatible features.
  */
  static std::string  getCompatibleFeatures(uint32_t c_f_flags);
  Variant *		getCompatibleFeatures(const SuperBlock * SB);

  /*! \brief incompatible features.

    \param i_f_flags the incompatible features flag.

    \return the list of the incompatible features.
  */
  static std::string  getIncompatibleFeatures(uint32_t i_f_flags);
  Variant *		getIncompatibleFeatures(const SuperBlock * SB);

  /*! \brief Read-only features.

    \param r_o_flag the read only features flag.

    \return the list of the read-only features.
  */
  static std::string  getReadOnlyFeatures(uint32_t r_o_flag);
  Variant *		getReadOnlyFeatures(const SuperBlock * SB);

  /*! \brief File sytem ID.

    \param fs_id the file system ID.

    \return the file system ID.
  */
  std::string     getFSID(const uint8_t * fs_id);

  /*! \brief Add time to results.

    Add a human readable date in the result's map.

    \param text the text assiociated with the date.
    \param t the timestamp we need to insert in the date.
  */
  Variant *      add_time(time_t t);
};

#endif // CUSTOMRESULTS_H
