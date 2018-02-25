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

#ifndef SUPERBLOCKUTILS_H
#define SUPERBLOCKUTILS_H

#include "node.hpp"
#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif


class SuperBlockUtils
{
 public:
  
  //! Constructor. Do nothing.
  SuperBlockUtils();

  //! Destructor. Do nothing.
  ~SuperBlockUtils();

  /*! \brief Compatible features.

    \param feature the feature.
    \param SB_flag a flag

    \return true if the file system uses the feature \b \e feature, false
    otherwise.
  */
  bool            useCompatibleFeatures(uint32_t feature, uint32_t SB_flag) const;

  /*! \brief Incompatible features.

    \param feature the feature.
    \param SB_flag a flag

    \return true if the file system uses the feature \b \e feature, false
    otherwise.
  */
  bool            useRoFeatures(uint32_t feature, uint32_t SB_flag) const;

  /*! \brief RO features.

    \param feature the feature.
    \param SB_flag a flag

    \return true if the file system uses the feature \b \e feature, false
    otherwise.
  */
  bool            useIncompatibleFeatures(uint32_t feature, uint32_t SB_flag) const;


 private:
};

#endif // SUPERBLOCKUTILS_H
