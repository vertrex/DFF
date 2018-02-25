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

#include "include/utils/SuperBlockUtils.h"

SuperBlockUtils::SuperBlockUtils()
{
}

SuperBlockUtils::~SuperBlockUtils()
{
}

bool    SuperBlockUtils::useCompatibleFeatures(uint32_t feature, uint32_t SB_flag) const
{
    return SB_flag & feature;
}

bool    SuperBlockUtils::useRoFeatures(uint32_t feature,  uint32_t SB_flag) const
{
    return SB_flag & feature;
}

bool    SuperBlockUtils::useIncompatibleFeatures(uint32_t feature,
						 uint32_t SB_flag) const
{
    return SB_flag & feature;
}

