/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
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
 *  Solal J. <sja@digital-forensic.org>
 */

#ifndef __IOSTAT_HPP__
#define __IOSTAT_HPP__

#include "datatype.hpp"

namespace DFF
{

class IOStat
{
public:
  EXPORT static IOStat&		getInstance();
  EXPORT void			pushReadStats(uint16_t fsoid, uint64_t read);
  EXPORT void			pushInstanceStats(uint16_t fsoid);
  EXPORT uint64_t		totalReadById(uint16_t fsoid);
  EXPORT uint64_t		totalInstanceById(uint16_t fsoid);
private:
  EXPORT	IOStat() {}
  EXPORT	~IOStat() {}
  EXPORT IOStat(const IOStat&) {}
  EXPORT const IOStat&	operator=(const IOStat&);
  DFF::map<uint16_t, uint64_t >	__io;
  DFF::map<uint16_t, uint64_t >	__instances;
};

}
#endif
