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

#include "iostat.hpp"

namespace DFF
{

IOStat&	IOStat::getInstance()
{
  static IOStat	instance;
  return instance;
}

void	IOStat::pushReadStats(uint16_t fsoid, uint64_t read)
{
  if (this->__io.exist(fsoid))
    this->__io[fsoid] += read;
  else
    this->__io[fsoid] = read;
}

void	IOStat::pushInstanceStats(uint16_t fsoid)
{
  if (this->__instances.exist(fsoid))
    this->__instances[fsoid] += 1;
  else
    this->__instances[fsoid] = 1;
}

uint64_t	IOStat::totalReadById(uint16_t fsoid)
{
  uint64_t	total;

  total = 0;
  if (this->__io.exist(fsoid))
    total = this->__io[fsoid];
  return total;
}

uint64_t	IOStat::totalInstanceById(uint16_t fsoid)
{
  uint64_t	total;

  total = 0;
  if (this->__instances.exist(fsoid))
    total = this->__instances[fsoid];
  return total;
}

}
