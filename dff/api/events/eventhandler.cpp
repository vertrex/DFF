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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#include "eventhandler.hpp"

namespace DFF
{

EventHandler::EventHandler()
{
}

bool    EventHandler::connection(class EventHandler *obs)
{
  std::vector<class EventHandler *>::iterator        it;

  for (it = this->watchers.begin(); it != this->watchers.end(); it++)
    if (*it == obs)
      {
        return false;
      }
  this->watchers.push_back(obs);
  return true;
}

bool    EventHandler::deconnection(class EventHandler *obs)
{
  std::vector<class EventHandler *>::iterator        it;

  for (it = this->watchers.begin(); it != this->watchers.end(), *it != obs; it++)
    ;
  if (it != this->watchers.end())
    {
      this->watchers.erase(it);
      return true;
    }
  else
    return false;
}

bool    EventHandler::notify(event *e)
{
  std::vector<class EventHandler *>::iterator        it;

  for (it = this->watchers.begin(); it != this->watchers.end(); it++)
    (*it)->Event(e);
  return true;
}

}
