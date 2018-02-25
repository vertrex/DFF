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

#include "datetime.hpp"

#if _MSC_VER >= 1800
#include <algorithm>
#endif

#include <stdio.h>
#include <string.h>

/**
  *  DateTime
  */
namespace DFF
{

int64_t  DateTime::__globalTimeZoneOffset = 0;

DateTime::DateTime(int64_t epochTime) : __epochTime(epochTime)
{
}

DateTime::DateTime(DateTime const& copy) : __epochTime(copy.__epochTime)
{
}

DateTime::DateTime(const std::string& dateTime) : __epochTime(0)
{
  struct tm    date;

  memset(&date, 0, sizeof(struct tm));
  if (sscanf(dateTime.c_str(), "%4d-%2d-%2d%*1c%2d:%2d:%2d", &date.tm_year, &date.tm_mon, &date.tm_mday, &date.tm_hour, &date.tm_min, &date.tm_sec) != 6)
    throw std::string("Can't convert invalid date : " + dateTime + " to DateTime");
  date.tm_year -= 1900;
  date.tm_mon -= 1;

  this->epochTime(this->__timegm(&date));
}

DateTime::DateTime(int32_t year, int32_t month, int32_t day, int32_t hour, int32_t minute, int32_t second) : __epochTime(0)
{
  struct tm     dateTime;

  dateTime.tm_year = year - 1900; 
  dateTime.tm_mon = month - 1;
  dateTime.tm_mday = day;
  dateTime.tm_hour = hour;
  dateTime.tm_min = minute;
  dateTime.tm_sec = second;
  dateTime.tm_wday = 0;
  dateTime.tm_yday = 0;
  dateTime.tm_isdst = 0;

  this->epochTime(this->__timegm(&dateTime));
}

DateTime::~DateTime()
{
}

bool    DateTime::operator==(const DateTime& other) const
{
  return (this->__epochTime == other.__epochTime);
}

bool    DateTime::operator!=(const DateTime& other) const
{
  return (this->__epochTime != other.__epochTime);
}

bool    DateTime::operator<(const DateTime& other) const
{
  return (this->__epochTime < other.__epochTime);
}

bool    DateTime::operator>(const DateTime& other) const
{
  return (this->__epochTime > other.__epochTime);
}

bool    DateTime::operator<=(const DateTime& other) const
{
  return (this->__epochTime <= other.__epochTime);
}

bool    DateTime::operator>=(const DateTime& other) const
{
  return (this->__epochTime >= other.__epochTime);
}

const int DateTime::__daysByMonth[12] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

int64_t DateTime::__timegm(struct tm* t)
{
   register int64_t year = 1900 + t->tm_year + t->tm_mon / 12;
   register int64_t result = (year - 1970) * 365 + this->__daysByMonth[t->tm_mon % 12];

   result += (year - 1968) / 4;
   result -= (year - 1900) / 100;
   result += (year - 1600) / 400;
   if ((year % 4) == 0 && ((year % 100) != 0 || (year % 400) == 0) && (t->tm_mon % 12) < 2)
     result--;
   result += t->tm_mday - 1;
   result *= 24;
   result += t->tm_hour;
   result *= 60;
   result += t->tm_min;
   result *= 60;
   result += t->tm_sec;
   if (t->tm_isdst == 1)
      result -= 3600;

   return (result);
}

int64_t DateTime::epochTime(void) const
{
  return (this->__epochTime + this->__globalTimeZoneOffset);
}

void    DateTime::epochTime(int64_t epochTime)
{
  this->__epochTime = epochTime;
}

int32_t DateTime::globalTimeZone(void) const
{
  return (this->__globalTimeZoneOffset);
}

void    DateTime::globalTimeZone(int32_t timeZoneMinutesOffset)
{
  this->__globalTimeZoneOffset = timeZoneMinutesOffset;
}

int32_t DateTime::year(void) const
{
  struct tm     date;
  time_t time = this->epochTime();

  if (gmtimex(&time, &date) != 0)
    return date.tm_year + 1900;
  return (1970);
}

int32_t  DateTime::month(void) const
{
  struct tm     date;
  time_t time = this->epochTime();

  if (gmtimex(&time, &date) != 0)
    return date.tm_mon + 1;
  return (1);	
}

int32_t DateTime::day(void) const
{
  struct tm     date;
  time_t time = this->epochTime();

  if (gmtimex(&time, &date) != 0)
    return date.tm_mday; 
  return (0);
}

int32_t DateTime::hour(void) const
{
  struct tm     date;
  time_t time = this->epochTime();

  if (gmtimex(&time, &date) != 0)
    return date.tm_hour;
  return (0);
}

	
int32_t DateTime::minute(void) const
{
  struct tm     date;
  time_t time = this->epochTime();

  if (gmtimex(&time, &date) != 0)
    return date.tm_min;
  return (0);
}

int32_t DateTime::second(void) const
{
  struct tm     date;
  time_t time = this->epochTime();

  if (gmtimex(&time, &date) != 0)
    return date.tm_sec;
  return (0);
}

int32_t DateTime::dayOfWeek(void) const
{
  struct tm     date;
  time_t time = this->epochTime();

  if (gmtimex(&time, &date) != 0)
    return date.tm_wday;
  return (0);
}

int32_t DateTime::dayOfYear(void) const
{
  struct tm     date;
  time_t time = this->epochTime();

  if (gmtimex(&time, &date) != 0)
    return date.tm_yday;
  return (0);
}

const std::string       DateTime::toISOString(void) const
{
  struct tm     date;
  char	        timeBuff[20];
  time_t        time = this->epochTime();

  memset(&date, 0, sizeof(struct tm));
  if (gmtimex(&time, &date) != 0)
    if (strftime(timeBuff, 20, "%Y-%m-%dT%H:%M:%S", &date) == 19) //use TZ !!
      return std::string(timeBuff);

  throw std::string("DateTime::toISOString() invalid time value");
}

const std::string       DateTime::toString(void) const
{
  struct tm     date;
  char	        timeBuff[20];
  time_t        time = this->epochTime();

  memset(&date, 0, sizeof(struct tm));
  if (gmtimex(&time, &date) != 0)
    if (strftime(timeBuff, 20, "%Y-%m-%d %H:%M:%S", &date) == 19) //use TZ !!
      return std::string(timeBuff);

  throw std::string("DateTime::toString() invalid time value");
}

/**
 *  DosDateTime
 */
time_t const  DosDateTime::daysInYear[] = { 0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 0, 0, 0, };
 
DosDateTime::DosDateTime(uint16_t time, uint16_t date) : DateTime((int64_t)0) //, timeZoneset timezone conversion to convert to GMT
{
  int64_t day = (std::max)(1, date & 0x1f) - 1;
  int64_t year  = date >> 9;
  int64_t month = (std::max)(1, (date >> 5) & 0xf);
  int64_t leap_day = (year + 3) / 4;

  if (year > YEAR_2100)
    leap_day--;
  if (IS_LEAP_YEAR(year) && month > 2)
    leap_day++;

  register int second =  (time & 0x1f) << 1;
  second += ((time >> 5) & 0x3f) * SECONDS_PER_MIN;
  second += (time >> 11) * SECONDS_PER_HOUR;
  second += (year * 365 + leap_day + daysInYear[month] + day + DAYS_DELTA) * SECONDS_PER_DAY;

  this->epochTime(second);
}

DosDateTime::~DosDateTime()
{
}

/**
 *  MS64DateTime
 */
MS64DateTime::MS64DateTime(uint64_t time) : DateTime((int64_t)0) 
{
  if (time == 0)
    return;
  
  time -= SECONDS_FROM_1601_TO_1970;
  time /= 10000000;

  this->epochTime(time);
}

MS64DateTime::~MS64DateTime()
{
}

/**
 *  MS128DateTime
 */
MS128DateTime::MS128DateTime(char *_time) : DateTime((int64_t)0) 
{
  if (_time == NULL)
    throw std::string("DateTimeMS128, time is NULL");

  struct tm     dateTime;
  uint16_t* t = (uint16_t*)_time;

  dateTime.tm_year = *t++; 
  dateTime.tm_year -= 1900;
  dateTime.tm_mon = *t++; 
  dateTime.tm_mon -= 1;
  dateTime.tm_wday = *t++;
  dateTime.tm_mday = *t++;
  dateTime.tm_hour = *t++;
  dateTime.tm_min = *t++;
  dateTime.tm_sec = *t++;
  //dateTime->usecond = *t++;
  dateTime.tm_yday = 0;
  dateTime.tm_isdst = 0;

  this->epochTime(this->__timegm(&dateTime));
}

MS128DateTime::~MS128DateTime()
{
}

/**
 *  HFSDateTime
 */
HFSDateTime::HFSDateTime(uint32_t hfsTime) : DateTime((int64_t)0)
{
  if (hfsTime <= SECONDS_FROM_1904_TO_1970)
    return;

  register uint64_t     time;

  time = (uint64_t)hfsTime;
  time -= SECONDS_FROM_1904_TO_1970;

  this->epochTime(time);
}

HFSDateTime::~HFSDateTime()
{
}

}
