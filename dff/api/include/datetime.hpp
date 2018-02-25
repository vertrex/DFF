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

#ifndef __DFF_DATETIME_HPP__
#define __DFF_DATETIME_HPP__

#ifndef WIN32   //XXX set in a header and import everywhere rather than copy/paste
#include <stdint.h>
#elif _MSC_VER >= 1600
#include <stdint.h>
#else
#include "wstdint.h"
#endif

#include <time.h>
#include <string>

#include "export.hpp"

namespace DFF
{

/**
 *  DateTime
 */
#ifdef WIN32
#define gmtimex(timet, structtm)\
   !_gmtime64_s(structtm, timet)
#else
#define gmtimex(timet, structtm)\
  gmtime_r(timet, structtm)
#endif

/**
 *  This class store time in UNIX epoch time GMT
 *  derivated class must pass epoch time as time GMT (converted from time zone)
 *  then user can specify a global time zone that will affect returned time informations.
 */
class DateTime
{
private:
  static const int     __daysByMonth[12];
  static int64_t       __globalTimeZoneOffset;
  int64_t              __epochTime;
protected:
  int64_t              __timegm(struct tm*); 
public:
  EXPORT explicit       DateTime(int64_t epochTime);
  EXPORT                DateTime(DateTime const&);
  EXPORT		DateTime(const std::string&);
  EXPORT 		DateTime(int32_t year, int32_t month, int32_t day, int32_t minute, int32_t hour, int32_t second);
  EXPORT virtual	~DateTime();

  EXPORT bool           operator==(const DateTime& other) const; //Take care to compare to None with is None in python not == None which can't convert None to DateTime
  EXPORT bool           operator!=(const DateTime& other) const;
  EXPORT bool		operator<(const DateTime& other) const;
  EXPORT bool           operator>(const DateTime& other) const;
  EXPORT bool		operator<=(const DateTime& other) const;
  EXPORT bool           operator>=(const DateTime& other) const;
/*
  need TimeDelta if we want to implement it
  EXPORT TimeDelta operator+(const DateTime& other) const;
  EXPORT TimeDelta operator-(const DateTime& other) const;
  const DateTime& operator+=(TimeDelta delta);
  const DateTime& operator-=(TimeDelta delta);
*/

  EXPORT int64_t                epochTime(void) const;
  EXPORT void                   epochTime(int64_t);

  EXPORT int32_t                globalTimeZone(void) const; //static use ICU lib to convert
  EXPORT void                   globalTimeZone(int32_t timeZone); //static use ICU lib to convert

  EXPORT const std::string      toString(void) const;
  EXPORT const std::string      toISOString(void) const;

  EXPORT int32_t                year(void) const;
  EXPORT int32_t                month(void) const;
  EXPORT int32_t                day(void) const;
  EXPORT int32_t                hour(void) const;
  EXPORT int32_t                minute(void) const;
  EXPORT int32_t                second(void) const;
  EXPORT int32_t                dayOfWeek(void) const;
  EXPORT int32_t                dayOfYear(void) const;
  //EXPORT uint8_t              dst(void) const;
};


/**
 *  DosDateTime
 */
class DosDateTime : public DateTime 
{
#define SECONDS_PER_MIN	  60
#define SECONDS_PER_HOUR  (60 * 60)
#define SECONDS_PER_DAY	  (SECONDS_PER_HOUR * 24)
#define DAYS_DELTA	  (365 * 10 + 2)
#define YEAR_2100	  120
#define IS_LEAP_YEAR(y)	(!((y) & 3) && (y) != YEAR_2100)
public:
  EXPORT DosDateTime(uint16_t time, uint16_t date);
  EXPORT ~DosDateTime();
private:
  static const time_t daysInYear[];
};

/**
 *  MS64DateTime
 */
class MS64DateTime : public DateTime
{
#if __WORDSIZE == 64
  #define SECONDS_FROM_1601_TO_1970  (uint64_t)(116444736000000000UL)
#else
  #define SECONDS_FROM_1601_TO_1970  (uint64_t)(116444736000000000ULL)
#endif
public:
  EXPORT MS64DateTime(uint64_t);
  EXPORT ~MS64DateTime();
};

/**
 *  MS128DateTime
 */
class MS128DateTime : public DateTime
{
public:
  EXPORT  MS128DateTime(char *);
  EXPORT  ~MS128DateTime();
}; 

/**
 *  HFSDateTime
 */
class HFSDateTime : public DateTime
{
#define SECONDS_FROM_1904_TO_1970  (uint64_t)(2082844800ULL)
public:
  EXPORT HFSDateTime(uint32_t);
  EXPORT ~HFSDateTime();
};

}

#endif
