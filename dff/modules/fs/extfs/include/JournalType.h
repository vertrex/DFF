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

#ifndef JOURNAL_TYPE_H
#define JOURNAL_TYPE_H
#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif


template <typename T> class JournalType
{
  /*! \class JournalType
    \brief Convert journal data to host endian.

    The journal is stored in big endian. This template class is used to
    convert the journal's values from big endian to the host endian.

    It is quiet simple to use. If you read an uint32_t from
    the journal the conversion will be done as in the following example :
    \code
    JournalType<uint32_t>     ex(val_to_convert);
    uint32_t whatever = ex.value();
    \endcode

    The conversion is done in the constructor.
  */
 public:

  /*!
    \brief Constructor.
    \param val the value we want to convert.
  */
  JournalType(T val = 0);

  /*!
    \brief Converted value.
    \return the value once it is converted to big endian.
  */
  T	value();

  /*!
    \brief set value needing to be converted.
    
    \param val the value we want to set.
  */
  void	setValue(T val);

 private:
  uint16_t      _convert_htob16();
  uint32_t      _convert_htob32();
  uint64_t	_convert_htob64();
  bool		_test();
  T		_convert();

  T		_value;
};

#include "../JournalType.tpp"
#endif // JOURNAL_TYPE_H
