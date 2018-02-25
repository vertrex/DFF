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

#include <iostream>
#include <typeinfo>

template <typename T>
JournalType<T>::JournalType(T val)
{
    _value = val;
    if (val)
      _value = _convert();
}

template <typename T>
T   JournalType<T>::value()
{
    return this->_value;
}

template <typename T>
bool   JournalType<T>::_test()
{
    uint32_t Value32;
    uint8_t *VPtr = (uint8_t *)&Value32;

    VPtr[0] = VPtr[1] = VPtr[2] = 0;
    VPtr[3] = 1;

    return Value32;
}

template <typename T>
T   JournalType<T>::_convert()
{
    if (typeid(T) == typeid(uint32_t))
        _value = _convert_htob32();
    else if (typeid(T) == typeid(uint16_t))
        _value = _convert_htob16();
    else if (typeid(T) == typeid(uint64_t))
        _value = _convert_htob64();
    return _value;
}

template <typename T>
uint16_t  JournalType<T>::_convert_htob16()
{
    if (_test())
         return ((((_value) >> 8) & 0xffu) | (((_value) & 0xffu) << 8));
    return _value;
}

template <typename T>
uint32_t  JournalType<T>::_convert_htob32()
{
    if (_test())
        return ((((_value) & 0xff000000u) >> 24)
                | (((_value) & 0x00ff0000u) >>  8)
                | (((_value) & 0x0000ff00u) <<  8)
                | (((_value) & 0x000000ffu) << 24));
    return _value;
}

template <typename T>
uint64_t  JournalType<T>::_convert_htob64()
{
    if (_test())
        return ((((_value) & 0xff00000000000000ull) >> 56)
        | (((_value) & 0x00ff000000000000ull) >> 40)
        | (((_value) & 0x0000ff0000000000ull) >> 24)
        | (((_value) & 0x000000ff00000000ull) >> 8)
        | (((_value) & 0x00000000ff000000ull) << 8)
        | (((_value) & 0x0000000000ff0000ull) << 24)
        | (((_value) & 0x000000000000ff00ull) << 40)
        | (((_value) & 0x00000000000000ffull) << 56));
    return _value;
}

template <typename T>
void	JournalType<T>::setValue(T val)
{
  _value = val;
  _convert();
}
