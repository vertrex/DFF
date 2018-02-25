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

#ifndef __DIRECTORY_ENTRY_H__
#define __DIRECTORY_ENTRY_H__

#ifndef WIN32
	#include <stdint.h>
#elif _MSC_VER >= 1600
	#include <stdint.h>
#else
	#include "wstdint.h"
#endif


typedef	struct	__directory_entry_original_s
{
    /*! \struct __directory_entry_original_s
        \brief The first version of a dirent structure.

        The file type is not present.
    */

    //! Inode value.
    uint32_t	inode_value;

    //! Lenght of the entry.
    uint16_t	entry_length;

    //! Lenght of the name.
    uint16_t	name_length;
}		dir_entry_v1;

/*! \struct	__directory_entry_2nd_version_s
    \brief The second version of a dirent structure.

    The file type is present. The uint16_t \c \b name_length is splitted in
    two 8 bits fields which respectively are :
        \li The name lenght.
        \li The file type.

    The file type can take the following values :
        \li 0 : Unknown type.
        \li 1 : Regular file.
        \li 2 : Directory.
        \li 3 : Character device.
        \li 4 : Block device.
        \li 5 : FIFO
        \li 6 : Unix socket.
        \li 7 : Symbolic link.

    \sa DirEntry
*/
typedef	struct	__directory_entry_2nd_version_s
{
    //! Inode value.
    uint32_t	inode_value;

    //! Lenght of the entry.
    uint16_t	entry_length;

    //! Lenght of the name.
    uint8_t	name_length;

    //! Type of the file.
    uint8_t	file_type;
}		dir_entry_v2;

#endif
