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

#ifndef __CUSTOM_ATTRIB_H__
#define __CUSTOM_ATTRIB_H__

#include "../data_structure/includes/Inode.h"

class CustomAttrib
{
    /*! \class CustomAttrib
        \brief Vfs node's attributes.

        This class inheritates attrib. Attributes are used to set some
        properties to nodes, as the modification time or the size. In case
        of extfs som other attributes can be set as access rights, file's
        owner, etc.

        \sa attrib
    */
    public:
                CustomAttrib();
        virtual ~CustomAttrib();

        void    setTime(Inode *);
        void    setTime(time_t);

        void    setMode(Inode *);
        bool    setMode(uint16_t, Inode * _inode);

        void    setSetUidGid(Inode *);
        void    setUidGid(Inode *);

        void    setAttr(Inode * inode);
	std::map<std::string, int>	imap;
	std::map<std::string, std::string> smap;

 private:

};

#endif // __CUSTOM_ATTRIB_H__
