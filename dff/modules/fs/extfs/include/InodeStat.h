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

#ifndef INODESTAT_H
#define INODESTAT_H

#include <string>

#include "../data_structure/includes/Inode.h"
#include "../data_structure/includes/ExtendedAttr.h"

//#include "../data_structure/includes/SuperBlock.h"
#include "../extfs.hpp"

class InodeStat
{
    /*! \class InodeStat
        \brief Stat about an inode.

        Display an inode status under the following format:
        \verbatim
	dff / > extfs --parent /ext3.test.dd --run no --istat 42
	Inode : 42
		Group : 0
		Allocated
		Permissions : rw-r--r--
		Set UID / GID ? :  No / No
		UID / GID : 1000 / 1000
		Extended attribute header : 0
		Fragment block : 0
		Fragment index : 0
		Fragment size : 0
		Link number : 8
		NFS generation number : 277478324
		Accessed : Mon Mar  8 18:06:17 2010

		Changed : Mon Mar  8 18:06:17 2010
		
		Modification : Mon Mar  8 18:06:17 2010
	Direct blocks :
        166     167     168     169     170     171     172     173
        174     175     176     177
	Single indirect blocks :

	Double indirect blocks :
        \endverbatim
    */

    public:
        //! Constructor.
        InodeStat(SuperBlock * SB, Extfs * extfs);

        //! Destructor.
        ~InodeStat();

        /*! \brief Inode stat.
            Display the stat.
            \param opt the option passed to the istat command. Must be
            a list of inode number separated by ,.
        */
        void            stat(std::string opt);

        /*! \brief Inode stat.
            Display the stat of the inode \b \e inode_nb.
            \param inode_nb the inode number.
        */
        void            stat(uint32_t inode_nb);

        /*! \brief Display.
            Display the content (key + value) of the map \b \e attr.
            \param attr a map containing informations that must be displayed.
        */
        template <typename T>
        void		display(const std::map<std::string, T> & attr);

	/*! \brief Content block list.
	    Display the content block number of inode \e \b inode.
	    \param inode the inode we want to display content blocks.
	*/
	void		block_list(Inode * inode);

	/* \brief Xattr
	   Display extended attr (if any).
	   \param xattr the extended attributes.
	 */
	void		disp_xattr(ExtendedAttr * xattr);
	void		disp_acl(ExtendedAttr * xattr);

    private:
        SuperBlock *    _SB;
        Extfs *         _extfs;
};

#endif // INODESTAT_H
