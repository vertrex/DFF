/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2014 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: *www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Solal Jacob <sja@digital-forensic.org>
 */

#ifndef __QCOW_HPP__
#define __QCOW_HPP__

#include "vfs.hpp"
#include "mfso.hpp"
#include "node.hpp"
#include "variant.hpp"
#include "typesconv.hpp"

#include "libbfio_wrapper.hpp"
#include <libqcow.h>

using namespace DFF;

typedef struct s_mount_handle
{
}	mount_handle_t;


class QCowNode : public Node
{
public:
  QCowNode(std::string name, uint64_t size, Node* parent, fso* fsobj);
  ~QCowNode();
  Attributes	_attributes();
};


class QCow : public mfso
{
public:
                        QCow();
                        ~QCow();
  int32_t	        vread(int fd, void *buff, unsigned int size);
  uint64_t	        vseek(int fd, uint64_t offset, int whence);
  void	                start(std::map<std::string, Variant_p >);
private:
  void			__createNode(void);

  Node*			__parent;
  Node*			__root;
  uint64_t		__size;
  libqcow_file_t*	__qcowFile;
  libbfio_handle_t*	__bfio_handle;
  mutex_def(__mutex);
};

#endif
