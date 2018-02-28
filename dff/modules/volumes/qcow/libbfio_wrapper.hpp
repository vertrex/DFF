/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
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

#ifndef __LIBBFIO_WRAPPER_HPP__
#define __LIBBFIO_WRAPPER_HPP__

#include <libbfio.h>
#include "node.hpp"
#include "vfile.hpp"

struct dff_libbfio_file_io_handle
{
   int		access_flags;
   Node*  	parent;
   VFile*	file;
} typedef dff_libbfio_file_io_handle_t;

int 	dff_libbfio_file_initialize(libbfio_handle_t **handle, libbfio_error_t **error, Node* parent);
int 	dff_libbfio_file_io_handle_initialize(dff_libbfio_file_io_handle_t** io_handle, libbfio_error_t **error);

int	dff_libbfio_file_io_handle_free(intptr_t **io_handle, libbfio_error_t **error);
int 	dff_libbfio_file_io_handle_clone(intptr_t **destination_io_handle, intptr_t *source_io_handle, libbfio_error_t **error);
int 	dff_libbfio_file_open(intptr_t *io_handle, int access_flags, libbfio_error_t **error);
int 	dff_libbfio_file_close(intptr_t *io_handle, libbfio_error_t **error);
ssize_t dff_libbfio_file_read(intptr_t *io_handle, uint8_t *buffer, size_t size, libbfio_error_t **error);
ssize_t dff_libbfio_file_write(intptr_t *io_handle, const uint8_t *buffer, size_t size, libbfio_error_t **error);
off64_t dff_libbfio_file_seek_offset(intptr_t *io_handle, off64_t offset, int whence, libbfio_error_t **error);
int 	dff_libbfio_file_exists(intptr_t *io_handle, libbfio_error_t **error);
int 	dff_libbfio_file_is_open(intptr_t *io_handle, libbfio_error_t **error);
int 	dff_libbfio_file_get_size(intptr_t *io_handle, size64_t *size, libbfio_error_t **error);

#endif
