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

#include "libbfio_wrapper.hpp"

int dff_libbfio_file_io_handle_initialize(dff_libbfio_file_io_handle_t** dff_io_handle, libbfio_error_t** error)
{
  if (dff_io_handle == NULL)
    return (-1);
  if (*dff_io_handle == NULL)
  {
    *dff_io_handle = (dff_libbfio_file_io_handle_t*)malloc(sizeof(dff_libbfio_file_io_handle_t));
    if (*dff_io_handle == NULL)
      return (-1);
  }

  return (1);
}

int dff_libbfio_file_initialize(libbfio_handle_t **handle, libbfio_error_t** error, Node* parent)
{
  dff_libbfio_file_io_handle_t *io_handle = NULL;

  if (handle == NULL)
     return( -1 );
 
  if (*handle == NULL)
  {
    if (dff_libbfio_file_io_handle_initialize(&io_handle, error) == -1)
      return (-1);

    io_handle->access_flags = 0;
    io_handle->file = NULL; 
    io_handle->parent = parent;	
    if (libbfio_handle_initialize(handle, (intptr_t*)io_handle,
        dff_libbfio_file_io_handle_free, dff_libbfio_file_io_handle_clone, dff_libbfio_file_open, 
	dff_libbfio_file_close, dff_libbfio_file_read, dff_libbfio_file_write, 
	dff_libbfio_file_seek_offset,  dff_libbfio_file_exists, dff_libbfio_file_is_open, 
	dff_libbfio_file_get_size, 
	LIBBFIO_FLAG_IO_HANDLE_MANAGED | LIBBFIO_FLAG_IO_HANDLE_CLONE_BY_FUNCTION, error) != 1 )
      {
         libbfio_error_free(error);
	 dff_libbfio_file_io_handle_free((intptr_t **) &io_handle, NULL );
	 return (-1);
      }
  }

  return (1);
}

int dff_libbfio_file_open(intptr_t *io_handle, int access_flags, libbfio_error_t** error)
{
  dff_libbfio_file_io_handle_t* file_io_handle = (dff_libbfio_file_io_handle_t*) io_handle;

  if (file_io_handle == NULL)
    return (-1);
  if (file_io_handle->parent == NULL)
    return (-1);

  VFile* file = file_io_handle->parent->open();
  if (file == NULL)
    return (-1);
  file_io_handle->file = file;
  file_io_handle->access_flags = access_flags;

  return (1);
}

int dff_libbfio_file_io_handle_free(intptr_t **io_handle, libbfio_error_t** error)
{
  if (io_handle == NULL)
    return (-1);
  if (*io_handle == NULL)
    return (-1);
  dff_libbfio_file_io_handle_t* file_io_handle = (dff_libbfio_file_io_handle_t*)(*io_handle);
  if (file_io_handle->file != NULL)
  {
     file_io_handle->file->close();
     delete file_io_handle->file;
     file_io_handle->file = NULL;
  }  
  free(file_io_handle);

  return (1);
}

int dff_libbfio_file_io_handle_clone(intptr_t **destination_io_handle, intptr_t *source_io_handle, libbfio_error_t** error)
{
  if (destination_io_handle == NULL)
    return (-1);
  if (*destination_io_handle != NULL)
    return (-1);

  dff_libbfio_file_io_handle_t*   source_file_io_handle = (dff_libbfio_file_io_handle_t*)source_io_handle;
  dff_libbfio_file_io_handle_t**  destination_file_io_handle = (dff_libbfio_file_io_handle_t**) destination_io_handle;
  *destination_file_io_handle = (dff_libbfio_file_io_handle_t*)malloc(sizeof(dff_libbfio_file_io_handle_t));
  (*destination_file_io_handle)->access_flags = source_file_io_handle->access_flags;
  (*destination_file_io_handle)->parent = source_file_io_handle->parent;
  (*destination_file_io_handle)->file = NULL;

  return (1);
}


int dff_libbfio_file_close(intptr_t *io_handle, libbfio_error_t** error)
{
  dff_libbfio_file_io_handle_t* file_io_handle = (dff_libbfio_file_io_handle_t*) io_handle;

  if (file_io_handle == NULL)
    return (-1);
  if (file_io_handle->file == NULL)
    return (-1);
  file_io_handle->file->close();
  file_io_handle->file = NULL;

  return (0);
}

ssize_t dff_libbfio_file_read(intptr_t *io_handle, uint8_t *buffer, size_t size, libbfio_error_t** error)
{
  dff_libbfio_file_io_handle_t* file_io_handle = (dff_libbfio_file_io_handle_t*) io_handle;

  if (file_io_handle == NULL)
    return (0);
  if (file_io_handle->file == NULL)
    return (0);

  return (file_io_handle->file->read((void*)buffer, size));
}

ssize_t dff_libbfio_file_write(intptr_t *io_handle, const uint8_t *buffer, size_t size, libbfio_error_t** error)
{
  return (-1);
}

off64_t dff_libbfio_file_seek_offset(intptr_t *io_handle, off64_t offset, int whence, libbfio_error_t** error)
{
  dff_libbfio_file_io_handle_t* file_io_handle = (dff_libbfio_file_io_handle_t*) io_handle;
  if (file_io_handle == NULL)
    return (0);
	
  if (file_io_handle->file == NULL)
    return (0);

  return file_io_handle->file->seek((uint64_t)offset, (int32_t)whence);
}

int dff_libbfio_file_exists(intptr_t *io_handle, libbfio_error_t** error)
{
  dff_libbfio_file_io_handle_t* file_io_handle = (dff_libbfio_file_io_handle_t*) io_handle;
  if (file_io_handle == NULL)
    return (0);
  if (file_io_handle->parent == NULL)
    return (0);	

  return (1);
}


int dff_libbfio_file_is_open(intptr_t *io_handle, libbfio_error_t** error)
{
  dff_libbfio_file_io_handle* file_io_handle = (dff_libbfio_file_io_handle_t*) io_handle;
  if (file_io_handle == NULL)
    return (-1);
  if (file_io_handle->file == 0)
    return (0);
  else 
    return (1); 

  return (-1);
}

int dff_libbfio_file_get_size(intptr_t *io_handle, size64_t *size, libbfio_error_t** error)
{
  dff_libbfio_file_io_handle_t* file_io_handle = (dff_libbfio_file_io_handle_t*) io_handle;
  if (file_io_handle == NULL)
    return (0);
  if (file_io_handle->parent == NULL)
    return (0);	
  *size = (size64_t) file_io_handle->parent->size();

  return (1);
}
