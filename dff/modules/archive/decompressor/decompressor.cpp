/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
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

#include "decompressor.hpp"
#include "decompressornode.hpp"

using namespace DFF;

DecompressorFdinfo::DecompressorFdinfo() : arch(NULL), archiveReadOffset(0) 
{

}

ArchiveData::ArchiveData(Node* parent) : node(parent), vfile(NULL), buffer(malloc(ArchiveDataBufferSize))
{
}

ArchiveData::~ArchiveData()
{
  free(buffer);
}

Decompressor::Decompressor() : fso("uncompress"), __rootNode(NULL), __fdManager(new FdManager)
{
}

Decompressor::~Decompressor()
{
  if (this->__fdManager)
   delete this->__fdManager;
}

archive*   Decompressor::newArchive(void)
{
  struct archive *archiv = archive_read_new();

  //archive_read_support_format_all(archiv);
  archive_read_support_format_7zip(archiv);
  //archive_read_support_format_ar(archiv);
  archive_read_support_format_cab(archiv);
  //archive_read_support_format_cpio(archiv);
  archive_read_support_format_iso9660(archiv);
  archive_read_support_format_lha(archiv);  // usefull ?
  //archive_read_support_format_mtree(archiv);
  archive_read_support_format_rar(archiv);
  archive_read_support_format_tar(archiv);
  archive_read_support_format_xar(archiv); // usefull ?
  archive_read_support_format_zip(archiv);
  archive_read_support_format_raw(archiv);

  archive_read_support_filter_all(archiv);

  ArchiveData* data = new ArchiveData(this->__rootNode);
  archive_read_set_open_callback(archiv, &this->archiveOpen);
  archive_read_set_read_callback(archiv, &this->archiveRead);
  archive_read_set_seek_callback(archiv, &this->archiveSeek);
  archive_read_set_close_callback(archiv, &this->archiveClose);
  archive_read_set_callback_data(archiv, (void*)data);
  
  return (archiv);
}

void    Decompressor::createNodeTree(archive* archiv)
{
  struct archive_entry *entry;
  if (archive_read_open1(archiv) != ARCHIVE_OK)
    throw envError("Can't open archive");

  bool isRawTest = 1;

  Node* decompressorNode = new Node("Uncompressed", 0, NULL, this);
  while (archive_read_next_header(archiv, &entry) == ARCHIVE_OK) 
  {
    uint64_t    size = archive_entry_size(entry);
    std::string fullPath = archive_entry_pathname(entry);
    Node*       parentChunk = decompressorNode;

    if (isRawTest)
    {
       isRawTest = 0;
      if (std::string(archive_format_name(archiv)) == "raw"  && fullPath == "data")
      {
        char buff[1024];
        ssize_t   res = 0;
        size = 0;

        while (true) 
        {
          if ((res = archive_read_data(archiv, &buff, 1024)) <= 0)
            break; 
          size += res;    
        }
        if (size)
          new DecompressorNode("data", size, parentChunk, this, entry);
        break;
      }
    }

    std::string consumedPath = fullPath;
    while (consumedPath != "")
    {
       std::string pathChunk = consumedPath.substr(0, consumedPath.find("/"));
       size_t res = consumedPath.find("/");
       if (res + 1 == consumedPath.size() || res == std::string::npos)
         consumedPath = "";
       else
         consumedPath = consumedPath.substr(res + 1);

       if (consumedPath == "" && size)
       {
         DecompressorNode* decompressed = new DecompressorNode(pathChunk, size, parentChunk, this, entry);
         decompressed->archive(archiv);
         decompressed->dataType();
         decompressed->archive(NULL);
         archive_read_data_skip(archiv);
         break;
       }

       std::vector<Node*> children = parentChunk->children();
       std::vector<Node*>::const_iterator child = children.begin();
       for (; child != children.end(); ++child)
       {
          if (pathChunk == (*child)->name())
          {
            parentChunk = (*child);
            break;
          }
       }
       if (child == children.end())
         parentChunk = new Node(pathChunk, 0, parentChunk, this);
    }
  }
  archive_read_close(archiv);
  if (archive_read_free(archiv) != ARCHIVE_OK)
    throw envError("Can't free archive");

  if (decompressorNode->hasChildren())
   this->registerTree(this->__rootNode, decompressorNode);
  else
    delete decompressorNode;
}

void    Decompressor::start(Attributes args)
{
  if (args.find("file") != args.end())
    this->__rootNode = args["file"]->value<Node* >();
  else
    throw envError("Registry module need a file argument.");

  /** 
   *   Crate Archive structure & setcallback
   */
  archive* archiv = this->newArchive();
  this->createNodeTree(archiv);

  this->setStateInfo("Finished successfully");
  this->res["Result"] = Variant_p(new Variant(std::string("Decompressor finished successfully.")));
}

Node*		Decompressor::rootNode(void) const
{
  return (this->__rootNode);
}

void            Decompressor::setStateInfo(const std::string& str)
{
  this->stateinfo = str;
}

/**
 *  Archive callback to read on DFF VFile
 */
int             Decompressor::archiveOpen(struct archive *, void *data)
{

  ArchiveData* archiveData = (ArchiveData*)data;

  archiveData->vfile = archiveData->node->open();
  if (archiveData->vfile == NULL)
    return (-1);
  return (0);
}

ssize_t         Decompressor::archiveRead(struct archive *, void *data, const void **buffer)
{
  ArchiveData* archiveData = (ArchiveData*)data;

  int64_t res = archiveData->vfile->read(archiveData->buffer, ArchiveDataBufferSize);
  *buffer = archiveData->buffer;
  return (res);
}

int64_t         Decompressor::archiveSeek(struct archive *, void *data, int64_t offset, int whence)
{
  return (((ArchiveData*)data)->vfile->seek((uint64_t)offset, (int32_t)whence));
}

int             Decompressor::archiveClose(struct archive *, void *data)
{
  ArchiveData* archiveData = static_cast<ArchiveData*>(data);
  archiveData->vfile->close();
  delete archiveData;
  return (0);
}

archive*        Decompressor::openNodeArchive(Node* node)
{
  DecompressorNode* decompressorNode = static_cast<DecompressorNode* >(node);
  if (decompressorNode->archive())
    return (decompressorNode->archive()); //let node called dataType directly in the main loop to avoid reopening archive when scanned 

  archive* archiv = this->newArchive();
 
  std::string absolute = node->absolute();
  std::string archivPath = absolute.substr(absolute.rfind("Uncompressed/") + 13);

  int res = archive_read_open1(archiv); 
  if (res != ARCHIVE_OK)
    throw envError("Can't open archive");

  struct archive_entry *entry;
  int flag = 0;
  while (archive_read_next_header(archiv, &entry) == ARCHIVE_OK) 
  {
    if (archive_entry_pathname(entry) == archivPath)
    {
      flag = 1;
      break; 
    }
  }
  if (flag == 0)
    throw std::string("Can't find file in archive");
  
  return (archiv);
}

/**
 *   DFF VFile method to return uncompressed content
 */
int32_t         Decompressor::vopen(Node* node)
{
  DecompressorFdinfo* fi = new DecompressorFdinfo();
  fi->node = node;
  fi->offset = 0;
  fi->arch = this->openNodeArchive(fi->node);

  return (this->__fdManager->push(fi));
}

int32_t         Decompressor::vread(int32_t fd, void *rbuff, uint32_t size)
{
  try
  {
    DecompressorFdinfo* fi = (DecompressorFdinfo*)this->__fdManager->get(fd);
    if (fi->offset >= fi->node->size())
      return 0;

    if (fi->offset < fi->archiveReadOffset)
    {
      archive_read_free(fi->arch);
      fi->arch = this->openNodeArchive(fi->node);
      fi->archiveReadOffset = 0;
    }

    int32_t  currentSize = 0;
    char skipBuff[1024*1024];
    while (fi->archiveReadOffset < fi->offset)
    {
      if (fi->offset - fi->archiveReadOffset > 1024*1024)
        currentSize = 1024*1024;
      else
        currentSize = fi->offset - fi->archiveReadOffset;
      int32_t res = archive_read_data(fi->arch, skipBuff, currentSize);
      fi->archiveReadOffset += res;
    }

    int32_t res = archive_read_data(fi->arch, rbuff, size);
    fi->offset += res;
    fi->archiveReadOffset += res;

    return (res);
  }
  catch (...) 
  {
    return (0);
  }
  return (0);
}

uint64_t        Decompressor::vseek(int32_t fd, uint64_t offset, int32_t whence)
{
  Node*	node;
  fdinfo* fi;

  try
  {
    fi = this->__fdManager->get(fd);
    node = fi->node;

    if (whence == 0)
    {
      if (offset <= node->size())
      {
        fi->offset = offset;
        return (fi->offset);
      } 
    }
    else if (whence == 1)
    {
      if (fi->offset + offset <= node->size())
      {
        fi->offset += offset;
	return (fi->offset);
      }
    }
    else if (whence == 2)
    {
      fi->offset = node->size();
      return (fi->offset);
    }
  }
  catch (...)
  {
    return ((uint64_t) -1);
  }

  return ((uint64_t) -1);
}

uint64_t        Decompressor::vtell(int32_t fd)
{
  try 
  {
    fdinfo* fi = this->__fdManager->get(fd);
    return (fi->offset);
  }
  catch (...)
  {
    return ((uint64_t)-1);
  }
}

int32_t         Decompressor::vclose(int32_t fd)
{
  DecompressorFdinfo* fi = (DecompressorFdinfo*)(this->__fdManager->get(fd));

  DecompressorNode* decomp = static_cast<DecompressorNode*>(fi->node);

  if (decomp->archive() == NULL)
    archive_read_free(fi->arch);

  this->__fdManager->remove(fd);
  return (0);
}

uint32_t        Decompressor::status(void)
{
  return (0);
}

int32_t         Decompressor::vwrite(int fd, void* buff, unsigned int size)
{
  return (0);
}
