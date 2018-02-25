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

#include <vector>

#include "bootsector.hpp"
#include "mftnode.hpp"
#include "ntfs.hpp"
#include "attributes/mftattributecontenttype.hpp"

MFTNode::MFTNode(NTFS* ntfs, MFTEntryNode* mftEntryNode) : Node("", 0, NULL, ntfs), __mftEntryNode(mftEntryNode), __isCompressed(false)
{
}

MFTNode::~MFTNode(void)
{
  if (this->__mftEntryNode != NULL)
  {
    //delete this->__mftEntryNode; //used by ads 
    this->__mftEntryNode = NULL;
  }
}

MFTEntryNode* MFTNode::mftEntryNode(MFTEntryNode* mftEntryNode)
{
  return (this->__mftEntryNode);
}

void            MFTNode::setName(const std::string name)
{
  this->__name = name;
}

void            MFTNode::setMappingAttributes(MappingAttributesInfo const&  mappingAttributesInfo)
{
  this->mappingAttributesOffset = mappingAttributesInfo.mappingAttributes;
  this->__isCompressed = mappingAttributesInfo.compressed;
  this->setSize(mappingAttributesInfo.size);
}

bool            MFTNode::isCompressed(void) const
{
  return (this->__isCompressed);
}

void		MFTNode::fileMapping(FileMapping* fm)
{
  if (this->size() == 0)
    return;

  std::list<MappingAttributes >::iterator attributeOffset = this->mappingAttributesOffset.begin();
  for (; attributeOffset != this->mappingAttributesOffset.end(); ++attributeOffset)
  {
    MappingAttributes ma = *attributeOffset;
    MFTAttribute* data = ma.entryNode->__MFTAttribute(ma.offset);
    MFTAttributeContent* content = data->content();
    content->fileMapping(fm);
    delete data;
    delete content;   
  } 
}

/**
 *  read compressed data at offset
 *  return readed data size
 */
int32_t         MFTNode::readCompressed(void* buff, unsigned int size, uint64_t* offset)
{
  uint32_t readed = 0;
  uint32_t compressionBlockSize = 0;
  uint64_t clusterSize = this->__mftEntryNode->ntfs()->bootSectorNode()->clusterSize();
  uint32_t attributeCount = 0;

  std::list<MappingAttributes >::iterator attributeOffset = this->mappingAttributesOffset.begin();
  for (; (readed < size) && (attributeOffset != this->mappingAttributesOffset.end()); ++attributeOffset)
  {
    MappingAttributes mappingAttributes = *attributeOffset;
    MFTAttribute* dataAttribute = mappingAttributes.entryNode->__MFTAttribute(mappingAttributes.offset);
    MFTAttributeContent* content = dataAttribute->content();
    Data* data = dynamic_cast<Data*>(content);  
    if (!data)
     return (0);

    if (!compressionBlockSize)
      compressionBlockSize = dataAttribute->compressionBlockSize();
    uint64_t start = dataAttribute->VNCStart() * clusterSize;
    uint64_t end = dataAttribute->VNCEnd() * clusterSize;
    if ((start <= *offset) && (*offset < end))
    {
      int32_t read = 0;
      try 
      {
        read = data->uncompress((uint8_t*)buff + readed, size - readed, *offset, compressionBlockSize);
      }
      catch (std::string const & error)
      {
        //std::cout << "MFTNode::readCompressed data uncompression error : " << error << std::endl;
      }
      if (read  <= 0)
        break;
      if (*offset + read > this->size())
      {
        readed += this->size() - *offset;
        *offset = this->size();
        break;
      }
      *offset += read;
      readed += read;
    }
    attributeCount++;
    delete data;
    delete dataAttribute;
  }
  return (readed);
}

Attributes	MFTNode::_attributes(void)
{
  if (this->__mftEntryNode != NULL)
    return (this->__mftEntryNode->_attributes());
  Attributes attr;
  return (attr);
}
