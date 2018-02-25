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
#include "vfile.hpp"

#include "data.hpp"
#include "mftattribute.hpp"
#include "ntfs.hpp"
#include "bootsector.hpp"

CompressionInfo::CompressionInfo(uint64_t runSize)
{
  this->uncomp_buf = (char*)malloc(runSize);
  this->comp_buf = (char*)malloc(runSize);
  memset(this->uncomp_buf, 0, runSize);
  memset(this->comp_buf, 0, runSize);
  this->buf_size_b = runSize; //XXX bs
  this->uncomp_idx = 0;
  this->comp_len = 0;
}

CompressionInfo::~CompressionInfo(void)
{
  free(this->uncomp_buf);
  free(this->comp_buf);
}

void Data::__uncompressBlock(CompressionInfo* comp)
{ //code from sleuthkit 4.0.x
  comp->uncomp_idx = 0;
  for (size_t cl_index = 0; cl_index + 1 < comp->comp_len;) 
  {
    size_t blk_end;         // index into the buffer to where block ends
    size_t blk_size;        // size of the current block
    uint8_t iscomp;         // set to 1 if block is compressed
    size_t blk_st_uncomp;   // index into uncompressed buffer where block started

    blk_size = ((((unsigned char) comp->comp_buf[cl_index + 1] << 8) | ((unsigned char) comp->comp_buf[cl_index])) & 0x0FFF) + 3;
    if (blk_size == 3)
      break;

    blk_end = cl_index + blk_size;
    if (blk_end > comp->comp_len) 
      throw std::string("Block length longer than buffer length");
    
    if ((comp->comp_buf[cl_index + 1] & 0x8000) == 0)
      iscomp = 0;
    else
      iscomp = 1;

    blk_st_uncomp = comp->uncomp_idx;
    cl_index += 2;
    if ((iscomp) || (blk_size - 2 != 4096)) 
    {
      while (cl_index < blk_end) 
      {
        unsigned char header = comp->comp_buf[cl_index];
        cl_index++;
        for (int a = 0; a < 8 && cl_index < blk_end; a++) 
        {
          if ((header & NTFS_TOKEN_MASK) == NTFS_SYMBOL_TOKEN) 
          {
            if (comp->uncomp_idx >= comp->buf_size_b) 
              throw ("Trying to write past end of uncompression buffer");
            comp->uncomp_buf[comp->uncomp_idx++] = comp->comp_buf[cl_index];
            cl_index++;
          }
          else 
          {
            size_t i;
            int shift;
            size_t start_position_index = 0;
            size_t end_position_index = 0;
            unsigned int offset = 0;
            unsigned int length = 0;
            uint16_t pheader;

            if (cl_index + 1 >= blk_end) 
              throw("Phrase token index is past end of block:");

            pheader = ((((comp->comp_buf[cl_index +1]) << 8) & 0xFF00) | (comp->comp_buf[cl_index] & 0xFF));
            cl_index += 2;
            shift = 0;
            for (i = comp->uncomp_idx - blk_st_uncomp - 1; i >= 0x10; i >>= 1) 
            {
              shift++;
            }

            offset = (pheader >> (12 - shift)) + 1;
            length = (pheader & (0xFFF >> shift)) + 2;
            start_position_index = comp->uncomp_idx - offset;
            end_position_index = start_position_index + length;
            if (offset > comp->uncomp_idx) 
              throw std::string("Phrase token offset is too large:");
            else if (length + start_position_index > comp->buf_size_b) 
              throw std::string("Phrase token length is too large");
            else if (end_position_index - start_position_index + 1 > comp->buf_size_b - comp->uncomp_idx) 
              throw std::string("Phrase token length is too large for rest of uncomp buf");

            for (; start_position_index <= end_position_index && comp->uncomp_idx < comp->buf_size_b; start_position_index++) 
              comp->uncomp_buf[comp->uncomp_idx++] = comp->uncomp_buf[start_position_index];
          }
          header >>= 1;
        }
     }
   }
    else 
    {
      while (cl_index < blk_end && cl_index < comp->comp_len) 
      {
        if (comp->uncomp_idx >= comp->buf_size_b) 
          throw("Trying to write past end of uncompression buffer (1) -- corrupt data?)");
        comp->uncomp_buf[comp->uncomp_idx++] = comp->comp_buf[cl_index++];
      }
    }
  }
}

uint64_t Data::__readBlock(VFile* fs, RunList run, uint8_t** data, int64_t runSize, uint64_t* lastValidOffset, uint32_t compressionBlockSize)
{
  uint32_t clusterSize = this->mftAttribute()->ntfs()->bootSectorNode()->clusterSize();
  uint64_t blockSize = (uint64_t)clusterSize * (uint64_t)compressionBlockSize;
  uint64_t runLength = run.length; 
  uint64_t runRoundedBlock = (runLength / compressionBlockSize) * compressionBlockSize;
  uint64_t runRoundedSize = runRoundedBlock * clusterSize;
  uint64_t runOffset = run.offset;
  uint64_t total = 0;
  CompressionInfo compressionInfo(runSize);

  if (run.length > compressionBlockSize)
    *data = (uint8_t*)malloc(clusterSize * ((runLength / compressionBlockSize) + 1) * compressionBlockSize); //roundedBlockSize + 1
  else
    *data = (uint8_t*)malloc(blockSize); //malloc before then free
 
  /* data is not compressed or data is sparse */ 
  if (runLength >= compressionBlockSize)
  {
    compressionInfo.uncomp_idx = 0;
    /* data is sparse */
    if (runOffset == 0)
    {
      memset(*data, 0, runRoundedSize);
      total += runRoundedSize;
      return (total); //even if there is still data a compressed run will follow
    }
    /* data is not compressed */
    else
    {
      if (fs->seek(runOffset * clusterSize) != (runOffset * clusterSize))
      {
        return (total);
      }
      if (fs->read(*data, runRoundedSize) != (int32_t)runRoundedSize)
      {
        return (total);
      }
      runOffset += runRoundedBlock;
      compressionInfo.uncomp_idx += runRoundedSize;
      *lastValidOffset = runOffset;
    }
    total += runRoundedSize;
    runLength = runLength % compressionBlockSize;
    if (runLength == 0)
      return total;
  }
  /* data is compressed */
  if (runOffset && runLength < compressionBlockSize)
  {
    if (fs->seek(runOffset * clusterSize) != (runOffset * clusterSize))
      throw std::string("Data::readBlock can't seek to data for decompression buffer");
    if (fs->read(&(compressionInfo.comp_buf[compressionInfo.comp_len]), clusterSize * runLength) != (int32_t)(clusterSize * runLength))
      throw std::string("Data::readBlock can't read data to decompression buffer");
    compressionInfo.comp_len += clusterSize * runLength; //increment buffer size
    *lastValidOffset += runLength;
    
    this->__uncompressBlock(&compressionInfo);

    if (run.length > compressionBlockSize)
      memcpy(*data + runRoundedSize, compressionInfo.uncomp_buf, blockSize);
    else
      memcpy(*data, compressionInfo.uncomp_buf, blockSize);
    total += blockSize;
    return (total);
  }
  return (total);
}

/**
 *  Use run list to determine if data is compressed, sparse or not compressed
 */
uint64_t        Data::uncompress(uint8_t* buff, uint64_t size, uint64_t offset, uint32_t compressionBlockSize)
{
  uint64_t readed = 0;
  uint64_t totalRead = 0;
  uint64_t lastValidOffset = 0;
  uint32_t clusterSize = this->mftAttribute()->ntfs()->bootSectorNode()->clusterSize();
  uint64_t startOffset = this->mftAttribute()->VNCStart() * clusterSize;
  std::vector<RunList>  runList = this->runList(); //runList
  std::vector<RunList>::iterator run = runList.begin(); 
  VFile* fs = this->mftAttribute()->ntfs()->fsNode()->open();

  /*
   * Read run list until end
   * Use run list to determine if data is compressed, sparse or not compressed
   */
  for (; (readed < size) && (run != runList.end()); ++run)
  {
    uint8_t* data = NULL;
    try
    {
      int64_t runSize = (*run).length;
      if (runSize < compressionBlockSize)
        runSize = (int64_t)compressionBlockSize * (int64_t)clusterSize;
      else
        runSize = runSize * clusterSize;

      if ((*run).offset != 0)
        lastValidOffset = (*run).offset; //keep track of last offset
     
      /*calculate next block run size */ 
      uint64_t uncompressedBlockSize = 0;
      uint64_t currentLength = (*run).length;
      if (currentLength > compressionBlockSize)
      {
        uint64_t rounded = (currentLength / compressionBlockSize ) * compressionBlockSize;
        uncompressedBlockSize = rounded * clusterSize;
        currentLength -= rounded;
      }
      if ((*run).offset && currentLength &&  (currentLength <= compressionBlockSize))       {
        uncompressedBlockSize += clusterSize * compressionBlockSize;
      }
      else if (((*run).offset  == 0) && (currentLength == compressionBlockSize))
      {
        uncompressedBlockSize += clusterSize * compressionBlockSize;
      }
      if (uncompressedBlockSize == 0) 
      {
        free(data);
        continue;
      }

      uint64_t currentOffset = totalRead + startOffset;
      uint64_t nextOffset = offset + readed;
      uint64_t maxOffset = totalRead  + startOffset + uncompressedBlockSize;
      if ((currentOffset <= nextOffset) && (nextOffset <= maxOffset)) //in range 
      {
        uint64_t dataSize = this->__readBlock(fs, *run, &data, runSize, &lastValidOffset, compressionBlockSize);
        if (dataSize <= 0)
        {
          free(data);
          delete fs;
          return (readed);
        }
        uint64_t dataOffset = nextOffset - currentOffset;
        uint64_t toCopy = size - readed;
        uint64_t copyMax = maxOffset - nextOffset;
        if (toCopy > copyMax)
          toCopy = copyMax;
        if (!toCopy)
        {
          free(data);
          totalRead += dataSize;
          continue ; //block boundary 
        }
        if (readed + dataSize >= size)
        {
          memcpy(buff + readed, data + dataOffset, toCopy);
          free(data);
          delete fs;
          return (size);
        }
        memcpy(buff + readed, data + dataOffset, dataSize - dataOffset);
        readed += dataSize - dataOffset;
      }
      free(data);
      totalRead += uncompressedBlockSize;
    }
    catch(std::string const& error)
    {
      free(data); 
      break;
    } 
  }
  delete fs;
  return (readed);
}

Data::Data(MFTAttribute* mftAttribute) : MFTAttributeContent(mftAttribute)
{
}

MFTAttributeContent*	Data::create(MFTAttribute*	mftAttribute)
{
  return (new Data(mftAttribute));
}
Data::~Data()
{
}

const std::string       Data::typeName(void) const
{
  return (std::string("$DATA"));
}
Attributes	Data::_attributes(void)
{
  Attributes	attrs;

  MAP_ATTR("Attributes", MFTAttributeContent::_attributes())
  return (attrs);
}
