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
#include "fdmanager.hpp"

#include "ntfs.hpp"
#include "ntfsopt.hpp"
#include "bootsector.hpp"
#include "mftentrynode.hpp"
#include "mftnode.hpp"
#include "mftattributecontent.hpp"
#include "mftattribute.hpp"
#include "mftmanager.hpp"
#include "attributes/data.hpp"
/**
 *  NTFS 
 */
NTFS::NTFS() : mfso("ntfs"), __opt(NULL), __bootSectorNode(NULL), __mftManager(NULL), __rootDirectoryNode(new Node("NTFS", 0, NULL, this)), __orphansNode(new Node("orphans"))
{
  
}

NTFS::~NTFS()
{
  if (this->__bootSectorNode)
    delete this->__bootSectorNode;
  if (this->__rootDirectoryNode)
    delete this->__rootDirectoryNode;
  if (this->__mftManager)
    delete this->__mftManager;
}

void    NTFS::start(Attributes args)
{
  this->__opt = new NTFSOpt(args);
  this->__bootSectorNode = new BootSectorNode(this);
  if (this->__opt->validateBootSector())
    this->__bootSectorNode->validate();

  /* 
   * GET MFT NODE 
   */ 
  this->setStateInfo("Reading main MFT");
  this->__mftManager = new MFTEntryManager(this);
  this->__mftManager->initMasterMFT();
  this->__mftManager->initEntries();
  this->__mftManager->linkEntries(); 
  this->__mftManager->linkOrphanEntries();
  this->registerTree(this->opt()->fsNode(), this->rootDirectoryNode());
  this->registerTree(this->rootDirectoryNode(), this->orphansNode());
  this->__mftManager->linkUnallocated();
  //this->registerTree(this->rootDirectoryNode(), this->unallocatedNode());
  this->__mftManager->linkReparsePoint();
  //delete this->__mftManager; //Unallocated node use it 

  this->setStateInfo("Finished successfully");
  this->res["Result"] = Variant_p(new Variant(std::string("NTFS parsed successfully.")));
}

NTFSOpt*	NTFS::opt(void) const
{
  return (this->__opt);
}

MFTEntryManager* NTFS::mftManager(void) const
{
  return (this->__mftManager);
}

Node*		NTFS::fsNode(void) const
{
  return (this->__opt->fsNode());
}

Node*           NTFS::orphansNode(void) const
{
  return (this->__orphansNode);
}

void 		NTFS::setStateInfo(const std::string& info)
{
  this->stateinfo = std::string(info);
}

Node*		NTFS::rootDirectoryNode(void) const
{
  return (this->__rootDirectoryNode);
}

BootSectorNode*	NTFS::bootSectorNode(void) const
{
  return (this->__bootSectorNode);
}

//Node*           NTFS::unallocatedNode(void) const
//{
  //return (this->__unallocatedNode);
//}

/**
 *  Redefine read to use both file mapping
 *  and special read method for compressed data
 */
int32_t  NTFS::vread(int fd, void *buff, unsigned int size)
{
  fdinfo* fi = NULL;
  try
  {
    fi = this->__fdmanager->get(fd);
  }
  catch (vfsError const& e)
  {
    return (0); 
  }
  catch (std::string const& e)
  {
    return (0);
  }
 
  MFTNode* mftNode = dynamic_cast<MFTNode* >(fi->node);
  if (mftNode == NULL)
    return (mfso::vread(fd, buff, size));

  if (fi->offset > mftNode->size())
    return (0);

  try 
  {
    if (!mftNode->isCompressed())
      return (mfso::vread(fd, buff, size));
    return (mftNode->readCompressed(buff, size, &fi->offset));
  }
  catch (const std::string& error)
  {
    std::string finalError = "NTFS::vread on " + mftNode->absolute() + " error: " + error;
    throw vfsError(finalError);
  }
}
