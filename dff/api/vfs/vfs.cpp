/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
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
 *  Solal J. <sja@digital-forensic.org>
 */

#include "fso.hpp"
#include "node.hpp"
#include "vfs.hpp"
#include "rootnode.hpp"
#include "vlink.hpp"

namespace DFF
{
/**
 *  Return singleton instance of VFS
 */
VFS&	VFS::Get()
{ 
  static VFS single;
  return single;
}

/**
 *  Construct VFS and register root node '/'
 */
VFS::VFS()
{
  this->root = new VFSRootNode("/");
  this->registerNode(this->root);
  cwd = root;
}

VFS::~VFS()
{
}

/**
 *  Handle Event
 */
void    VFS::Event(event *e)
{
}

/**
 *  Change current working directory
 */
void    VFS::cd(Node *path)
{
  cwd = path;
}

/**
 *  Return current working directory
 */
Node*   VFS::GetCWD(void)
{
  return (cwd);
}

/**
 *  Register FSobj to a list and return an UID 
 */
uint16_t	VFS::registerFsobj(fso* fsobj) throw (vfsError)
{
  if (fsobj != NULL)
    this->__fsobjs.push_back(fsobj);
  else
    throw (vfsError("registerFsobj() NULL pointer provided"));
  return (uint16_t)(this->__fsobjs.size());
}

/**
 *  Return an ID and register ndoe in the node/ID manager
 */
uint64_t        VFS::registerNode(Node* node)
{
  return (this->__nodeManager.uid(node));
}

/**
 *  Deleted Node and remove them from the UID manager recursively
 */
void    VFS::__deleteNode(Node* node)
{
  std::vector<Node*> children = node->children();
  std::vector<Node*>::const_iterator child = children.begin();
  for (; child != children.end(); ++child)
    this->__deleteNode(*child);
  Node* parent = node->parent();
  if (parent)
    parent->removeChild(node);
  this->__nodeManager.remove(node);
  delete node;
}

/** 
 *  Unregister node from the tree by removing it in parent list
 *  Use delete node recursively to delete and unregister the tree
 *  Node destructor call this method (must be used on root/registered root)
 *  Event is sent before deletion so registered event can clear data recursively before deletion
 */
bool            VFS::unregister(Node* node) 
{
  if (node == NULL)
    return (false);

  VLink*  vlink = dynamic_cast<VLink*>(node);
  fso* fsobj = node->fsobj();
  if (vlink || !fsobj)
  {
    event* e = new event;
    e->type = 0x0de1; 
    e->value = Variant_p(new Variant(node));
    this->notify(e);

    this->__deleteNode(node);
    return (true);
  }
  else 
  {
    //Not implemented yet
    throw ("Not implemented");
    //node->parent()->removeChild(node); //XXX if we want do handle it ... 
    //fsobj->unamp(node);
    //fsobj->remove(node);
    return (true);
  }

  return (false);
}

/**
 *  Return lists of all registered fsobjs
 */
std::vector<fso*>	VFS::fsobjs()
{
  return (this->__fsobjs);
}

/**
 *  Return current total of nodes registered in the VFS and fsobjs
 */
uint64_t	VFS::totalNodes(void)
{
  size_t	i;
  uint64_t	totalnodes;

  totalnodes = this->__nodeManager.orphansCount();
  for (i = 0; i != this->__fsobjs.size(); i++)
    totalnodes += this->__fsobjs[i]->nodeCount();
  return (totalnodes);
}

/**
 *  Return node by path from starting point Node where
 */
Node* VFS::GetNode(std::string path, Node* where)
{
  std::vector<Node *>	next;
  uint32_t		i;

  if (path == "..")
    return (where->parent());
  if (where->hasChildren())
  {
      next = where->children();
      for (i = 0; i < next.size(); i++)
      {
	if (next[i]->name() == path)
	  return (next[i]); 
      }
      return (0);
  }
  else
    return (0);
}

/**
 *  Return node by path
 */
Node* VFS::GetNode(std::string path)
{
  if (path == "/")
    return root;	
  path = path.substr(path.find('/') + 1);
  std::string lpath;
  std::string rpath = path;
  Node* tmp = root;
  do
  {
    if (rpath.find('/') != std::string::npos)
    {
      lpath = rpath.substr(0, rpath.find('/'));
      rpath = rpath.substr(rpath.find('/') + 1); 
    }
    else
    { 
      lpath = rpath;
      rpath = "";
    }
    tmp = GetNode(lpath, tmp);
  }  while (tmp && rpath.size());
  return (tmp);
}

/**
 *  Return node by id
 */
Node*	VFS::getNodeById(uint64_t id)
{
  uint16_t fsoid = id >> 48;

  if (fsoid == 0)
    return (this->__nodeManager.node(id)); //orphans / unlinked
  else if ((fsoid > 0) && ((fsoid - 1) < (uint16_t)this->__fsobjs.size()))
  {
    fso* fsobj = this->__fsobjs[fsoid - 1];
    if (fsobj)
      return fsobj->getNodeById(id);
  }
  return (NULL);
}

/**
 *  Node Manager
 *  This class manager node by giving them an unique id 
 *  that permet to track node and get them back from that uid
 */
NodeManager::NodeManager() : __nextId(0)
{
}

/**
 *  Register a node by Id or return the node id
 */
uint64_t NodeManager::uid(Node* node)
{
  uint64_t uid = 0;
  fso*  fsobj = node->fsobj();
  VLink* vlink = dynamic_cast<VLink*>(node); 

  if (fsobj && !vlink)
  {
    uid = (uint64_t)fsobj->uid() << 48;
   // if (node->parent()) //XXX for NTFS and module that deleted node,  what happen if parent is linked after ?
   // {
      uid |= this->__nextId;
      node->fsobj()->registerNode(uid, node);
      this->__nextId++;
      return (uid);
   // }
  }
  uid |= __nextId;
  this->__orphans[uid] = node;
  this->__nextId++;
  return (uid);
}

/** 
 *  Return node not managed by fso from an uid (fso orphans)  
 */ 
Node* NodeManager::node(uint64_t uid) const
{
  std::map<uint64_t, Node* >::const_iterator node = this->__orphans.find(uid);
  if (node != this->__orphans.end())
    return (node->second);
  return (NULL);
}

/**
 *  Return number of nodes not managed by fso (fso orphans)
 */
uint64_t	NodeManager::orphansCount() const
{
  return (this->__orphans.size());
}

/**
 *  Remove node by uid from fso orphans nodes list
 */
bool  NodeManager::remove(uint64_t uid)
{
  if (this->__orphans.erase(uid) == 0)
    return (false);
  return (true);
}

/**
 *  Remode node from fso orphans nodes list
 */
bool  NodeManager::remove(Node* node)
{
  return (this->remove(node->uid())); 
}

}
