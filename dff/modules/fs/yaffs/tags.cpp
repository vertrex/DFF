#include <stdint.h>
#include <stdio.h>

#include "tags.hpp"
#include "fso.hpp"
#include "vfile.hpp"
#include "typesconv.hpp"

#include "yaffs.hpp"
#include "node.hpp"
#include "object_node.hpp"

enum yaffs_obj_type {
	YAFFS_OBJECT_TYPE_UNKNOWN,
	YAFFS_OBJECT_TYPE_FILE,
	YAFFS_OBJECT_TYPE_SYMLINK,
	YAFFS_OBJECT_TYPE_DIRECTORY,
	YAFFS_OBJECT_TYPE_HARDLINK,
	YAFFS_OBJECT_TYPE_SPECIAL
};

#define YAFFS_OBJECTID_ROOT		1
#define YAFFS_OBJECTID_LOSTNFOUND	2
#define YAFFS_OBJECTID_UNLINKED		3
#define YAFFS_OBJECTID_DELETED		4

/*
 * Tag
 */
Tag::Tag(uint8_t* spare, uint64_t offset) : offset(offset) 
{
  this->page_status = spare[4];
  this->block_status = spare[5]; //not used ? 
  this->chunk_id =  (spare[0] << 12) + (spare[1] <<4) + (spare[2] >> 4);
  this->serial_number = (spare[2] & 0xf) >> 2; //check to know wich version use ? asdd to node info ?
  
  this->object_id = (spare[6] << 10) + (spare[7] << 2) + (spare[11] >> 6);

  this->size = (((spare[2] & 0xf) & 0x3) << 8) + spare[3]; //don't use msb ? as block size == 512?
}

void  Tag::display(void)
{
  printf("chunk_id %x size %d block_status %x page_status %x\n",  chunk_id, size, block_status, page_status); 
}

/*
 * Tags
 */
Tags::Tags()
{
  this->number_of_tags = 0;
  this->number_of_ok_tags = 0;
  this->number_of_bad_tags =0;
}

void Tags::addTag(uint8_t* spare, uint64_t offset)
{
  Tag tag = Tag(spare, offset);
  this->number_of_tags +=1;
  if (tag.object_id != 0x3ffff)
  {
    this->number_of_ok_tags +=1;
    this->objects[tag.object_id].push_back(tag);
  }
  else
  {
    this->number_of_bad_tags += 1;
  }
}

void  Tags::createNodes(YAFFS* yaffsFSO, DFF::Node* root)
{
  std::map<uint32_t, std::vector<Tag> >::iterator object = this->objects.begin();

  for (; object != this->objects.end(); ++object)
  {
    createNode(yaffsFSO, root, object->second);
  }
}

void  Tags::createNode(YAFFS* yaffsFSO, DFF::Node* parent, std::vector<Tag> tags)
{
  uint32_t multi_zero = 0;
  DFF::Node*  dump_node = yaffsFSO->parent(); 
  DFF::VFile* dump_file = dump_node->open();

  std::vector<Tag>::iterator tag = tags.begin();
  for (; tag != tags.end(); ++tag)
  {
    //XXX must create only node for 0xff cluster (block 0 & other blocks !!!!)
    //then maybe create deleted version (add deleted flag or deleted in the name)
    //here as we put in map[uid] = node we create all the node but link only one the latest
    //when we call create tree ....
    //we can have different version but we can't keep it them here 
    //or must add an options for that ! 

    if (tag->chunk_id == 0) //check for node without 0 ? check if block / chunk page status etc ??? XXX
    {
      multi_zero += 1;
      ObjectHeader object_header;

      dump_file->seek(tag->offset);
      dump_file->read(&object_header, sizeof(ObjectHeader));
     
      NodeObject* object_node = NULL;
      uint32_t object_type = bytes_swap32(object_header.type);
 
      if (object_type == YAFFS_OBJECT_TYPE_FILE)
      { 
        object_node = new NodeObjectFile(yaffsFSO, object_header, tags, tag->object_id);//+tags list 
      }
      else if (object_type == YAFFS_OBJECT_TYPE_DIRECTORY) 
      {
        object_node = new NodeObjectDirectory(yaffsFSO, object_header, tag->object_id);
      }
      else if (object_type == YAFFS_OBJECT_TYPE_UNKNOWN)
      {
        object_node = new NodeObjectDirectory(yaffsFSO, object_header, tag->object_id);
      }
      else if (object_type == YAFFS_OBJECT_TYPE_HARDLINK)
      {
        object_node = new NodeObjectHardlink(yaffsFSO, object_header, tag->object_id);
      }
      else if (object_type == YAFFS_OBJECT_TYPE_SYMLINK)
      {
        object_node = new NodeObjectDirectory(yaffsFSO, object_header, tag->object_id);
      }
      else if (object_type == YAFFS_OBJECT_TYPE_SPECIAL)
      {
        object_node = new NodeObjectDirectory(yaffsFSO, object_header, tag->object_id);
      }
      else 
        std::cout << "Unknown object id " << tag->object_id << std::endl;

      if (object_node)
      {
        if (tag->page_status != 0xff) //check serial too to avoid duplicate ?
        {
          object_node->setDeleted();
          this->deleted_nodes[tag->object_id].push_back(object_node);
        } 
        else
        {
          //must XXX must check if already exist or there is a problemn !
          //must only have one node for directory parent not deleted but check here please
          this->nodes[tag->object_id] = object_node;
        }
      }
    }
  }


  delete dump_file;
}

void  Tags::addNodeToTree(YAFFS* yaffsFSO, NodeObject* node)
{
  uint32_t parentId = node->parentObjectId(); 

  if (parentId == YAFFS_OBJECTID_ROOT)
  {
     yaffsFSO->root()->addChild(node);
  }
  else if (parentId == YAFFS_OBJECTID_LOSTNFOUND)
  {
    yaffsFSO->lostnfound()->addChild(node);
  }
  else if (parentId == YAFFS_OBJECTID_UNLINKED)
  {
     yaffsFSO->unlinked()->addChild(node);
  }
  else if (parentId == YAFFS_OBJECTID_DELETED)
  {
    node->setDeleted(); //XXX we already checked for 0xff tag what's the difference ??
    yaffsFSO->deleted()->addChild(node);
  }
  else
  {
    std::map<uint32_t, NodeObject* >::iterator parent = this->nodes.find(parentId);
    //check if parent in deleted if not in normal nodes ??? XXX 
    if (parent != this->nodes.end())
    {
      NodeObject* parentNode = parent->second;  
      parentNode->addChild(node);
    }
    else
    {
      yaffsFSO->orphaned()->addChild(node);
    }
  }
}

void  Tags::createTree(YAFFS* yaffsFSO)
{
  std::map<uint32_t, NodeObject* >::const_iterator node = this->nodes.begin();

  for (; node != this->nodes.end(); ++node)
  {
    this->addNodeToTree(yaffsFSO, node->second);
  }

  std::map<uint32_t, std::vector<NodeObject*> >::const_iterator nodes_lists = this->deleted_nodes.begin();
  for (; nodes_lists != this->deleted_nodes.end(); ++nodes_lists)
  {
    std::vector<NodeObject*> nodes_list = nodes_lists->second;
    std::vector<NodeObject*>::const_iterator node = nodes_list.begin();
    for (; node != nodes_list.end(); ++node)
    {
      this->addNodeToTree(yaffsFSO, *node); 
    }
  }
}

void  Tags::display(void)
{
  std::map<uint32_t, std::vector<Tag> >::iterator object = this->objects.begin();

  for (; object != this->objects.end(); object++)
  {
    std::cout << "Object id " << object->first << std::endl;
    std::vector<Tag>::iterator chunk = object->second.begin();
    for (; chunk != object->second.end(); ++chunk)
    {
      chunk->display();
    }
  }
}
