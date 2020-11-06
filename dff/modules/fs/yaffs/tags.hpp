#ifndef __YAFFS_TAGS_HPP__
#define __YAFFS_TAGS_HPP__

#include <vector>
#include <map>

namespace DFF
{
class Node;
}

class YAFFS;
class NodeObject;

class Tag
{
public:
  Tag(uint8_t* spare, uint64_t offset);
  void display(void);

  uint32_t  offset;
  uint32_t  object_id;
  uint8_t   page_status;
  uint8_t   block_status;
  uint32_t  chunk_id;
  uint8_t   serial_number;
  uint32_t  size;
};

class Tags
{
public:
  Tags();

  uint32_t number_of_tags;
  uint32_t number_of_ok_tags;
  uint32_t number_of_bad_tags;

  std::vector<Tag>                         tags; 
  std::map<uint32_t, std::vector<Tag> > objects;
  std::map<uint32_t, NodeObject* >        nodes; //list of node and list of int32 is ok ? 

  void addTag(uint8_t* spare, uint64_t offset);
  void display(void);

  void createNode(YAFFS* fsobj, DFF::Node* parent, std::vector<Tag>);
  void createNodes(YAFFS* fsobj, DFF::Node* root);
  
  void createTree(YAFFS* fsobj);
};

#endif
