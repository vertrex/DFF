#ifndef __YAFFS_OBJECT_NODE_HPP__
#define __YAFFS_OBJECT_NODE_HPP__

#include "export.hpp"
#include "yaffs.hpp"
#include "tags.hpp"
#include "node.hpp"

//#ifdef CONFIG_YAFFS_UNICODE
//#define YAFFS_MAX_NAME_LENGTH		127
//#define YAFFS_MAX_ALIAS_LENGTH		79
//#else
#define YAFFS_MAX_NAME_LENGTH		255
#define YAFFS_MAX_ALIAS_LENGTH		159
//#endif

namespace DFF
{
  class fso;
  class Node;
  class FileMapping;
}

//#include "node.hpp"
//pack it please
PACK_START
typedef struct ObjectHeader
{
	uint32_t  type;  /* enum yaffs_obj_type  */

	/* Apply to everything  */
	uint32_t  parent_obj_id;
	uint16_t  sum_no_longer_used;	/* checksum of name. No longer used */
	uint8_t   name[YAFFS_MAX_NAME_LENGTH + 1 + 2]; //add +2 to fix packing ...

	/* The following apply to all object types except for hard links */
	uint32_t  yst_mode;		/* protection */

	uint32_t  yst_uid;
	uint32_t  yst_gid;
	uint32_t  yst_atime;
	uint32_t  yst_mtime;
	uint32_t  yst_ctime;

	/* File size  applies to files only */
	uint32_t  file_size_low;

	/* Equivalent object id applies to hard links only. */
	int       equiv_id;

	/* Alias is for symlinks only. */
	uint8_t   alias[YAFFS_MAX_ALIAS_LENGTH + 1];

	uint32_t  yst_rdev;	/* stuff for block and char devices (major/min) */

	uint32_t  win_ctime[2];
	uint32_t  win_atime[2];
	uint32_t  win_mtime[2];

	uint32_t  inband_shadowed_obj_id;
	uint32_t  inband_is_shrink;

	uint32_t  file_size_high;
	uint32_t  reserved[1];
	//int     shadows_obj;	[> This object header shadows the
	//specified object if > 0 */

	/* is_shrink applies to object headers written when wemake a hole. */
	//uint32_t is_shrink;
} ObjectHeader_s;
PACK_END

class NodeObject : public DFF::Node
{
private:
  uint32_t  __objectId;
  uint32_t  __parentObjectId;
  uint32_t  __uid;
  uint32_t  __gid;
  uint32_t  __mode;
  uint32_t  __atime;
  uint32_t  __mtime;
  uint32_t  __ctime;
public:
            NodeObject(DFF::fso* fsobj, uint32_t size, ObjectHeader& objectHeader, uint32_t objectId);
  uint32_t  parentObjectId();
  virtual   DFF::Attributes  _attributes();
};

class NodeObjectFile : public NodeObject//inherit NodeObject 
{
  Node*               parent;
  YAFFS*              yaffsObj;
  std::vector<Tag>    tags;
public:
  NodeObjectFile(YAFFS* fsobj, ObjectHeader& objectHeader, std::vector<Tag> tags, uint32_t objectId);
  virtual void		    fileMapping(DFF::FileMapping* fm);
};

class NodeObjectDirectory : public NodeObject
{
public:
  NodeObjectDirectory(DFF::fso* fsobj,  ObjectHeader& objectHeader, uint32_t objectId);
};

class NodeObjectHardlink : public NodeObject
{
public:
  NodeObjectHardlink(DFF::fso* fsobj,  ObjectHeader& objectHeader, uint32_t objectId);
};

#endif
