#include <string>

#include "yaffs.hpp"
#include "object_node.hpp"

#include "node.hpp"
#include "typesconv.hpp"
#include "filemapping.hpp"

#include "datetime.hpp"
#include "exceptions.hpp"


/*
 * NodeObject
 */
NodeObject::NodeObject(DFF::fso* fsobj, uint32_t size, ObjectHeader& objectHeader, uint32_t objectId) : DFF::Node(std::string((char*)objectHeader.name), size, NULL, fsobj)
{
  this->__objectId = objectId;
  this->__parentObjectId = bytes_swap32(objectHeader.parent_obj_id);

  this->__uid = bytes_swap32(objectHeader.yst_uid);
  this->__gid = bytes_swap32(objectHeader.yst_gid);

  this->__mode = bytes_swap32(objectHeader.yst_mode);

  this->__atime = bytes_swap32(objectHeader.yst_atime);
  this->__mtime = bytes_swap32(objectHeader.yst_mtime);
  this->__ctime = bytes_swap32(objectHeader.yst_ctime);
}

uint32_t NodeObject::parentObjectId(void)
{
  return (this->__parentObjectId);
}

DFF::Attributes	     NodeObject::_attributes()
{
  DFF::Attributes    attr;

  attr["object id"] = Variant_p(new DFF::Variant(this->__objectId));
  attr["parent id"] = Variant_p(new DFF::Variant(this->__parentObjectId)); 
  attr["uid"] =  Variant_p(new DFF::Variant(this->__uid));
  attr["gid"] =  Variant_p(new DFF::Variant(this->__gid));
  attr["modified"] = Variant_p(new DFF::Variant(new DFF::DateTime(this->__mtime)));
  attr["accessed"] = Variant_p(new DFF::Variant(new DFF::DateTime(this->__atime)));
  attr["changed"] = Variant_p(new DFF::Variant(new DFF::DateTime(this->__ctime)));

  return (attr);
}                  

/*
 * NodeObjectFile
 */
NodeObjectFile::NodeObjectFile(YAFFS* fsobj, ObjectHeader& objectHeader, std::vector<Tag> tags, uint32_t objectId) : yaffsObj(fsobj), tags(tags), NodeObject(fsobj, bytes_swap32(objectHeader.file_size_low), objectHeader, objectId)
{
}

void  NodeObjectFile::fileMapping(DFF::FileMapping* fm)
{
  std::map<uint32_t, Tag> chunks; 

  std::vector<Tag>::iterator tag = this->tags.begin();
  for (; tag != tags.end(); tag++)
  {
    Tag newTag(*tag);
    if (tag->page_status == 0xff) //if not wecould have old version of the tag as we put in the map only the old version

      chunks.insert(std::pair<uint32_t, Tag>(tag->chunk_id,newTag));
  }

  uint32_t number_of_block = (this->size() / 512) + 1;
  for (uint32_t i = 1; i <= number_of_block ; ++i)
  {
    std::map<uint32_t, Tag>::iterator it = chunks.find(i);
    Tag tag = it->second;
    if (it != chunks.end())
    {
      fm->push((i-1) * 512, tag.size, this->yaffsObj->parent(), tag.offset);
    }
    else
    {
      std::cout << "error i " << i << " tag.size " << tag.size  << " offset " << tag.offset << std::endl;
      //printf("error on tag");
    }
  }
}

/*
 *  NodeObjectDirectory
 */
NodeObjectDirectory::NodeObjectDirectory(DFF::fso* fsobj, ObjectHeader& objectHeader, uint32_t objectId) : NodeObject(fsobj, 0, objectHeader, objectId) 
{
}

/*
 *  NodeObjectHardlink
 */
NodeObjectHardlink::NodeObjectHardlink(DFF::fso* fsobj, ObjectHeader& objectHeader, uint32_t objectId) : NodeObject(fsobj, 0, objectHeader, objectId) 
{
  std::cout << "equiv id " << bytes_swap32(objectHeader.equiv_id) << std::endl;
}
