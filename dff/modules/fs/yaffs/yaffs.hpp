#ifndef __YAFFS_HPP__
#define __YAFFS_HPP__

#include <map>

#include "variant.hpp"
#include "mfso.hpp"
#include "node.hpp"

#include "tags.hpp"

class YAFFS : public DFF::mfso
{
private:
  DFF::Node*		__parent;
  DFF::Node*    __yaffs;
  DFF::Node*    __root;
  DFF::Node*    __deleted;
  DFF::Node*    __unlinked;
  DFF::Node*    __lostnfound;
  DFF::Node*    __orphaned;

  Tags          __tags;
  //Vector<Tag>;

  void          readTags();
  void          createNodes();
public:
                YAFFS();
                ~YAFFS();
  virtual void	start(std::map<std::string, Variant_p > args);
  DFF::Node*    parent();
  DFF::Node*    root();
  DFF::Node*    deleted();
  DFF::Node*    unlinked();
  DFF::Node*    lostnfound();
  DFF::Node*    orphaned();
};

#endif
