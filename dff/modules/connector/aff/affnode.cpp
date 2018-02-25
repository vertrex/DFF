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
 *  Solal Jacob <sja@digital-forensic.org>
 */
#include "fcntl.h"
#include "stdlib.h"

#include "affnode.hpp"

int             AffNode::addSegmentAttribute(DFF::Attributes* vmap, AFFILE* af, const char* segname)
{
#ifdef NEW_AFF_LIB
    uint32_t arg;
#else
    unsigned long arg;
#endif
    unsigned char *data = 0;
    if (segname[0] == 0)
	return (0); 

    size_t data_len = 0;

    if(af_get_seg(af, segname, &arg, 0, &data_len))
    {
	return (0);
    }
    data = (unsigned char *)malloc(data_len);
    if(af_get_seg(af, segname, 0, data, &data_len))
    {
	free(data);
	return (0);
    }
   
    if(strcmp(segname, AF_ACQUISITION_SECONDS) == 0)
    {
        //XXX FIXME TIME_FIX
        //int hours = arg / 3600;
        //int minutes = (arg / 60) % 60;
        //int seconds = arg % 60;

        //DateTime*	time = new DateTime;
        //time->hour = hours;
        //time->minute = minutes;
        //time->second = seconds;
        //(*vmap)[std::string(segname)] = Variant_p(new Variant(time));
	free(data);
	return (1);
    }

    if(((arg == AF_SEG_QUADWORD) && (data_len==8)) || af_display_as_quad(segname))
    {
	switch(data_len)
        {
	 case 8:
	   (*vmap)[segname] = Variant_p(new DFF::Variant(af_decode_q(data)));
	    break;
	case 0:
	  (*vmap)[segname] = Variant_p(new DFF::Variant(0));
	    break;
	default:
	  (*vmap)[segname] = Variant_p(new DFF::Variant(std::string("Cannot decode segment")));
	}
	free(data);
	return (1);
    }
    if (data_len == 0 && arg != 0)
    {
      (*vmap)[std::string(segname)] = Variant_p(new DFF::Variant((uint64_t)arg));
       free(data);
       return (1);
    }

    if(af_display_as_hex(segname) || (data_len == 16 && strstr(segname, "md5")) || (data_len == 20 && strstr(segname, "sha1")))
    {
        char buf[80];

	af_hexbuf(buf, sizeof(buf), data, data_len, AF_HEXBUF_NO_SPACES); 
	(*vmap)[std::string(segname)] = Variant_p(new DFF::Variant(std::string(buf)));
    	free(data);
    	return (1);
    }
    else 
    {
      (*vmap)[segname] = Variant_p(new DFF::Variant(std::string((char *)data)));
        free(data);
        return (1);
    }
}


DFF::Attributes	AffNode::_attributes()
{
  DFF::Attributes 	vmap;
  struct af_vnode_info vni;
  unsigned long total_segs = 0;
  unsigned long total_pages = 0;
  unsigned long total_hashes = 0;
  unsigned long total_signatures =0;
  unsigned long total_nulls = 0;

  vmap["orignal path"] =  Variant_p(new DFF::Variant(this->originalPath));
  AFFILE*  affile = af_open(this->originalPath.c_str(), O_RDONLY, 0);
  if (affile)
  {
    vmap["dump type"] = Variant_p(new DFF::Variant(std::string(af_identify_file_name(this->originalPath.c_str(), 1))));
    if (af_vstat(affile, &vni) == 0)
    {
	if (vni.segment_count_encrypted > 0 || vni.segment_count_signed > 0)
        {
	  vmap["encrypted segments"] = Variant_p(new DFF::Variant(vni.segment_count_encrypted));
	  vmap["signed segments"] = Variant_p(new DFF::Variant(vni.segment_count_signed));
	}
      std::vector<std::string> segments;
      char segname[AF_MAX_NAME_LEN];
      af_rewind_seg(affile);
      int64_t total_datalen = 0;
      size_t total_segname_len = 0;
      size_t datalen = 0;
      int aes_segs=0;
      while(af_get_next_seg(affile, segname, sizeof(segname), 0, 0, &datalen)==0)
      {
	total_segs++;
	total_datalen += datalen;
	total_segname_len += strlen(segname);
	if(segname[0]==0) 
	  total_nulls++;

	char hash[64];
	int64_t page_num = af_segname_page_number(segname);
	int64_t hash_num = af_segname_hash_page_number(segname,hash,sizeof(hash));
	if(page_num>=0) 
		total_pages++;
	if(hash_num>=0) 
		total_hashes++;
	if(strstr(segname,AF_SIG256_SUFFIX)) 
		total_signatures++;
	if(strstr(segname,AF_AES256_SUFFIX)) 
		aes_segs++;
	if((page_num>=0||hash_num>=0)) 
		continue;
	if(af_is_encrypted_segment(segname)) 
		continue; 
	this->addSegmentAttribute(&vmap, affile, segname); 
      }
      vmap["Total segments"] = Variant_p(new DFF::Variant((uint64_t)total_segs));
      vmap["Total segments real"] = Variant_p(new DFF::Variant((uint64_t)(total_segs - total_nulls)));
      if (aes_segs)
	vmap["Encrypted segments"] = Variant_p(new DFF::Variant(aes_segs));
      vmap["Page segments"] = Variant_p(new DFF::Variant((uint64_t)total_pages));
      vmap["Hash segments"] = Variant_p(new DFF::Variant((uint64_t)total_hashes));
      vmap["Signature segments"] = Variant_p(new DFF::Variant((uint64_t)total_signatures)); 	 
      vmap["Null segments"] = Variant_p(new DFF::Variant((uint64_t)total_nulls));
      vmap["Total data bytes"] = Variant_p(new DFF::Variant((uint64_t)total_datalen));
    } 

  } 

  af_close(affile);

  return vmap;
}


AffNode::AffNode(std::string Name, uint64_t size, DFF::Node* parent, aff* fsobj, std::string origPath, AFFILE* _affile): DFF::Node(Name, size, parent, fsobj)
{
  this->originalPath = origPath;
  this->affile = _affile;
}

AffNode::~AffNode()
{
}

