/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
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

#ifndef __PFF_HH__
#define __PFF_HH__

#include "pff_common.hpp"
#include "pff_node.hpp"
#include "pff_macro.hpp"
#include "pff_item_info.hpp"
#include "libbfio_wrapper.hpp"

using namespace DFF;

class pff : public DFF::mfso
{
private:
  Node*			parent;
  libpff_file_t*	__pff_file;
  int			export_attachments(ItemInfo* item, Node* parent);
  int			export_task(ItemInfo* item, Node* parent);	
  int			export_note(ItemInfo* item, Node* parent);	
  int 		        export_email(ItemInfo* item, Node* parent);
  int 		        export_contact(ItemInfo* item, Node* parent);
  int 		        export_meeting(ItemInfo* item, Node* parent);
  int			export_appointment(ItemInfo* item, Node* parent);
  int			export_message_default(ItemInfo* item, Node* parent, std::string item_type_name);
  int 		        export_folder(ItemInfo* item, Node* parent);
  int		        export_sub_messages(ItemInfo* folder, PffNodeFolder* message);
  int		        export_sub_folders(ItemInfo* folder, PffNodeFolder* nodeFolder);
public:
                         pff();
                        ~pff();
  void		        initialize(Node* parent);
  void		        info();
  void		        info_file();
  void		        info_message_store();
  void		        create_item();
  void			create_recovered();
  void			create_orphan();
  void			create_unallocated();
  void		        export_sub_items(libpff_item_t* item, Node* parent);
  int 		        export_item(ItemInfo* item, Node* parent);
  int32_t       	vopen(Node*);
  int32_t 	        vread(int fd, void *buff, unsigned int size);
  int32_t 	        vclose(int fd);
  int32_t       	vwrite(int fd, void *buff, unsigned int size);
  uint32_t      	status(void);
  uint64_t      	vseek(int fd, uint64_t offset, int whence);
  uint64_t      	vtell(int32_t fd);
  virtual void  	start(std::map<std::string, Variant_p >);
  libpff_file_t*        pff_file(void);
};

#endif
