#include "exceptions.hpp"
#include "node.hpp"
#include "vfile.hpp"

#include "yaffs.hpp"

#define YAFFS_OBJECTID_ROOT		1
#define YAFFS_OBJECTID_LOSTNFOUND	2
#define YAFFS_OBJECTID_UNLINKED		3
#define YAFFS_OBJECTID_DELETED		4

/*struct yaffs_tags {
	u32 chunk_id:20;  // 8 8 + 4 
	u32 serial_number:2; // 2 
	u32 n_bytes_lsb:10;  //2 + 8

	u32 obj_id:18;//16 + 2
	u32 ecc:12;
	u32 n_bytes_msb:2;
} __attribute__((packed));

struct yaffs_spare {
	u8 tb0;           //0
	u8 tb1;           //1
	u8 tb2;           //2
	u8 tb3;           //3

	u8 page_status;		//4 /xff [> set to 0 to delete the chunk <]
	u8 block_status;  //5 /xff 

	u8 tb4;           //6
	u8 tb5;           //7

	u8 ecc1[3];       //9,8, 10
	u8 tb6;           //11
	u8 tb7;           //12
	u8 ecc2[3];       //14,13,15
} __attribute__((packed));*/

//ecc0 9,8, 10
//ecc1 14,13,15

static const unsigned char column_parity_table[] = {
	0x00, 0x55, 0x59, 0x0c, 0x65, 0x30, 0x3c, 0x69,
	0x69, 0x3c, 0x30, 0x65, 0x0c, 0x59, 0x55, 0x00,
	0x95, 0xc0, 0xcc, 0x99, 0xf0, 0xa5, 0xa9, 0xfc,
	0xfc, 0xa9, 0xa5, 0xf0, 0x99, 0xcc, 0xc0, 0x95,
	0x99, 0xcc, 0xc0, 0x95, 0xfc, 0xa9, 0xa5, 0xf0,
	0xf0, 0xa5, 0xa9, 0xfc, 0x95, 0xc0, 0xcc, 0x99,
	0x0c, 0x59, 0x55, 0x00, 0x69, 0x3c, 0x30, 0x65,
	0x65, 0x30, 0x3c, 0x69, 0x00, 0x55, 0x59, 0x0c,
	0xa5, 0xf0, 0xfc, 0xa9, 0xc0, 0x95, 0x99, 0xcc,
	0xcc, 0x99, 0x95, 0xc0, 0xa9, 0xfc, 0xf0, 0xa5,
	0x30, 0x65, 0x69, 0x3c, 0x55, 0x00, 0x0c, 0x59,
	0x59, 0x0c, 0x00, 0x55, 0x3c, 0x69, 0x65, 0x30,
	0x3c, 0x69, 0x65, 0x30, 0x59, 0x0c, 0x00, 0x55,
	0x55, 0x00, 0x0c, 0x59, 0x30, 0x65, 0x69, 0x3c,
	0xa9, 0xfc, 0xf0, 0xa5, 0xcc, 0x99, 0x95, 0xc0,
	0xc0, 0x95, 0x99, 0xcc, 0xa5, 0xf0, 0xfc, 0xa9,
	0xa9, 0xfc, 0xf0, 0xa5, 0xcc, 0x99, 0x95, 0xc0,
	0xc0, 0x95, 0x99, 0xcc, 0xa5, 0xf0, 0xfc, 0xa9,
	0x3c, 0x69, 0x65, 0x30, 0x59, 0x0c, 0x00, 0x55,
	0x55, 0x00, 0x0c, 0x59, 0x30, 0x65, 0x69, 0x3c,
	0x30, 0x65, 0x69, 0x3c, 0x55, 0x00, 0x0c, 0x59,
	0x59, 0x0c, 0x00, 0x55, 0x3c, 0x69, 0x65, 0x30,
	0xa5, 0xf0, 0xfc, 0xa9, 0xc0, 0x95, 0x99, 0xcc,
	0xcc, 0x99, 0x95, 0xc0, 0xa9, 0xfc, 0xf0, 0xa5,
	0x0c, 0x59, 0x55, 0x00, 0x69, 0x3c, 0x30, 0x65,
	0x65, 0x30, 0x3c, 0x69, 0x00, 0x55, 0x59, 0x0c,
	0x99, 0xcc, 0xc0, 0x95, 0xfc, 0xa9, 0xa5, 0xf0,
	0xf0, 0xa5, 0xa9, 0xfc, 0x95, 0xc0, 0xcc, 0x99,
	0x95, 0xc0, 0xcc, 0x99, 0xf0, 0xa5, 0xa9, 0xfc,
	0xfc, 0xa9, 0xa5, 0xf0, 0x99, 0xcc, 0xc0, 0x95,
	0x00, 0x55, 0x59, 0x0c, 0x65, 0x30, 0x3c, 0x69,
	0x69, 0x3c, 0x30, 0x65, 0x0c, 0x59, 0x55, 0x00,
};

void yaffs_ecc_calc(const unsigned char *data, unsigned char *ecc)
{
	unsigned int i;
	unsigned char col_parity = 0;
	unsigned char line_parity = 0;
	unsigned char line_parity_prime = 0;
	unsigned char t;
	unsigned char b;

	for (i = 0; i < 256; i++) {
		b = column_parity_table[*data++];
		col_parity ^= b;

		if (b & 0x01) {	/* odd number of bits in the byte */
			line_parity ^= i;
			line_parity_prime ^= ~i;
		}
	}

	ecc[2] = (~col_parity) | 0x03;

	t = 0;
	if (line_parity & 0x80)
		t |= 0x80;
	if (line_parity_prime & 0x80)
		t |= 0x40;
	if (line_parity & 0x40)
		t |= 0x20;
	if (line_parity_prime & 0x40)
		t |= 0x10;
	if (line_parity & 0x20)
		t |= 0x08;
	if (line_parity_prime & 0x20)
		t |= 0x04;
	if (line_parity & 0x10)
		t |= 0x02;
	if (line_parity_prime & 0x10)
		t |= 0x01;
	ecc[1] = ~t;

	t = 0;
	if (line_parity & 0x08)
		t |= 0x80;
	if (line_parity_prime & 0x08)
		t |= 0x40;
	if (line_parity & 0x04)
		t |= 0x20;
	if (line_parity_prime & 0x04)
		t |= 0x10;
	if (line_parity & 0x02)
		t |= 0x08;
	if (line_parity_prime & 0x02)
		t |= 0x04;
	if (line_parity & 0x01)
		t |= 0x02;
	if (line_parity_prime & 0x01)
		t |= 0x01;
	ecc[0] = ~t;

}

YAFFS::YAFFS(): mfso("yaffs"), __parent(NULL)
{
}

void    YAFFS::readTags()
{
  DFF::VFile* dump = this->__parent->open();
   
  uint64_t size = this->__parent->size();
  uint32_t number_of_blocks = this->__parent->size() / (512 + 16);

  //std::cout << "Found " << number_of_blocks << std::endl;//add to YAFFS metadata

  for (int i = 0; i < number_of_blocks; i++)
  {
    uint8_t spare[16];
    uint8_t buff0[256];
    uint8_t buff1[256];
    uint8_t calc_ecc0[3];
    uint8_t calc_ecc1[3];
    uint64_t current_offset = dump->tell();

    dump->read(buff0, 256);
    dump->read(buff1, 256);
    dump->read(spare, 16);

    //if calc_checksum optiosn
    /*yaffs_ecc_calc((const unsigned char*)&buff0, calc_ecc0);
    if (calc_ecc0[0] != spare[9] || calc_ecc0[1] != spare[8] || calc_ecc0[2] != spare[10])
    {
      std::cout << "ecc0 badchecksum\n" << std::endl;
    }

    yaffs_ecc_calc((const unsigned char*)&buff1, calc_ecc1);
    if (calc_ecc1[0] != spare[14] || calc_ecc1[1] != spare[13] || calc_ecc1[2] != spare[15])
    {
      std::cout << "ecc1 badchecksum\n" << std::endl;
    }*/

    this->__tags.addTag(spare, current_offset);
  }

  delete dump;
}


void		YAFFS::start(std::map<std::string, Variant_p > args)
{
  try
  {
    if (args.find("file") != args.end())
      this->__parent = args["file"]->value<DFF::Node* >();
    else
      throw DFF::envError("NTFS module need a file argument.");

    if (this->__parent->size() > 0)
	  {
       this->__yaffs = new DFF::Node("YAFFS", 0 , this->__parent);
       this->__root = new DFF::Node("root", 0, this->__yaffs);
       this->__deleted = new DFF::Node("deleted", 0, this->__yaffs);
       this->__unlinked = new DFF::Node("unlinked", 0, this->__yaffs);
       this->__lostnfound = new DFF::Node("lost+found", 0, this->__yaffs);
       this->__orphaned = new DFF::Node("orphaned", 0, this->__yaffs);

       this->readTags();
       this->__tags.createNodes(this, this->__root);
       this->__tags.createTree(this);
	  }
  }
  catch(...)
  {
    throw(std::string("YAFFS module: error while processing"));
  }
}

DFF::Node* YAFFS::parent(void)
{
  return (this->__parent);
}

DFF::Node* YAFFS::root(void)
{
  return (this->__root);
}

DFF::Node* YAFFS::deleted(void)
{
  return (this->__deleted);
}

DFF::Node* YAFFS::unlinked(void)
{
  return (this->__unlinked);
}

DFF::Node* YAFFS::lostnfound(void)
{
  return (this->__lostnfound);
}

DFF::Node* YAFFS::orphaned(void)
{
  return (this->__orphaned);
}

YAFFS::~YAFFS()
{
}
