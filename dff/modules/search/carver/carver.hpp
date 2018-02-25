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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */


#ifndef __CARVER_HPP__
#define __CARVER_HPP__

#include "mfso.hpp"
#include "node.hpp"
#include "eventhandler.hpp"
#include "common.hpp"

//Let the possibility to modify the matching footer or to dynamically set the window
//representing the carved file.

using namespace DFF;

class CarvedNode: public DFF::Node
{
private:
  uint64_t	__start;
  Node*		__origin;
public:
  CarvedNode(std::string name, uint64_t size, Node* parent, fso* fsobj);
  ~CarvedNode();
  void		setStart(uint64_t start);
  void		setOrigin(Node* origin);
  virtual void	fileMapping(class FileMapping* fm);
};

class Carver: public DFF::mfso, public DFF::EventHandler
{
private:
  Node			*inode;
  Node			*root;
  VFile			*ifile;
  BoyerMoore		*bm;
  std::vector<context*>	ctx;
  unsigned int		maxNeedle;
  bool			aligned;
  bool			stop;
  std::string		Results;

  bool			createFile();
  void			createNode(Node *parent, uint64_t start, uint64_t end);
  unsigned int		createWithoutFooter(Node *parent, std::vector<uint64_t> *headers, unsigned int max, bool aligned);
  unsigned int		createWithFooter(Node *parent, std::vector<uint64_t> *headers, std::vector<uint64_t> *footers, uint32_t max, bool aligned);
  int		        createTree();
  void			mapper();
  std::string		generateName(uint64_t start, uint64_t end);
  description*		createDescription(std::map<std::string, Variant_p >);
  void			createContexts(std::list<Variant_p > patterns);
  void			fillResult(context* ctx);
  std::string		needleToHexString(unsigned char* needle, int size);

public:
  enum	EventTypes
    {
      Position = 0x01,
      Matches = 0x02,
      EndOfProcessing = 0x03,
      Stop = 0x04
    };
  Carver();
  ~Carver();
  uint64_t		tell();
  virtual void          start(std::map<std::string, Variant_p > args);
  virtual void		Event(event* e);
  int			Read(char *buffer, unsigned int size);
};

#endif
