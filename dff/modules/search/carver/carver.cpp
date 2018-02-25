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

#include "carver.hpp"

#include <iostream>
#include <iomanip>
#include <sstream>

#include "exceptions.hpp"
#include "filemapping.hpp"
#include "vfile.hpp"
// Next gen: process like scalpel
//   for each BUFFER
//     for each (header => footer)
//       find()
// implies to preprocess each shift table
// Test if faster or not

CarvedNode::CarvedNode(std::string name, uint64_t size, Node* parent, fso* fsobj): Node(name, size, parent, fsobj), __start(0), __origin(NULL)
{
}

CarvedNode::~CarvedNode()
{
}

void	CarvedNode::setStart(uint64_t start)
{
  this->__start = start;
}

void	CarvedNode::setOrigin(Node* origin)
{
  this->__origin = origin;
}

void	CarvedNode::fileMapping(class FileMapping* fm)
{
  fm->push(0, this->size(), this->__origin, this->__start);
}

Carver::Carver(): mfso("carver"), inode(NULL), root(NULL), ifile(NULL), bm(NULL), ctx(std::vector<context*>()), maxNeedle(0), aligned(true), stop(false), Results(std::string())
{
  //res = new results("empty");
}

Carver::~Carver()
{
  //  delete this->header;
  //delete this->footer;
}

uint64_t	Carver::tell()
{
  return this->ifile->tell();
}

void		Carver::Event(event* e)
{
  if (e != NULL && e->type == Carver::Stop)
    this->stop = true;
}

void		Carver::start(std::map<std::string, Variant_p > args)
{
  event*	e1;

  this->inode = args["file"]->value<Node*>();
  this->ifile = this->inode->open();
  this->createContexts(args["patterns"]->value< std::list<Variant_p > >());
  this->root = new Node("carved", 0, NULL, this);
  this->root->setDir();
  this->ifile->seek(args["start-offset"]->value<uint64_t>(), 0);
  this->mapper();
  e1 = new event;
  e1->type = Carver::EndOfProcessing;
  e1->value = new Variant(0);
  this->notify(e1);
  //delete e1;
}

int		Carver::Read(char *buffer, unsigned int size)
{
  try
    {
      return (this->ifile->read(buffer, size));
    }
  catch (vfsError e)
    {
      return -1;
    }
}


std::string	Carver::needleToHexString(unsigned char* needle, int size)
{
  int			i;
  std::stringstream	ss;

  for (i = 0; i != size; i++)
    {
      ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<unsigned int>(needle[i]);
      ss << " ";
    }
  return ss.str();
}

description*	Carver::createDescription(std::map<std::string, Variant_p > ctx)
{
  description*	descr;
  std::map<std::string, Variant_p >	cpattern;

  descr = new description;

  descr->type = ctx["filetype"]->toCArray();
  cpattern = ctx["header"]->value<std::map<std::string, Variant_p > >();
  descr->header = new pattern;
  descr->header->needle = (unsigned char*)(cpattern["needle"]->toCArray());
  descr->header->size = cpattern["size"]->value<uint32_t>();
  descr->header->wildcard = '\0';//cpattern["wildcard"]->value<char>();

  cpattern = ctx["footer"]->value<std::map<std::string, Variant_p > >();
  descr->footer = new pattern;
  descr->footer->needle = (unsigned char*)(cpattern["needle"]->toCArray());
  descr->footer->size = cpattern["size"]->value<uint32_t>();
  descr->footer->wildcard = '\0';//cpattern["wildcard"]->value<char>();
  descr->window = ctx["window"]->value<uint32_t>();
  descr->aligned = ctx["aligned"]->value<bool>();
  
  return descr;
}


void		Carver::createContexts(std::list<Variant_p > patterns)
{
  std::list<Variant_p >::iterator		it;
  std::map<std::string, Variant_p >	vpattern;
  context				*cctx;
  unsigned int					i;
  description*				descr;
  unsigned int				ctxsize;
  
  ctxsize = this->ctx.size();
  if (ctxsize)
    for (i = 0; i != ctxsize; i++)
      {
  	free(this->ctx[i]->headerBcs);
  	free(this->ctx[i]->footerBcs);
	this->ctx[i]->headers.clear();
	this->ctx[i]->footers.clear();
	delete this->ctx[i]->descr;
	delete this->ctx[i];
      }
  this->ctx.clear();
  if (patterns.size() > 0)
    {
      this->stop = false;
      this->maxNeedle = 0;
      for (it = patterns.begin(); it != patterns.end(); it++)
	{
	  cctx = new context;
	  descr = this->createDescription((*it)->value< std::map<std::string, Variant_p > >());
	  cctx->descr = descr;
	  cctx->headerBcs = this->bm->generateBcs(descr->header);
	  cctx->footerBcs = this->bm->generateBcs(descr->footer);
	  if (this->maxNeedle < descr->header->size)
	    this->maxNeedle = descr->header->size;
	  if (this->maxNeedle < descr->footer->size)
	    this->maxNeedle = descr->footer->size;
	  this->ctx.push_back(cctx);
	}
    }
}

void		Carver::mapper()
{
  unsigned int	i;
  char		*buffer;
  int		bytes_read;
  int		offset;
  event*	e;
  event*	e1;
  uint64_t	total_headers;
  uint64_t	offpos;
  std::stringstream	percent;
  unsigned int		ctxsize;

  e = new event;
  e1 = new event;
  if ((buffer = (char*)malloc(sizeof(char) * BUFFSIZE)) == NULL)
    return;
  int seek;
  e->type = Carver::Position;
  e1->type = Carver::Matches;
  total_headers = 0;
  ctxsize = this->ctx.size();
  while (((bytes_read = this->Read(buffer, BUFFSIZE)) > 0) && (!this->stop))
    {
      offpos = this->tell();
      percent.str("");
      percent << ((offpos * 100) / this->inode->size()) << " %";
      this->stateinfo = percent.str();
      
      for (i = 0; i != ctxsize; i++)
	{
	  offset = this->bm->search((unsigned char*)buffer, bytes_read, this->ctx[i]->descr->header, this->ctx[i]->headerBcs);
	  seek = offset;
	  while (offset != -1)
	    {
	      if (this->ctx[i]->descr->aligned)
		{
		  if (((this->tell() - bytes_read + seek) % 512) == 0)
		    total_headers += 1;
		}
	      else
		total_headers += 1;
	      this->ctx[i]->headers.push_back(this->tell() - bytes_read + seek);
	      seek += ctx[i]->descr->header->size;
	      if (seek + ctx[i]->descr->header->size >= (uint64_t)bytes_read)
		break;
	      else
		{
		  offset = this->bm->search((unsigned char*)(buffer+seek), bytes_read - seek, this->ctx[i]->descr->header, this->ctx[i]->headerBcs);
		  seek += offset;
		}
	    }
	  if (this->ctx[i]->descr->footer->size != 0)
	    {
	      offset = this->bm->search((unsigned char*)buffer, bytes_read, this->ctx[i]->descr->footer, this->ctx[i]->footerBcs);
	      seek = offset;
	      while (offset != -1)
		{
		  this->ctx[i]->footers.push_back(this->tell() - bytes_read + seek + this->ctx[i]->descr->footer->size);
		  seek += ctx[i]->descr->footer->size;
		  if (seek + ctx[i]->descr->footer->size >= (uint64_t)bytes_read)
		    break;
		  else
		    {
		      offset = this->bm->search((unsigned char*)(buffer+seek), bytes_read - seek, this->ctx[i]->descr->footer, this->ctx[i]->footerBcs);
		      seek += offset;
		    }
		}
	    }
          e1->value = new Variant(total_headers);
          this->notify(e1);
	}
      e->value = new Variant(this->tell());
      this->notify(e);
      if (bytes_read == BUFFSIZE)
	this->ifile->seek(this->tell() - this->maxNeedle, 0);
    }
  free(buffer);
  ///delete e;
  //delete e1;
  this->createTree();
}

std::string	Carver::generateName(uint64_t start, uint64_t end)
{
  std::ostringstream os;

  os << start << "-" << end;
  return os.str();
}

void		Carver::createNode(Node *parent, uint64_t start, uint64_t end)
{
  CarvedNode*	cn;
  std::stringstream	name;

  name << "0x" << std::setw(2) << std::setfill('0') << std::hex << start;
  name << "-";
  name << "0x" << std::setw(2) << std::setfill('0') << std::hex << end;

  cn = new CarvedNode(name.str(), end-start, parent, this);
  cn->setFile();
  cn->setStart(start);
  cn->setOrigin(this->inode);
}

unsigned int		Carver::createWithoutFooter(Node *parent, std::vector<uint64_t> *headers, unsigned int max, bool aligned)
{
  unsigned int	i;
  unsigned int	hlen;
  unsigned int	total;

  hlen = headers->size();
  total = 0;
  for (i = 0; i != hlen; i++)
    {
      if (aligned)
	{
	  if (((*headers)[i] % 512) == 0)
	    this->createNode(parent, (*headers)[i], (*headers)[i] + (uint64_t)max);
	  total += 1;
	}
      else
	{
	  this->createNode(parent, (*headers)[i], (*headers)[i] + (uint64_t)max);
	  total += 1;
	}
    }
  return total;
}

unsigned int		Carver::createWithFooter(Node *parent, std::vector<uint64_t> *headers, std::vector<uint64_t> *footers, unsigned int max, bool aligned)
{
  unsigned int	i;
  unsigned int	j;
  unsigned int	flen;
  unsigned int	hlen;
  bool		found;
  unsigned int	total;

  hlen = headers->size();
  flen = footers->size();
  j = 0;
  total = 0;
  for (i = 0; i != hlen; i++)
    {
      found = false;
      while ((j != flen) && (!found))
	{
	  if ((*footers)[j] > (*headers)[i])
	    found = true;
	  else
	    j++;
	}
      if (aligned)
	{
	  if (((*headers)[i] % 512) == 0)
	    {
	      if (found && ((*footers)[j] > (*headers)[i]))
		this->createNode(parent, (*headers)[i], (*footers)[j]);
	      else
		this->createNode(parent, (*headers)[i], (*headers)[i] + (uint64_t)max);
	      total += 1;
	    }
	}
      else
	{
	  if (found && ((*footers)[j] > (*headers)[i]))
	    this->createNode(parent, (*headers)[i], (*footers)[j]);
	  else
	    this->createNode(parent, (*headers)[i], (*headers)[i] + (uint64_t)max);
	  total += 1;
	}
    }
  return total;
}


void		Carver::fillResult(context* ctx)
{
  std::stringstream	totalheaders;
  std::stringstream	totalfooters;
  std::map<std::string, Variant_p >::iterator	mit;
  std::list<Variant_p >				vlistptr;
  
  totalheaders.str("");
  totalheaders << "Header " << ctx->headers.size() << " (pattern " << this->needleToHexString(ctx->descr->header->needle, ctx->descr->header->size) << ") ";
  if ((mit = this->res.find(std::string(ctx->descr->type))) != this->res.end())
    {
      mit->second->convert(typeId::List, &vlistptr);
      totalheaders << ctx->headers.size() << " header(s) found";
    }
  else
    {
      std::list<Variant_p >	vlist;
      vlist.push_back(Variant_p(new Variant(totalheaders.str())));
      this->res[std::string(ctx->descr->type)] = Variant_p(new Variant(vlist));
      this->res[std::string(ctx->descr->type)]->convert(typeId::List, &vlistptr);
      vlistptr.push_back(Variant_p(new Variant(totalheaders.str())));
      this->res[std::string(ctx->descr->type)] = Variant_p(new Variant(vlistptr));
    }
  std::cout << vlistptr.size() << std::endl;
}


int		Carver::createTree()
{
  context	*ctx;
  Node		*parent;
  unsigned int	max;
  unsigned int	clen;
  unsigned int	i;

  clen = this->ctx.size();
  if (clen > 0)
    this->registerTree(this->inode, this->root);
  for (i = 0; i != clen; i++)
    {
      ctx = this->ctx[i];
      if (ctx->headers.size() > 0)
	{
	  parent = new Node(ctx->descr->type, 0, NULL, this);
	  parent->setDir();
	  if (ctx->descr->window > 0)
	    max = ctx->descr->window;
	  else
	    max = BUFFSIZE;
	  if (ctx->footers.size() > 0)
	    this->createWithFooter(parent, &(ctx->headers), &(ctx->footers), max, ctx->descr->aligned);
	  else
	    this->createWithoutFooter(parent, &(ctx->headers), max, ctx->descr->aligned);
	  //this->fillResult(ctx);
	  this->registerTree(this->root, parent);
	}
    }
  return 0;
}
