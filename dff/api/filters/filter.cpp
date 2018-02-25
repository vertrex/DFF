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

#include "filter.hpp"
#include "scanner.hpp"
#include "fso.hpp"
#include "node.hpp"
#include "vfs.hpp"

namespace DFF
{

Filter::Filter(std::string fname) 
{
  this->__stop = false;
  this->__fname = fname;
  this->__query = "";
  this->__uid = 0;
  if ((this->__ctx = (filter_ctx*)malloc(sizeof(filter_ctx))) == NULL)
    throw (std::string("Filter: cannot allocate memory for context"));
  this->__ctx->ic = new InterpreterContext();
  this->__ctx->root = NULL;
  this->__ctx->buf = NULL;
  this->__ctx->column = 0;
  this->__ev = new event;
}

Filter::~Filter()
{
  if (this->__ctx != NULL)
    {
      if (this->__ctx->ic != NULL)
	delete this->__ctx->ic;
      if (this->__ctx->root != NULL)
	{
	  //this->deconnection(this->__ctx->root);
	  delete this->__ctx->root;
	}
      if (this->__ctx->buf != NULL)
	delete this->__ctx->buf;
      free(this->__ctx);
    }
  if (this->__ev != NULL)
    delete this->__ev;
}

void			Filter::__reset()
{
  this->__stop = false;
  this->__matchednodes.clear();
  if (this->__ctx->root != NULL && this->__ev != NULL)
    {
      this->__ev->type = Filter::AstReset;
      this->__ev->value = NULL;
      this->__ctx->root->Event(this->__ev);
    }
}


void		Filter::__initCtx() 
{
  this->__matchednodes.clear();
  if (this->__ctx == NULL)
    throw std::string("Filter: context has not been allocated yet");
  this->__ctx->ic->clear();
  if (this->__ctx->buf == NULL)
    this->__ctx->buf = new std::string;
  else
    this->__ctx->buf->clear();
  if (this->__ctx->root != NULL)
    {      
      this->deconnection(this->__ctx->root);
      delete this->__ctx->root;
      this->__ctx->root = NULL;
    }
  this->__ctx->column = 0;
}

std::string	Filter::__formatErrorMsg()
{
  std::string	err;

  return err;
}



// Future implementation will provide a filter manager with precompiled
// queries.
// Currently, fname is automatically associated but in future, method will
// ask if it can register the provided name. If name already registered,
// the method will throw an exception to warn the user.
void			Filter::setFilterName(std::string fname) 
{
  this->__fname = fname;
}

std::string		Filter::filterName()
{
  return this->__fname;
}

std::string		Filter::query()
{
  return this->__query;
}

void			Filter::compile(std::string query) 
{
  std::string	err;
  int		status;

  this->__initCtx();
  this->__query = query;
  status = parse_filter_string(query.c_str(), this->__ctx);
  if (status == -1)
    {
      if (this->__ctx->root != NULL)
	{
	  delete this->__ctx->root;
	  this->__ctx->root = NULL;
	}
      err = this->__formatErrorMsg();
      throw (std::string(err));
    }
  this->__ctx->root->compile(this->__ctx->ic);
  this->connection(this->__ctx->root);
}

void			Filter::processFolder(Node* nodeptr) 
{
  uint64_t		nodescount;
  std::vector<Node*>	children;
  size_t		i = 0;

  this->__reset();
  if (this->__ctx->root != NULL)
    {
      if (nodeptr != NULL)
	{
	  if (nodeptr->hasChildren())
	    {
	      nodescount = nodeptr->childCount();
	      this->__notifyNodesToProcess(nodescount);
	      children = nodeptr->children();
	      i = 0;
	      while ((i != children.size()) && (!this->__stop) )
		{
		  if (this->__eval(children[i]))
		    this->__notifyMatch(children[i]);
		  i++;
		  this->__notifyProgress(i);
		}
	    }
	}
      else
	throw std::string("provided node does not exist");
    }
  else
    throw std::string("no query compiled yet");
  this->__notifyEndOfProcessing(i);
}

void			Filter::process(Node* nodeptr, bool recursive)
{
  uint64_t		nodescount;
  uint64_t		processed;

  this->__reset();
  processed = 0;
  if (this->__ctx->root != NULL)
    {
      if (nodeptr != NULL)
	{
	  if (nodeptr->hasChildren() && recursive)
	    {
	      nodescount = nodeptr->totalChildrenCount();
	      this->__notifyNodesToProcess(nodescount);
	      this->__process(nodeptr, &processed);
	    }
	  else
	    {
	      this->__notifyNodesToProcess(1);
	      try 
	      {
	        if (this->__eval(nodeptr))
		  this->__notifyMatch(nodeptr);
	      }
	      catch (...)
	      {
		std::cout << "Filter::process catch an error " << std::endl;
	      }
	      this->__notifyProgress(1);
	    }
	}
      else
	throw std::string("provided node does not exist");
    }
  else
    throw std::string("no query compiled yet");
  this->__notifyEndOfProcessing(processed);
}

void				Filter::process(std::list<Node*> nodes) 
{
  uint64_t			processed;
  std::list<Node*>::iterator	it;

  this->__reset();
  processed = 0;
  if (this->__ctx->root != NULL)
    {
      if (nodes.size() > 0)
	{
	  this->__notifyNodesToProcess(nodes.size());
	  it = nodes.begin();
	  while (it != nodes.end() && !this->__stop)
	    {
	      if (this->__eval(*it))
		this->__notifyMatch(*it);
	      this->__notifyProgress(processed++);
	      it++;
	    }
	}
      this->__notifyEndOfProcessing(processed);
    }
  else
    throw std::string("no query compiled yet");
}


void				Filter::process(std::vector<Node*> nodes) 
{
  uint64_t			processed;
  std::vector<Node*>::iterator	it;

  this->__reset();
  processed = 0;
  if (this->__ctx->root != NULL)
    {
      if (nodes.size() > 0)
	{
	  this->__notifyNodesToProcess(nodes.size());
	  it = nodes.begin();
	  while (it != nodes.end() && !this->__stop)
	    {
	      if (this->__eval(*it))
		this->__notifyMatch(*it);
	      this->__notifyProgress(processed++);
	      it++;
	    }
	}
      this->__notifyEndOfProcessing(processed);
    }
  else
    throw std::string("no query compiled yet");
}


void			Filter::process(uint64_t nodeid, bool recursive) 
{
  Node*			node;

  if ((node = VFS::Get().getNodeById(nodeid)) != NULL)
    this->process(node, recursive);
}

void			Filter::process(fso* fsobj) 
{
  if (fsobj != NULL)
    this->process(fsobj->nodes());
}

std::vector<Node*>	Filter::matchedNodes()
{
  return this->__matchednodes;
}


void			Filter::Event(event* e)
{
  if (e != NULL && e->type == Filter::StopProcessing)
    {
      this->__stop = true;
      if (this->__ctx->root != NULL)
	this->__ctx->root->Event(e);
    }
}


void			Filter::__notifyNodesToProcess(uint64_t nodescount)
{
  if (this->__ev != NULL)
    {
      this->__ev->type = Filter::TotalNodesToProcess;
      this->__ev->value = Variant_p(new Variant(nodescount));
      this->notify(this->__ev);
    }
}

void			Filter::__notifyMatch(Node* nodeptr)
{
  this->__matchednodes.push_back(nodeptr);
  if (this->__ev != NULL)
    {
      this->__ev->type = Filter::NodeMatched;
      this->__ev->value = Variant_p(new Variant(nodeptr));
      this->notify(this->__ev);
    }
}

void			Filter::__notifyProgress(uint64_t processed)
{
  if (this->__ev != NULL)
    {
      this->__ev->value = Variant_p(new Variant(processed));
      this->__ev->type = Filter::ProcessedNodes;
      this->notify(this->__ev);
    }
}

void			Filter::__notifyEndOfProcessing(uint64_t processed)
{
  if (this->__ev != NULL)
    {
      this->__ev->type = Filter::EndOfProcessing;
      this->__ev->value = Variant_p(new Variant(processed));
      this->notify(this->__ev);
    }
}


bool			Filter::match(Node* nodeptr)
{
  bool			_match;
  
  if (nodeptr == NULL)
    return false;
  if (this->__ctx->root == NULL)
    return false;
  try 
    {
      _match = this->__eval(nodeptr);
    }
  catch (...)
    {
      _match = false;
    }
  return _match;
}


bool			Filter::match(uint64_t nodeId)
{
  bool			_match;
  Node*			node;

  if ((node = VFS::Get().getNodeById(nodeId)) == NULL)
    return false;
  if (this->__ctx->root == NULL)
    return false;
  try 
    {
      _match = this->__eval(node);
    }
  catch (...)
    {
      _match = false;
    }
  return _match;
}
 
  
void			Filter::__process(Node* nodeptr, uint64_t* processed)
{
  std::vector<Node*>	children;
  uint32_t		i;

  if (nodeptr != NULL && !this->__stop)
    {
      (*processed)++;
      this->__notifyProgress(*processed);
      if (this->__eval(nodeptr))
	this->__notifyMatch(nodeptr);
      if (nodeptr->hasChildren())
	{
	  children = nodeptr->children();
	  i = 0;
	  while ((i != children.size()) && (!this->__stop))
	    {
	      this->__process(children[i], processed);
	      i++;
	    }
	}
    }
  return;
}

bool			Filter::__eval(Node* node)
{
  Variant*		vptr;
  bool			ret;

  ret = false;
  vptr = NULL;
  this->__ctx->ic->setCurrentNode(node);
  try {
    if (((vptr = this->__ctx->root->evaluate()) != NULL) && (vptr->type() == typeId::Bool))
      ret = vptr->value<bool>();
  }
  catch (...)
  {
	std::cout << "Filter::__eval catch an error" << std::endl; 
  }
  if (vptr != NULL)
    delete vptr;
  return ret;
}

}
