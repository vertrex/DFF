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
 *  Frederic B. <fba@digital-forensic.org>
 */

#include <sstream>

#include "datetime.hpp"
#include "vfile.hpp"
#include "fso.hpp"
#include "tags.hpp"
#include "astnodes.hpp"
#include "parser.hpp"
#include "exceptions.hpp"

using namespace DFF;

static int __namedcreator__ = AttributeFactory::instance()->registerCreator(AttributeFactory::Named, NamedAttribute::create);
static int __timestampcreator__ = AttributeFactory::instance()->registerCreator(AttributeFactory::Timestamp, TimestampAttribute::create);

KEYWORD(time, time, AttributeFactory::Timestamp, QueryFlags::Advanced)
KEYWORD(year, year, AttributeFactory::Timestamp, QueryFlags::Advanced)
KEYWORD(type, type, AttributeFactory::Named, QueryFlags::DataType)
KEYWORD(size, filesize, AttributeFactory::Named, QueryFlags::Primitive)
KEYWORD(deleted, deleted, AttributeFactory::Named, QueryFlags::Primitive)
KEYWORD(folder, folder, AttributeFactory::Named, QueryFlags::Primitive)
KEYWORD(file, file, AttributeFactory::Named, QueryFlags::Primitive)
KEYWORD(extension, extension, AttributeFactory::Named, QueryFlags::Primitive)
KEYWORD(name, filename, AttributeFactory::Named, QueryFlags::Primitive)
KEYWORD(path, path, AttributeFactory::Named, QueryFlags::Primitive)
KEYWORD(tags, tags, AttributeFactory::Named, QueryFlags::Tags)
KEYWORD(tagged, tagged, AttributeFactory::Named, QueryFlags::Tags)
KEYWORD(to, pff.Transport headers.To, AttributeFactory::Named, QueryFlags::Advanced)
KEYWORD(from, pff.Transport headers.From, AttributeFactory::Named, QueryFlags::Advanced)
KEYWORD(module, module, AttributeFactory::Named, QueryFlags::Advanced)

InterpreterContext::InterpreterContext()
{
  this->__cnode = NULL;
  this->__data = NULL;
  this->__qflags = QueryFlags::Empty;
}

InterpreterContext::~InterpreterContext()
{
  Attributes::iterator			it;

  if (this->__data != NULL)
    {
      this->__data->close();
      delete this->__data;
    }
  if (!this->__attributes.empty())
    this->__attributes.clear();
}

void	InterpreterContext::clear()
{
  if (this->__data != NULL)
    {
      this->__data->close();
      delete this->__data;
      this->__data = NULL;
    }
  if (!this->__attributes.empty())
    this->__attributes.clear();
  this->__cnode = NULL;
  this->__qflags = QueryFlags::Empty;
}

void		InterpreterContext::setQueryFlags(QueryFlags::Level qflags)
{
  this->__qflags |= qflags;
}

void		InterpreterContext::setCurrentNode(DFF::Node* node)
{
  Attributes::iterator			it;
  Variant*				vptr;
  Attributes				attr;
  fso*					fsobj;

  if (!this->__attributes.empty())
    this->__attributes.clear();
  if (this->__data != NULL)
    {
      this->__data->close();
      delete this->__data;
      this->__data = NULL;
    }
  if (node != NULL)
    {
      this->__cnode = node;
      if ((this->__qflags & QueryFlags::Primitive) == QueryFlags::Primitive)
	{
	  this->__attributes["path"] = new Variant(node->path());
	  this->__attributes["filename"] = new Variant(node->name());
	  this->__attributes["extension"] = new Variant(node->extension());
	  this->__attributes["filesize"] = new Variant(node->size());
	  this->__attributes["deleted"] = new Variant(node->isDeleted());
	  this->__attributes["folder"] = new Variant(node->isDir());
	  this->__attributes["file"] = new Variant(node->isFile());
	}
      if ((this->__qflags & QueryFlags::DataType) == QueryFlags::DataType)
	this->__attributes["type"] = new Variant(this->__cnode->dataType());
      if ((this->__qflags & QueryFlags::Advanced) == QueryFlags::Advanced)
	{
	  VLIST modules;
	  if ((fsobj = this->__cnode->fsobj()) != NULL)
	    {
	      modules.push_back(new Variant(fsobj->name));
	      try
	      {
	        attr = this->__cnode->fsoAttributes();
	      }
	      catch (...)
	      {
	    	std::cout << "astnodes InterpreterContext::setCurrentNode can't get node->fsoAttributes()" << std::endl;
	      }
	      if (!attr.empty())
		{
		  if ((vptr = new Variant(attr)) != NULL)
		    this->__attributes.insert(std::pair<std::string, Variant_p >(fsobj->name, vptr));
		}
	    }
	  try
	    {
	      attr = this->__cnode->dynamicAttributes();
	      if (!attr.empty())
		{
		  this->__attributes.insert(attr.begin(), attr.end());
		  for (it = attr.begin(); it != attr.end(); it++)
		    modules.push_back(new Variant(it->first));
		}
	    }
	  catch (...)
	    {
	      std::cout << "astnodes InterpreterContext::setCurrentNode can't get node->dynamicAttributes()" << std::endl;
	    }
	  this->__attributes["module"] = new Variant(modules);
	}
      if ((this->__qflags & QueryFlags::Tags) == QueryFlags::Tags)
	{
	  std::vector< Tag* >	tags;
	  VLIST			vtags;
	  size_t		i;
	  tags = node->tags();
	  if (tags.size() > 0)
	    this->__attributes["tagged"] = new Variant(true);
	  else
	    this->__attributes["tagged"] = new Variant(false);
	  for (i = 0; i != tags.size(); ++i)
	    vtags.push_back(new Variant(tags[i]->name()));
	  this->__attributes["tags"] = new Variant(vtags);
	}
    }
}


void	InterpreterContext::__lookupByName(Variant_p rcvar, std::string name, std::list< Variant_p >* result)
{
  if (rcvar->type() == typeId::List)
    {
      std::list< Variant_p > lvariant = rcvar->value<std::list< Variant_p > >();
      std::list< Variant_p >::iterator it;

      for (it = lvariant.begin(); it != lvariant.end(); it++)
	this->__lookupByName((*it), name, result);
    }
  else if (rcvar->type() == typeId::Map)
    {
      Attributes mvariant = rcvar->value< Attributes >();
      Attributes::iterator it;

      for (it = mvariant.begin(); it != mvariant.end(); it++)
	{
	  if (it->first == name)
	    result->push_back(it->second);
	  else
	    this->__lookupByName(it->second, name, result);
	}
    }
}


void		InterpreterContext::__lookupByAbsoluteName(Variant_p rcvar, std::string name, std::list< Variant_p >* result)
{
  std::string	subname;
  std::string	subabs;
  size_t	idx;

  idx = name.find(".");
  if (idx != std::string::npos)
    {
      subname = name.substr(0, idx);
      subabs = name.substr(idx+1, name.size());
    }
  else
    {
      subname = name;
      subabs = "";
    }
  if ((rcvar->type() == typeId::List) && (!subabs.empty()))
    {
      std::list< Variant_p > lvariant = rcvar->value<std::list< Variant_p > >();
      std::list< Variant_p >::iterator it;

      for (it = lvariant.begin(); it != lvariant.end(); it++)
	if ((*it)->type() == typeId::Map)
	  this->__lookupByAbsoluteName((*it), subabs, result);
    }
  else if (rcvar->type() == typeId::Map)
    {
      Attributes mvariant = rcvar->value< Attributes >();
      Attributes::iterator it;

      if (subname == "*")
	{
	  for (it = mvariant.begin(); it != mvariant.end(); ++it)
	    {
	      if (!subabs.empty())
		this->__lookupByAbsoluteName(it->second, subabs, result);
	      else
		result->push_back(it->second);	      
	    }
	}
      else
	{
	  it = mvariant.find(subname);
	  if (it != mvariant.end())
	    {
	      if (!subabs.empty())
		this->__lookupByAbsoluteName(it->second, subabs, result);
	      else
		result->push_back(it->second);
	    }
	}
    }
}


std::list< Variant_p >	InterpreterContext::lookupByName(std::string name, attributeNameType tname)
{
  Attributes::iterator		attrit;
  std::list< Variant_p >	result;

  if (tname == ABSOLUTE_ATTR_NAME)
    {
      std::string	subname;
      std::string	subabs;
      size_t		idx;
      
      idx = name.find(".");
      if (idx != std::string::npos)
	{
	  subname = name.substr(0, idx);
	  subabs = name.substr(idx+1, name.size());
	  if ((attrit = this->__attributes.find(subname)) != this->__attributes.end())
	    this->__lookupByAbsoluteName(attrit->second, subabs, &result);
	}
      else if ((attrit = this->__attributes.find(name)) != this->__attributes.end())
	result.push_back(attrit->second);
    }
  else
    {      
      for (attrit = this->__attributes.begin(); attrit != this->__attributes.end(); attrit++)
	{
	  if (attrit->first == name)
	    result.push_back(attrit->second);
	  this->__lookupByName(attrit->second, name, &result);
	}
    }
  return result;
}



void	InterpreterContext::__lookupByType(Variant_p rcvar, uint8_t type, std::list< Variant_p >* result)
{
  if (rcvar->type() == typeId::List)
    {
      std::list<Variant_p > lvariant = rcvar->value<std::list< Variant_p > >();
      std::list<Variant_p >::iterator it = lvariant.begin();
      for (; it != lvariant.end(); it++)
	this->__lookupByType((*it), type, result);
    }
  else if (rcvar->type() == typeId::Map)
    {
      Attributes mvariant = rcvar->value<Attributes >();
      Attributes::iterator it = mvariant.begin();
      for (; it != mvariant.end(); it++)
	{
	  if (it->second->type() == type)
	    result->push_back(it->second);
	  else
	    this->__lookupByType(it->second, type, result);
	}
    }
}


std::list< Variant_p >	InterpreterContext::lookupByType(uint8_t type)
{
  std::list< Variant_p >	result;
  Attributes::iterator		attrit;

  for (attrit = this->__attributes.begin(); attrit != this->__attributes.end(); attrit++)
    {
      if (attrit->second->type() == type)
	result.push_back(attrit->second);
      this->__lookupByType(attrit->second, type, &result);
    }
  return result;
}

VFile*		InterpreterContext::data()
{
  if (this->__data == NULL)
    {
      try
	{
	  this->__data = this->__cnode->open();
	}
      catch (vfsError err)
	{
	  this->__data = NULL;
	}
    }
  return this->__data;
}

LogicalAnd::LogicalAnd(Expression* lhs, Expression* rhs) throw (std::string)
{
  this->__lhs = NULL;
  this->__rhs = NULL;
  if (lhs != NULL && rhs != NULL)
    {
      this->__lhs = lhs;
      this->__rhs = rhs;
      this->connection(this->__lhs);
      this->connection(this->__rhs);
    }
  else
    throw std::string("And expression, right or left expression cannot be NULL");
}

LogicalAnd::~LogicalAnd()
{
  if (this->__lhs != NULL && this->__rhs != NULL)
    {
      this->deconnection(this->__lhs);
      this->deconnection(this->__rhs);
      delete this->__lhs;
      delete this->__rhs;      
    }
}

bool		LogicalAnd::compile(InterpreterContext* ic)
{
  this->_ic = ic;
  return (this->__lhs->compile(ic) && this->__rhs->compile(ic));
}

Variant*	LogicalAnd::evaluate()
{
  Variant*	vlhs;
  Variant*	vrhs;
  bool	ret;
  
  ret = false;
  vlhs = NULL;
  vrhs = NULL;
  if (((vlhs = this->__lhs->evaluate()) != NULL) && (vlhs->type() == typeId::Bool))
    {
      ret = vlhs->value<bool>();
      if (ret && ((vrhs = this->__rhs->evaluate()) != NULL) && (vrhs->type() == typeId::Bool))
	ret = vrhs->value<bool>();
      else
	ret = false;
    }
  if (vlhs != NULL)
    delete vlhs;
  if (vrhs != NULL)
    delete vrhs;
  return new Variant(ret);
}

LogicalOr::LogicalOr(Expression* lhs, Expression* rhs)  throw (std::string)
{
  this->__lhs = NULL;
  this->__rhs = NULL;
  if (lhs != NULL && rhs != NULL)
    {
      this->__lhs = lhs;
      this->__rhs = rhs;
      this->connection(this->__lhs);
      this->connection(this->__rhs);
    }
  else
    throw std::string("Or expression, right or left expression cannot be NULL");
}

LogicalOr::~LogicalOr()
{
  if (this->__lhs != NULL && this->__rhs != NULL)
    {
      this->deconnection(this->__lhs);
      this->deconnection(this->__rhs);
      delete this->__lhs;
      delete this->__rhs;      
    }
}

bool		LogicalOr::compile(InterpreterContext* ic)
{
  this->_ic = ic;
  return (this->__lhs->compile(ic) && this->__rhs->compile(ic));
}

Variant*	LogicalOr::evaluate()
{
  Variant*	vlhs;
  Variant*	vrhs;
  bool	ret;
  
  ret = false;
  vlhs = NULL;
  vrhs = NULL;
  if (((vlhs = this->__lhs->evaluate()) != NULL) && (vlhs->type() == typeId::Bool))
    {
      ret = vlhs->value<bool>();
      if (!ret && ((vrhs = this->__rhs->evaluate()) != NULL) && (vrhs->type() == typeId::Bool))
	ret = vrhs->value<bool>();
    }
  if (vlhs != NULL)
    delete vlhs;
  if (vrhs != NULL)
    delete vrhs;
  return new Variant(ret);
}

ComparisonExpression::ComparisonExpression(Expression* lhs, Expression* rhs, int op) throw (std::string)
{
  this->__lhs = NULL;
  this->__rhs = NULL;
  if (lhs != NULL && rhs != NULL)
    {
      this->__lhs = lhs;
      this->__rhs = rhs;
      this->connection(this->__lhs);
      this->connection(this->__rhs);
      switch (op)
	{
	case GT:
	  __cmp = &ComparisonExpression::__gt;
	  break;
	case GTE:
	  __cmp = &ComparisonExpression::__gte;
	  break;
	case LT:
	  __cmp = &ComparisonExpression::__lt;
	  break;
	case LTE:
	  __cmp = &ComparisonExpression::__lte;
	  break;
	case EQ:
	  __cmp = &ComparisonExpression::__eq;
	  break;
	case NEQ:
	  __cmp = &ComparisonExpression::__neq;
	  break;
	default:
	  __cmp = NULL;
	  break;
	}
    }
  else
    throw std::string("Comparison expression, left or right expression cannot be NULL");
}

ComparisonExpression::~ComparisonExpression()
{
  if (this->__lhs != NULL && this->__rhs != NULL)
    {
      this->deconnection(this->__lhs);
      this->deconnection(this->__rhs);
      delete this->__lhs;
      delete this->__rhs;      
    }
}

bool		ComparisonExpression::compile(InterpreterContext* ic) 
{
  this->_ic = ic;
  return (this->__lhs->compile(ic) && this->__rhs->compile(ic));
}

Variant*	ComparisonExpression::evaluate()
{
  bool	ret;
  Variant*	vlhs;
  Variant*	vrhs;
  
  vlhs = this->__lhs->evaluate();
  vrhs = this->__rhs->evaluate();
  ret = false;
  if (vlhs && vrhs)
    {
      if (vlhs->type() == typeId::List && vrhs->type() == typeId::List)
	{
	  VLIST	lhs = vlhs->value< VLIST >();
	  VLIST	rhs = vrhs->value< VLIST >();
	  VLIST::iterator	lit = lhs.begin();
	  VLIST::iterator	rit = rhs.begin();
	  while (lit != lhs.end() && !ret && !this->_stop)
	    {
	      while (rit != rhs.end() && !ret && !this->_stop)
		{
		  ret = (this->*(__cmp))(*lit, *rit);
		  rit++;
		}
	      lit++;
	    }
	}
      else if (vlhs->type() == typeId::List && vrhs->type() != typeId::List)
	{
	  VLIST	lhs = vlhs->value< VLIST >();
	  VLIST::iterator	lit = lhs.begin();
	  while (lit != lhs.end() && !ret && !this->_stop)
	    {
	      ret = (this->*(__cmp))(*lit, vrhs);
	      lit++;
	    }
	}
      else if (vrhs->type() == typeId::List && vlhs->type() != typeId::List)
	{
	  VLIST	rhs = vrhs->value< VLIST >();
	  VLIST::iterator	rit = rhs.begin();
	  while (rit != rhs.end() && !ret && !this->_stop)
	    {	  
	      ret = (this->*(__cmp))(vlhs, *rit);
	      rit++;
	    }
	}
      else
	ret = (this->*(__cmp))(vlhs, vrhs);
    }
  return new Variant(ret);
}


LogicalNot::LogicalNot(Expression* expr) throw (std::string)
{
  this->__expr = NULL;
  if (expr != NULL)
    {
      this->__expr = expr;
      this->connection(this->__expr);
    }
  else
    throw std::string("Not expression cannot be NULL");
}

LogicalNot::~LogicalNot()
{
  if (this->__expr)
    {
      this->deconnection(this->__expr);
      delete this->__expr;
    }
}

bool	LogicalNot::compile(InterpreterContext* ic)
{
  this->_ic = ic;
  return this->__expr->compile(ic);
}

Variant*	LogicalNot::evaluate()
{
  Variant*	vexpr;
  bool	ret;
  
  ret = true;
  vexpr = NULL;
  
  if (((vexpr = this->__expr->evaluate()) != NULL) && (vexpr->type() == typeId::Bool))
    ret = vexpr->value<bool>();	
  if (vexpr !=  NULL)
    delete vexpr;
  return new Variant(!ret);
}


Number::Number(uint64_t val) : __val(val) 
{
}

Number::~Number() 
{ 
}

bool		Number::compile(InterpreterContext* ic) 
{ 
  this->_ic = ic;
  return true; 
}

Variant*	Number::evaluate()
{
  return new Variant(__val);
}

Boolean::Boolean(bool val) : __val(val)
{
}
 
Boolean::~Boolean() 
{ 
}

bool		Boolean::compile(InterpreterContext* ic) 
{ 
  this->_ic = ic;
  return true; 
}

Variant*	Boolean::evaluate()
{
  return new Variant(__val);
}  


TimestampAttribute::TimestampAttribute(std::string val) : __val(val)
{
}

TimestampAttribute::~TimestampAttribute()
{
}

bool		TimestampAttribute::compile(InterpreterContext* ic) 
{
  this->_ic = ic;
  this->_ic->setQueryFlags(QueryFlags::Advanced);
  return true;
}

Variant*	TimestampAttribute::evaluate()
{
  std::list< Variant_p >  types = this->_ic->lookupByType(typeId::DateTime);
  if (types.size() > 0)
    return new Variant(types);
  else
    return NULL;
}

Expression*	TimestampAttribute::create(std::string val)
{
  return new TimestampAttribute(val);
}

NamedAttribute::NamedAttribute(std::string val) : __val(val), __attrtype(attributeNameType())
{
}

NamedAttribute::~NamedAttribute()
{
}

bool		NamedAttribute::compile(InterpreterContext* ic) 
{
  this->_ic = ic;
  QueryFlags::Level	_qflags;
  try
    {
      _qflags = AttributeFactory::instance()->getQueryFlags(__val);
      this->_ic->setQueryFlags(_qflags);
    }
  catch (std::string)
    {
      _qflags = QueryFlags::Advanced;
      this->_ic->setQueryFlags(_qflags);
    }
  if (__val.find(".") != std::string::npos)
    __attrtype = ABSOLUTE_ATTR_NAME;
  else
    __attrtype = RELATIVE_ATTR_NAME;
  return true;
}

Variant*	NamedAttribute::evaluate()
{
  std::list< Variant_p >  types = this->_ic->lookupByName(__val, __attrtype);
  if (types.size() == 1)
    {
      return new Variant(types.front().get());
    }
  else if (types.size() > 1)
    return new Variant(types);
  else
    return NULL;
}

Expression*	NamedAttribute::create(std::string val)
{
  return new NamedAttribute(val);
}


String::String(std::string val) : __val(val) 
{ 
}

String::~String() 
{
}

bool		String::compile(InterpreterContext* ic) 
{ 
  this->_ic = ic;
  return true; 
}

Variant*	String::evaluate()
{
  return new Variant(__val);
}

Timestamp::Timestamp(std::string val) : __val(val) 
{
}

Timestamp::Timestamp(uint32_t val)
{
  std::stringstream	vstr;

  vstr << val;
  __val = vstr.str();
  __val += "-01-01";
}

Timestamp::~Timestamp()
{
}

bool		Timestamp::compile(InterpreterContext* ic) 
{
  this->_ic = ic;
  return true; 
}

Variant*	Timestamp::evaluate()
{
  return new Variant(new DateTime(__val));
}


DataPatternCount::DataPatternCount(uint64_t count, PatternContainer* container) : __count(count), __container(container)
{
}

DataPatternCount::~DataPatternCount()
{
}

bool		DataPatternCount::compile(InterpreterContext* ic)
{
  this->_ic = ic;
  return true;
}

Variant*	DataPatternCount::evaluate()
{
  VFile*	vf;
  Search*	s;
  uint64_t	counter;
  
  vf = NULL;
  s = NULL;
  counter = 0;
  try
    {    
      if ((vf = this->_ic->data()) != NULL)
	{
	  this->connection(vf);
	  this->__container->reset();
	  while (counter != this->__count && !this->_stop && ((s = this->__container->getPattern()) != NULL))
	    {
	      if (vf->find(s) != -1)
		{
		  IndexedPatterns::instance()->addPattern(s->pattern(), vf->node());
		  ++counter;
		}
	    }
	}
    }
  catch (vfsError err)
    {
      std::cout << err.error << std::endl;
    }
  catch (std::exception err)
    {
      //std::cout << err.error << std::endl;
    }
  if (vf != NULL)
    this->deconnection(vf);
  return new Variant(counter == this->__count);
}


DataMatches::DataMatches(uint64_t count, Search* pattern) : __count(count), __pattern(pattern)
{
  
}

DataMatches::~DataMatches()
{
}

bool		DataMatches::compile(InterpreterContext* ic)
{
  bool		ret;

  ret = false;
  try
    {
      this->__pattern->compile();
      this->_ic = ic;
      ret = true;
    }
  catch (std::string)
    {
    }
  return ret;
}

Variant*	DataMatches::evaluate()
{
  VFile*	vf;
  bool		ret;
  int32_t	counter;
  
  ret = false;
  vf = NULL;
  counter = 0;
  try
    {      
      if ((vf = this->_ic->data()) != NULL)
	{
	  this->connection(vf);
	  if (this->__count > 1)
	    {
	      if ((counter = vf->count(this->__pattern, (int32_t)this->__count)) == this->__count)
		ret = true;
	    }
	  else
	    {
	      int64_t	off = vf->find(this->__pattern);
	      if (off != -1)
		counter = 1;
	      ret = ((__count == 0 && off == -1) || (__count == 1 && off != -1));
	    }
	  if (counter)
	    IndexedPatterns::instance()->addPattern(this->__pattern->pattern(), vf->node());
	}
    }
  catch (vfsError err)
    {
      std::cout << err.error << std::endl;
    }
  catch (std::exception err)
    {
      //std::cout << err.error << std::endl;
    }
  if (vf != NULL)
    this->deconnection(vf);
  return new Variant(ret);
}



AttributeExpression::AttributeExpression(Expression* attr, uint64_t count, ExpressionList* exprs) throw (std::string)
{
  this->__attr = NULL;
  this->__count = 0;
  this->__exprs = NULL;
  this->__patterns = NULL;  
  if (attr != NULL && exprs != NULL)
    {
      ExpressionList::iterator	eit;
      this->__attr = attr;
      this->__count = count;
      this->__exprs = exprs;
      this->connection(this->__attr);
      for (eit = this->__exprs->begin(); eit != this->__exprs->end(); ++eit)
	{
	  this->connection(*eit);
	}
    }
}

AttributeExpression::AttributeExpression(Expression* attr, uint64_t count, PatternContainer* patterns) throw (std::string)
{  
  this->__attr = NULL;
  this->__count = 0;
  this->__exprs = NULL;
  this->__patterns = NULL;  
  if (attr != NULL && patterns != NULL)
    {
      this->__attr = attr;
      this->__count = count;
      this->__patterns = patterns;
      this->connection(this->__attr);
    }
}

AttributeExpression::~AttributeExpression()
{
  ExpressionList::iterator	eit;

  if (this->__exprs != NULL)
    {
      for (eit = this->__exprs->begin(); eit != this->__exprs->end(); ++eit)
	{
	  this->deconnection(*eit);
	  delete (*eit);
	}
      delete this->__exprs;
    }
  if (this->__patterns != NULL)
    {
      delete this->__patterns;
    }
  if (this->__attr != NULL)
    {
      this->deconnection(this->__attr);
      delete this->__attr;
    }
}

bool		AttributeExpression::compile(InterpreterContext* ic)
{
  this->_ic = ic;
  return this->__attr->compile(ic);
}

void		AttributeExpression::__evaluate(Variant_p vattr, uint64_t* counter)
{
  if (vattr->type() == typeId::String || vattr->type() == typeId::CArray)
    {
      std::string attr = vattr->value<std::string>();
      Search*	sh;
      
      this->__patterns->reset();
      while (*counter != this->__count && ((sh = this->__patterns->getPattern()) != NULL))
	{
	  if (sh->find(attr) != -1)
	    ++(*counter);
	}
    }
}

Variant*	AttributeExpression::evaluate()
{
  bool		ret;
  Variant*	vattr = NULL;
  uint64_t counter = 0;

  ret = false;
  if ((vattr = this->__attr->evaluate()) != NULL)
    {
      if (this->__patterns != NULL)
	{
	  if (vattr->type() == typeId::List)
	    {
	      VLIST vlist = vattr->value< VLIST >();
	      VLIST::iterator	it;

	      it = vlist.begin();
	      while (counter != this->__count && it != vlist.end())
		{
		  this->__evaluate(*it, &counter);
		  ++it;
		}
	    }
	  else
	    this->__evaluate(vattr, &counter);
	  ret = (counter == this->__count);
	}
    }
  // else if (this->__exprs != NULL)
  //   {
  //   }
  //   }
  return new Variant(ret);
}

// PropertiesExpression::PropertiesExpression(uint64_t count, AttributeList* attrs)
// {
// }
// PropertiesExpression::~PropertiesExpression()
// {
// }

// bool		PropertiesExpression::compile(InterpreterContext* ic)
// {
// }

// Variant*	PropertiesExpression::evaluate()
// {
//   return new Variant(false);
// }


MatchExpression::MatchExpression(Expression *expr, Search* pattern) throw (std::string)
{
  this->__expr = NULL;
  this->__pattern = NULL;
  if (expr != NULL && pattern != NULL)
    {
      this->__expr = expr;
      this->connection(this->__expr);
      this->__pattern = pattern;
    }
  else
    throw std::string("Match expression cannot be NULL");
}

MatchExpression::~MatchExpression()
{
  if (this->__expr != NULL)
    {
      this->deconnection(this->__expr);
      delete this->__expr;
    }
  if (this->__pattern != NULL)
    delete this->__pattern;
}

bool		MatchExpression::compile(InterpreterContext* ic)
{ 
  this->_ic = ic;
  this->__expr->compile(ic);
  this->__pattern->compile();
  return true; 
}

Variant*	MatchExpression::evaluate()
{
  Variant*	lexpr = NULL;
  std::string	str;
  int32_t	off;
  bool		ret;

  ret = false;
  lexpr = this->__expr->evaluate();
  if (lexpr != NULL && (lexpr->type() == typeId::String || lexpr->type() == typeId::CArray))
    {
      str = lexpr->value< std::string >();
      if ((off = this->__pattern->find(str)) != -1)
	ret = true;
    }
  if (lexpr != NULL)
    delete lexpr;
  return new Variant(ret);
}


// DataMatchExpression::DataMatchExpression(uint64_t count, Search* pattern) : __count(count), __pattern(pattern)
// {
// }

// DataMatchExpression::~DataMatchExpression()
// {
// }

// bool		DataMatchExpression::compile(InterpreterContext* ic)  
// { 
//   this->_ic = ic;
//   return true; 
// }


// Variant*	DataMatchExpression::evaluate()
// {
// }


PatternList::PatternList()
{
  this->__pos = 0;
}

PatternList::PatternList(Search* pattern)
{
  this->__pos = 0;
  this->__patterns.push_back(pattern);
}

PatternList::~PatternList()
{
}

void    PatternList::push(Search* pattern)
{
  this->__patterns.push_back(pattern);
}

Search*		PatternList::getPattern()
{
  Search*	pattern;

  pattern = NULL;
  if (this->__pos < this->__patterns.size())
    {
      pattern = this->__patterns[this->__pos];
      this->__pos++;
    }
  return pattern;
}

void		PatternList::reset()
{
  this->__pos = 0;
}

PatternDictionnary::PatternDictionnary(Dictionnary* dict)
{
  this->__idx = this->__dicts.begin();
  dict->compile();
  this->__dicts.push_back(dict);
}

void	PatternDictionnary::push(Dictionnary* dict)
{
  dict->compile();
  this->__dicts.push_back(dict);
}

PatternDictionnary::~PatternDictionnary()
{
}

Search*	PatternDictionnary::getPattern()
{ 
  Search*	s;
  s = NULL;
  while (this->__idx != this->__dicts.end())
    {
      if ((s = (*this->__idx)->nextSearchPattern()) != NULL)
	return s;
      else
	this->__idx++;
    }
  return s;
}

void		PatternDictionnary::reset()
{
  std::vector<Dictionnary*>::iterator it;
  
  for (it = this->__dicts.begin(); it != this->__dicts.end(); it++)
    (*it)->reset();
  this->__idx = this->__dicts.begin();
}
