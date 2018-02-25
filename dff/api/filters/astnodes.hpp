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

#ifndef __ASTNODES_HPP__
#define __ASTNODES_HPP__

#include <iostream>
#include <vector>
#include "search.hpp"
#include "eventhandler.hpp"
#include "factory.hpp"
#include "dictionnary.hpp"
#include "node.hpp"


using namespace DFF;
// forward declaration
class Expression;
class PatternContainer;


#define KEYWORD(_kwd, _fqn, _type, _qflag)					\
  static int _kwd ## _default_kw = AttributeFactory::instance()->addKeyword(#_kwd, #_fqn, _type, _qflag);


typedef std::vector<uint64_t>		NumberList;
typedef std::vector<std::string>	StringList;
typedef std::vector<std::string>	AttributeList;
typedef std::vector<DateTime*>		TimeList;
typedef std::vector<Expression*>	ExpressionList;
typedef std::list< Variant_p >		VLIST;

#define IN_RANGE	0
#define NOT_IN_RANGE	1

typedef struct
{
  std::string*	pattern;
  Search::CaseSensitivity cs;
}		sfunc_params;

// class PatternIndexer
// {
// private:
//   EXPORT	PatternIndexer() {}
//   EXPORT	PatternIndexer(PatternIndexer &) {}
//   EXPORT	~PatternIndexer() {}
//   PatternIndexer&	operator=(PatternIndexer &) {}
// public:
//   EXPORT static PatternIndexer*	instance()
//   {
//     static PatternIndexery fact;
//     return &fact;
//   }
// };

class InterpreterContext
{  
public :
  InterpreterContext();
  ~InterpreterContext();
  void		setCurrentNode(DFF::Node* node);
  void		setQueryFlags(QueryFlags::Level qflags);
  std::list< Variant_p >	lookupByType(uint8_t type);
  std::list< Variant_p >	lookupByName(std::string name, attributeNameType tname);
  VFile*	data();
  void		clear();
private:
  Attributes				__attributes;
  DFF::Node*				__cnode;
  void					__lookupByName(Variant_p rcvar, std::string name, std::list< Variant_p >* result);
  void					__lookupByAbsoluteName(Variant_p rcvar, std::string name, std::list< Variant_p >* result);
  void					__lookupByType(Variant_p rcvar, uint8_t type, std::list< Variant_p >* result);
  VFile*				__data;
  int					__qflags;
};

class Expression : public EventHandler
{
protected:
  bool	_stop;
  InterpreterContext*	_ic;
  Expression() : _stop(false), _ic(NULL) {}
public:
  virtual ~Expression() {}
  virtual Variant*	evaluate() = 0;
  virtual bool		compile(InterpreterContext* ic) = 0;
  virtual void		Event(event* e)
  { 
    if (e != NULL)
      {
  	if (e->type == 0x4242)
  	  {
  	    _stop = false;
  	    notify(e);
  	  }
  	else if (e->type == 0x204)
  	  {
  	    _stop = true;
  	    notify(e);
  	  }
      }
  }
};

class LogicalAnd : public Expression
{
private:
  Expression*	__lhs;
  Expression*	__rhs;
public:
  LogicalAnd(Expression* lhs, Expression* rhs) throw (std::string);
  ~LogicalAnd();
  virtual bool		compile(InterpreterContext* ic);
  virtual Variant*	evaluate();
};

class LogicalOr : public Expression
{
private:
  Expression*	__lhs;
  Expression*	__rhs;
public:
  LogicalOr(Expression* lhs,  Expression* rhs) throw (std::string);
  ~LogicalOr();
  virtual bool		compile(InterpreterContext* ic);
  virtual Variant*	evaluate();
};

class ComparisonExpression : public Expression
{
private:
  Expression*	__lhs;
  Expression*	__rhs;
  typedef  bool (ComparisonExpression::*Op)(Variant* lhs, Variant* rhs);
  bool	__gt(Variant* lhs, Variant*rhs) { return lhs->operator>(rhs); }
  bool	__gte(Variant* lhs, Variant*rhs) { return lhs->operator>=(rhs); }
  bool	__lt(Variant* lhs, Variant*rhs) { return lhs->operator<(rhs); }
  bool	__lte(Variant* lhs, Variant*rhs) { return lhs->operator<=(rhs); }
  bool	__eq(Variant* lhs, Variant*rhs) { return lhs->operator==(rhs); }
  bool	__neq(Variant* lhs, Variant*rhs) { return lhs->operator!=(rhs); }
  Op	__cmp;
public:
  ComparisonExpression(Expression* lhs, Expression* rhs, int op) throw (std::string);
  ~ComparisonExpression();
  virtual bool		compile(InterpreterContext* ic);
  virtual Variant*	evaluate();
};


class LogicalNot : public Expression
{
private:
  Expression*		__expr;
public:
  LogicalNot(Expression* expr) throw (std::string);
  ~LogicalNot();
  virtual bool		compile(InterpreterContext* ic);
  virtual Variant*	evaluate();
};


class Number : public Expression
{
private:
  uint64_t		__val;
public:
  Number(uint64_t val);
  ~Number();
  virtual bool		compile(InterpreterContext* ic);
  virtual Variant*	evaluate();
};


class Boolean : public Expression
{
private:
  bool			__val;
public:
  Boolean(bool val);
  ~Boolean();
  virtual bool		compile(InterpreterContext* ic);
  virtual Variant*	evaluate();
};


class TimestampAttribute : public Expression
{
private:
  std::string		__val;
public:
  TimestampAttribute(std::string val);
  ~TimestampAttribute();
  virtual bool		compile(InterpreterContext* ic);
  virtual Variant*	evaluate();
  static Expression*	create(std::string val);
};

class NamedAttribute : public Expression
{
private:
  std::string		__val;
  attributeNameType	__attrtype;
public:
  NamedAttribute(std::string val);
  ~NamedAttribute();
  virtual bool		compile(InterpreterContext* ic);
  virtual Variant*	evaluate();
  static Expression*	create(std::string val);
};

class String : public Expression
{
private:
  std::string	__val;
public:
  String(std::string val);
  ~String();
  virtual bool		compile(InterpreterContext* ic);
  virtual Variant*	evaluate();
};

//typedef std::list<String*> StringList;

class Timestamp : public Expression
{
private:
  std::string	__val;
public:
  Timestamp(std::string val);
  Timestamp(uint32_t val);
  ~Timestamp();
  virtual bool		compile(InterpreterContext* ic);
  virtual Variant*	evaluate();
};

class DataPatternCount: public Expression
{
private:
  uint64_t		__count;
  PatternContainer*	__container;
public:
  DataPatternCount(uint64_t count, PatternContainer* container);
  ~DataPatternCount();
  virtual bool		compile(InterpreterContext* ic);
  virtual Variant*	evaluate();  
};

class DataMatches : public Expression
{
private:
  uint64_t		__count;
  Search*		__pattern;
public:
  DataMatches(uint64_t count, Search* pattern);
  ~DataMatches();
  virtual bool		compile(InterpreterContext* ic);
  virtual Variant*	evaluate();
};


class AttributeExpression : public Expression
{
private:
  Expression*		__attr;
  uint64_t		__count;  
  ExpressionList*	__exprs;
  PatternContainer*	__patterns;
  void			__evaluate(Variant_p attr, uint64_t* counter);
public:
  AttributeExpression(Expression* attr, uint64_t count, ExpressionList* exprs) throw (std::string);
  AttributeExpression(Expression* attr, uint64_t count, PatternContainer* patterns) throw (std::string);
  ~AttributeExpression();
  virtual bool		compile(InterpreterContext* ic);
  virtual Variant*	evaluate();
};


// class PropertiesExpression : public Expression
// {
// private:
//   uint64_t		__count;
//   AttributeList*	__attrs;
// public:
//   PropertiesExpression(uint64_t count, AttributeList* attrs);
//   ~PropertiesExpression();
//   virtual bool		compile(InterpreterContext* ic);
//   virtual Variant*	evaluate();
// };

class MatchExpression : public Expression
{
private:
  Expression*	__expr;
  Search*	__pattern;
public:
  MatchExpression(Expression *expr, Search* pattern) throw (std::string);
  ~MatchExpression();
  virtual bool		compile(InterpreterContext* ic);
  virtual Variant*	evaluate();
};

class PatternContainer
{
public:
  virtual ~PatternContainer() {}
  virtual Search*	getPattern() = 0;
  virtual void		reset() = 0;
};

class PatternList : public PatternContainer
{
private:
  std::vector<Search*>	__patterns;
  size_t		__pos;
public:
  PatternList();
  PatternList(Search* pattern);
  ~PatternList();
  void	push(Search* pattern);
  virtual Search*	getPattern();
  virtual void		reset();
};

class PatternDictionnary : public PatternContainer
{
private:
  std::vector<Dictionnary*>		__dicts;
  std::vector<Dictionnary*>::iterator  	__idx;
public:
  explicit PatternDictionnary(Dictionnary* dict);
  ~PatternDictionnary();
  virtual Search*	getPattern();
  virtual void		reset();
  void			push(Dictionnary* dict);
};

#endif
