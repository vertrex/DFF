/*
 * typeparser.h
 * Definition of the structure used internally by the parser and lexer
 * to exchange data.
 */
 
#ifndef __TYPEPARSER_H__
#define __TYPEPARSER_H__
 
#include "astnodes.hpp"

/**
 * @brief The structure used by flex and bison
 */
typedef union		stypeParser
{
  AstNode*		node;
  NumberList*		numlist;
  StringList*		strlist;
  TimeList*		timelist;
  Processor*		proc;
  uint64_t		number;
  std::string*		str;
  std::string*		token;
  CmpOperator::Op	comp;
  bool			boolean;
}			typeParser;

// define the type for flex and bison
#define YYSTYPE typeParser
 
#endif // __TYPE_PARSER_H__
