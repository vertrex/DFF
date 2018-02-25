/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

#ifndef YY_YY_DATA_DFF_GUIMERGE_DFF_API_FILTERS_PARSER_HPP_INCLUDED
# define YY_YY_DATA_DFF_GUIMERGE_DFF_API_FILTERS_PARSER_HPP_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 1
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    CONTAIN = 258,
    DATA = 259,
    DOTDOT = 260,
    ATTRIBUTE = 261,
    FILESIZE = 262,
    TIMESTAMP = 263,
    IDENTIFIER = 264,
    NUMBER = 265,
    STRING = 266,
    REGEXP = 267,
    WILDCARD = 268,
    FUZZY = 269,
    DICT = 270,
    ATTRIBUTES = 271,
    MATCHES = 272,
    _TRUE_ = 273,
    _FALSE_ = 274,
    ALL = 275,
    ANY = 276,
    NONE = 277,
    OF = 278,
    OR = 279,
    AND = 280,
    BIN_OR = 281,
    BIN_XOR = 282,
    BIN_AND = 283,
    LT = 284,
    LTE = 285,
    GT = 286,
    GTE = 287,
    EQ = 288,
    NEQ = 289,
    IS = 290,
    _IN_ = 291,
    LSHIFT = 292,
    RSHIFT = 293,
    PLUS = 294,
    MINUS = 295,
    MUL = 296,
    DIV = 297,
    MOD = 298,
    POW = 299,
    NOT = 300
  };
#endif

/* Value type.  */



int yyparse (void* yyscanner);

#endif /* !YY_YY_DATA_DFF_GUIMERGE_DFF_API_FILTERS_PARSER_HPP_INCLUDED  */
