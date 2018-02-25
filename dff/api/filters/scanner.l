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

/*

Some parts (str token) of the lexer have been inspired from yara-project developed by 
Victor M. Alvarez and released under GPLv2

http://code.google.com/p/yara-project/

*/

%{

#include <stdlib.h>
#include <limits.h> 
#include <stdint.h>

#include "parser.hpp"
#include "scanner.hpp"

#ifdef _WIN32 || _WIN64
  #define strtoll(x, y, z) _strtoi64(x, y, z)
  #define strtoull(x, y, z) _strtoui64(x, y, z)
#endif

%}

%option reentrant bison-bridge
%option never-interactive
%option noyywrap
%option nounistd
%option yylineno
%option verbose
%option warn

%x str
%x attribute
%x regexp
%x fuzzy
%x wildcard
%x dict

digit		[0-9]
letter		[a-zA-Z]
hexdigit	[a-fA-F0-9]

%%

"<"				{ return LT;		}
">"				{ return GT;		}
"<="				{ return LTE;		}
">="				{ return GTE;		}
"=="				{ return EQ;		}
"!="				{ return NEQ;		}
">>"				{ return RSHIFT;	}
"<<"				{ return LSHIFT;	}
"**"				{ return POW;		}
"&"				{ return BIN_AND;	}
"|"				{ return BIN_OR;	}
"^"				{ return BIN_XOR;	}
"*"				{ return MUL;		}
"%"				{ return MOD;		}
"+"				{ return PLUS;		}
"-"				{ return MINUS;		}
".."				{ return DOTDOT;	}
"true"				{ return _TRUE_;	}
"false"				{ return _FALSE_;	}
"not"				{ return NOT;		}
"and"				{ return AND;		}
"or"				{ return OR;		}
"in"				{ return _IN_;		}
"is"				{ return IS;		}
"of"				{ return OF;		}
"all"				{ return ALL;		}
"any"				{ return ANY;		}
"none"				{ return NONE;		}
"attributes"			{ return ATTRIBUTES;	}
"contain"			{ return CONTAIN;	}
"data"				{ return DATA;		}
"matches"			{ return MATCHES;	}

{digit}+(KiB|MiB|GiB|TiB|PiB|EiB){0,1}	{
  uint64_t      mul;
  uint64_t      size;
  char*         unit;
  char*         number;
  int           digit;

  mul = 1;
  size = 0;
  unit = NULL;
  number = NULL;
  digit = strspn(yytext, "0123456789");
  if (digit == 0)
    yyerror(yyscanner, "Size contains no digit");
  if (digit < yyleng)
    {
      number = (char*)calloc(digit+1, sizeof(char));
      strncpy(number, yytext, digit);
      unit = yytext+digit;
      if (*unit == 'k' || *unit == 'K')
        mul = 1024;
      if (*unit == 'm' || *unit == 'M')
        mul = 1048576;
      if (*unit == 'g' || *unit == 'G')
        mul = 1073741824;
      if (*unit == 't' || *unit == 'T')
        mul = 1099511627776;
      if (*unit == 'p' || *unit == 'P')
        mul = 1125899906842624;
      if (*unit == 'e' || *unit == 'E')
        mul = 1152921504606846976;
    }
  else
    number = yytext;
  errno = 0;
  size = strtoull(number, NULL, 10);
  if (number != yytext)
    free(number);
  if (errno == ERANGE && size == ULLONG_MAX)
    yyerror(yyscanner, "Provided size is too large");
  if (size > (ULLONG_MAX / mul))
    yyerror(yyscanner, "Provided size is too large");
  size *= mul;
  yylval->number = size;
  return NUMBER;
}


0(x|X){hexdigit}+ {
  uint64_t	val = 0;
  errno = 0;
  val = strtoull(yytext+2, NULL, 16);
  if (errno == ERANGE && val == ULLONG_MAX)
    yyerror(yyscanner, "overflow error\n");
  yylval->number = val;
  return NUMBER;
}



({letter}|_)({letter}|{digit}|_)* {
  yylval->cstr = new std::string(yytext, yyleng);
  return IDENTIFIER;
}


[0-9]{4}("-"[0-9]{2}){2}"T"[0-9]{2}(":"[0-9]{2}){2} {
  yylval->cstr = new std::string(yytext, yyleng);
  return TIMESTAMP;
}


[0-9]{4}("-"[0-9]{2}){2} {
  yylval->cstr = new std::string(yytext, yyleng);
  return TIMESTAMP;
}


[0-9]{2}(":"[0-9]{2}){2} {
  yylval->cstr = new std::string(yytext, yyleng);
  return TIMESTAMP;
}



<str>\"                              {     /* saw closing quote - all done */
                                         if (yyextra->buf->size() == 0)
                                         {
                                             yyerror(yyscanner, "empty string");
                                         }
                                         BEGIN(INITIAL);
                                         yylval->cstr = new std::string(yyextra->buf->c_str());
                                         return STRING;
                                     }

<str>\\t                             { yyextra->buf->append(1, '\t'); }
<str>\\\"                            { yyextra->buf->append("\""); }
<str>\\\\                            { yyextra->buf->append("\\"); }

<str>\\x{hexdigit}{2}                {
                                         int result;

                                         sscanf( yytext + 2, "%x", &result );                                         
					 yyextra->buf->append(1, (char)result);
                                     }

<str>[^\\\n\"]+                      {
					yyextra->buf->append(yytext, yyleng);
                                     }


<str>\\(.|\n)                        {
                                         yyerror(yyscanner, "illegal escape sequence");
                                     }


\"                                   {
					yyextra->buf->clear();
                                        BEGIN(str);
                                     }


<attribute>@			     {

                                        if (yyextra->buf->size() == 0)
                                         {
						yyerror(yyscanner, "empty attribute");
						yyterminate();
                                         }
                                         BEGIN(INITIAL);
                                         yylval->cstr = new std::string(yyextra->buf->c_str());
                                         return ATTRIBUTE;
                                     }
				       

<attribute>[^@]+                     {

					yyextra->buf->append(yytext, yyleng);
                                     }


@				     {
					yyextra->buf->clear();
					BEGIN(attribute);
				     }



<wildcard>"$"                       {
					if (yyextra->buf->size() == 0)
                                         {
                                             yyerror(yyscanner, "empty wildcard pattern");
                                         }
                                         BEGIN(INITIAL);
                                         yylval->cstr = new std::string(yyextra->buf->c_str());
                                         return WILDCARD;
                                     }


<wildcard>\\x{hexdigit}{2}           {
                                         int result;

                                         sscanf( yytext + 2, "%x", &result );                                         
					 yyextra->buf->append(1, (char)result);
                                     }

<wildcard>[^\\\n\"$]+                {

					yyextra->buf->append(yytext, yyleng);
                                     }


"$"                                  {
					yyextra->buf->clear();
                                        BEGIN(wildcard);
                                     }



<fuzzy>"~"			     {

                                        if (yyextra->buf->size() == 0)
                                         {
						yyerror(yyscanner, "empty fuzzy pattern");
						yyterminate();
                                         }
                                         BEGIN(INITIAL);
                                         yylval->cstr = new std::string(yyextra->buf->c_str());
                                         return FUZZY;
                                     }

<fuzzy>[^"~"]+			     {

					yyextra->buf->append(yytext, yyleng);
                                     }


"~"				    {
					yyextra->buf->clear();
                                        BEGIN(fuzzy);					
				    }


<regexp>"/"			     {

                                        if (yyextra->buf->size() == 0)
                                         {
						yyerror(yyscanner, "empty regexp pattern");
						yyterminate();
                                         }
                                         BEGIN(INITIAL);
                                         yylval->cstr = new std::string(yyextra->buf->c_str());
                                         return REGEXP;
                                     }

<regexp>\\\/                         {
					 yyextra->buf->append(1, '/');
                                     }

<regexp>\\.                          {
					yyextra->buf->append(yytext, 2);
                                     }

<regexp>[^/\n\\]+                    {
					yyextra->buf->append(yytext, yyleng);
                                     }

<regexp>\n                           {
                                         yyerror(yyscanner, "unterminated regular expression");
                                         yyterminate();
                                     }


"/"				    {
					yyextra->buf->clear();
                                        BEGIN(regexp);					
				    }


":"				    {
					yyextra->buf->clear();
					BEGIN(dict);
				    }


<dict>[^:\n]+                       {
					yyextra->buf->append(yytext, yyleng);
                                     }


<dict>":"			    {
                                        if (yyextra->buf->size() == 0)
                                         {
						yyerror(yyscanner, "empty dictionnary term");
						yyterminate();
                                         }
                                         BEGIN(INITIAL);
                                         yylval->cstr = new std::string(yyextra->buf->c_str());
                                         return DICT;
				    }


[ \t\r\n]*                            { /* skip whitespace */ }

.                                    {
                                         return yytext[0];
                                     }


%%

void yyerror(yyscan_t yyscanner, const char* error_msg)
{
//   if (error_msg != NULL)
//      printf("%s\n", error_msg);
}

int	parse_filter_string(const char* filter_string, filter_ctx* ctx)
{
	yyscan_t	yyscanner;
	YY_BUFFER_STATE	state;
	int		status;

	yylex_init(&yyscanner);
	yyset_extra(ctx, yyscanner);
	state = yy_scan_string(filter_string, yyscanner);
        if (yyparse(yyscanner) != 0)
	   status = -1;
	else
	   status = 0;
	yylex_destroy(yyscanner);
	return status;
}
