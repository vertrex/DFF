#ifndef __SCANNER_H__
#define __SCANNER_H__

#include "astnodes.hpp"

#define LEX_BUF_SIZE 1024

typedef struct	s_filter_ctx
{
  int			column;
  std::string*		buf;
  Expression*		root;
  InterpreterContext*	ic;
}			filter_ctx;

#ifndef YY_TYPEDEF_YY_SCANNER_T
	#define YY_TYPEDEF_YY_SCANNER_T
	typedef void* yyscan_t;
#endif

#define YY_EXTRA_TYPE filter_ctx*
#define YY_USE_CONST

typedef union YYSTYPE
{
  Expression*   node;
  Search*	search;
  PatternContainer*	pcontainer;
  AttributeList*	lattrs;
  ExpressionList*	lexprs;
  std::string*	cstr;
  uint64_t      number;
  int		tok;
  sfunc_params*	sfp;
} YYSTYPE;

# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1


void		yyerror(yyscan_t yyscanner, const char *error_message);
YY_EXTRA_TYPE	yyget_extra(yyscan_t yyscanner);

int		yylex(YYSTYPE*, yyscan_t);
int		yyparse(yyscan_t);

int		parse_filter_string(const char* filter_string, filter_ctx* ctx);

#endif
