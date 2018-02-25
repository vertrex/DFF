%{

#define YYERROR_VERBOSE

#include <stdio.h>
#include <stdint.h>
#include "scanner.hpp"
#include "astnodes.hpp"
#include "dictionnary.hpp"

  Expression*	check_for_timestamp(Expression* lhs, Expression* rhs);

%}

%debug
%verbose
%define api.pure

%parse-param {void* yyscanner}
%lex-param {yyscan_t yyscanner}

 /*

reserved identifier (keywords) are the following:

* filesize
* timestamp
  * time
  * date
  * datetime
* setted 
* data
* deleted
* extension
* filetype
* mime
* name
* module
* tag
  */

%token CONTAIN

%token DATA

%token DOTDOT

%token <cstr> ATTRIBUTE
%token <node> FILESIZE
%token <cstr> TIMESTAMP
%token <cstr> IDENTIFIER
%token <number> NUMBER
%token <cstr> STRING
%token <cstr> REGEXP
%token <cstr> WILDCARD
%token <cstr> FUZZY
%token <cstr> DICT
%token ATTRIBUTES
%token MATCHES

%token <tok> _TRUE_
%token <tok> _FALSE_

%token <number> ALL
%token <number> ANY
%token <number> NONE

%token OF

%token <tok> OR
%token <tok> AND
%token <tok> BIN_OR
%token <tok> BIN_XOR
%token <tok> BIN_AND
%token LT LTE GT GTE EQ NEQ IS _IN_ //"<" "<=" ">" ">=" "==" "!=" "is" "in"
%token <tok> LSHIFT RSHIFT //"<<" ">>"
%token PLUS MINUS
%token MUL DIV MOD
%token POW
%token <tok> NOT


/* "extension" */
/* "filename" */
/* "filetype" */
/* "filesize" */
/* "deleted" */
/* "date" */
/* "time" */
/* "datetime" */


/* operators precedence from lowest to highest */

%left OR
%left AND
%left BIN_OR
%left BIN_XOR
%left BIN_AND
%left LT LTE GT GTE EQ NEQ IS _IN_ //"<" "<=" ">" ">=" "==" "!=" "is" "in"
%left LSHIFT RSHIFT //"<<" ">>"
%left PLUS MINUS
%left MUL DIV MOD
%right NOT
 //%right '~'

/* %type <tok> arith_operator */
/* %type <tok> comp_operator */

%type <node> boolean_expression
%type <node> comparison_expression
%type <node> expression
%type <node> match_expression
%type <node> contain_expression
%type <node> contain_expression_attr
%type <node> contain_expression_id
%type <node> attribute_id
%type <search> pattern search_function
%type <pcontainer> pattern_container pattern_list dict_list
%type <sfp> search_func_params
%type <number> counter
 //%type <lattrs> attribute_list
 //%type <lexprs> expression_list


/* %type <node> bitwise_expression */
/* %type <node> arith_expression */

/* %type <number> counter */
/* %type <node> string_list_form */
/* %type <node> attributes_list_form */
/* %type <node> attributes_list */

/* %type <node> range_form */
/* %type <node> range_left_expression */
/* %type <node> call_expression */

/* %type <node> expression_list */

%type <node> literal
%type <node> primary

/* %type <node> string_list */
/* %type <node> string_list_item */


/* union used for all possible data types and used in lexer */
/* defined in scanner.hpp with YYSTYPE union */

/* %union { */
/*   AstNode*	node; */
/*   //void*	node; */
/*   void*	list; */
/*   void*	set; */
/*   void* range; */
/*   void*	func; */
/*   uint64_t	number; */
/*   void*	str; */
/* } */

%{

//Function declaration

%}

%start input


%%

input: boolean_expression 
{ 
  filter_ctx*	ctx = yyget_extra(yyscanner);
  ctx->root = $1; 
}
;

boolean_expression : boolean_expression AND boolean_expression { $$ = new LogicalAnd($1, $3); }
| boolean_expression OR boolean_expression { $$ = new LogicalOr($1, $3); }
| NOT boolean_expression { $$ = new LogicalNot($2); }
| '(' boolean_expression ')' { $$ = $2; }
| comparison_expression { $$ = $1; }
| match_expression { $$ = $1; }
| contain_expression { $$ = $1; }
;


pattern_container : '[' pattern_list ']' { $$ = $2; }
| DICT 
{
  try
    {
      Dictionnary* dict = DictRegistry::instance()->get(*$1);
      delete $1;
      if (($$ = new PatternDictionnary(dict)) == NULL)
	{
	  yyerror(yyscanner, NULL);
	  YYERROR;
	}
    }
  catch (std::string)
    {
      delete $1;
      yyerror(yyscanner, NULL);
      YYERROR;
    }
}
| '[' dict_list ']'
{
  $$ = $2;
}
;

dict_list: DICT 
{ 
  try
    {
      Dictionnary* dict = DictRegistry::instance()->get(*$1);
      delete $1;
      if (($$ = new PatternDictionnary(dict)) == NULL)
	{
	  yyerror(yyscanner, NULL);
	  YYERROR;
	}
    }
  catch (std::string)
    {
      delete $1;
      yyerror(yyscanner, NULL);
      YYERROR;
    }
}
| dict_list ',' DICT
{
  try
    {
      Dictionnary* dict = DictRegistry::instance()->get(*$3);
      delete $3;
      ((PatternDictionnary*)$1)->push(dict);
    }
  catch (std::string)
    {
      delete $3;
      yyerror(yyscanner, NULL);
      YYERROR;
    }
}
;

/* attribute_expression: attribute_id CONTAIN counter OF '[' expression_list ']' { $$ = new AttributeExpression($1, $3, $6); } */
/* ; */

/* properties_expression : ATTRIBUTES CONTAIN counter OF '[' attributes_list ']' { $$ = new PropertiesExpression($3, $6); } */
/* | ATTRIBUTES HAS ATTRIBUTE { $$ = new PropertiesExpression(1, $3); } */
/* ; */

/* contain_expression: attribute_id CONTAIN counter OF '[' expression_list ']' */
/* { */
/*   $$ = new AttributeExpression($1, $3, $6); */
/* } */
/* | attribute_id IN pattern_container { $$ = new AttributeExpression($1, 1, $3); } */
//| ATTRIBUTE CONTAIN counter OF '[' pattern_list ']' { $$ = new AttributeExpression($1, $3, $6); }
/* | contain_expression_id */
/* { */
/*   $$ = $1; */
/* } */
//;

contain_expression: attribute_id _IN_ pattern_container { $$ = new AttributeExpression($1, 1, $3); }
| contain_expression_attr { $$ = $1; }
| contain_expression_id { $$ = $1; }
;

contain_expression_attr: ATTRIBUTE MATCHES counter OF pattern_container
{
  Expression*	expr;
  
  if ((expr = new NamedAttribute(*$1)) != NULL)
    $$ = new AttributeExpression(expr, $3, $5);
  else
    {
      delete $1;
      delete $5;
      yyerror(yyscanner, NULL);
      YYERROR;
    }
}
/*| ATTRIBUTE CONTAIN counter OF '[' expression_list ']' */
/* { */
/*   Expression*	expr; */
  
/*   if ((expr = new NamedAttribute(*$1)) != NULL) */
/*     $$ = new AttributeExpression(expr, $3, $6); */
/*   else */
/*     { */
/*       delete $1; */
/*       delete $6; */
/*       yyerror(yyscanner, NULL); */
/*       YYERROR; */
/*     } */
/* } */
;

contain_expression_id: IDENTIFIER MATCHES counter OF pattern_container
{

  Expression*	expr;
  
  if ((expr = AttributeFactory::instance()->create(*$1)) != NULL)
    {
      delete $1;
      $$ = new AttributeExpression(expr, $3, $5);
    }
  else
    {
      delete $1;
      yyerror(yyscanner, NULL);
      YYERROR;
    }
}
| DATA MATCHES counter OF pattern_container
{
  $$ = new DataPatternCount($3, $5);
}
;

/* attribute_list : ATTRIBUTE  */
/* {  */
/*   AttributeList*	attrs; */
  
/*   if ((attrs = new AttributeList) != NULL) */
/*     { */
/*       attrs->push_back(*$1); */
/*       delete $1; */
/*     } */
/*   else */
/*     { */
/*       delete $1; */
/*       yyerror(yyscanner, NULL); */
/*       YYERROR; */
/*     } */
/* } */
/* | attribute_list ',' ATTRIBUTE  */
/* {  */
/*   ((AttributeList*)$1)->push_back(*$3); */
/*   delete $3;  */
/* } */
/* ; */

pattern_list : pattern { $$ = new PatternList($1); }
| pattern_list ',' pattern { ((PatternList*)$1)->push($3); }
;

/* expression_list : expression  */
/* {  */
/*   ExpressionList*	exprs; */
/*   if ((exprs = new ExpressionList()) != NULL) */
/*     { */
/*       exprs->push_back($1); */
/*       $$ = exprs; */
/*     } */
/*   else */
/*     { */
/*       yyerror(yyscanner, NULL); */
/*       YYERROR; */
/*     }     */
/* } */
/* | expression_list ',' expression { ((ExpressionList*)$1)->push_back($3); } */
/* ; */

match_expression : ATTRIBUTE MATCHES pattern
{
  Expression*	expr;
  
  if ((expr = new NamedAttribute(*$1)) != NULL)
    $$ = new MatchExpression(expr, $3);
  else
    {
      delete $3;
      yyerror(yyscanner, NULL);
      YYERROR;
    }    
}
| DATA MATCHES NUMBER pattern
{
  if (($$ = new DataMatches($3, $4)) == NULL)
    {
      delete $4;
      yyerror(yyscanner, NULL);
      YYERROR;
    }
}
| DATA MATCHES pattern
{
  if (($$ = new DataMatches(1, $3)) == NULL)
    {
      delete $3;
      yyerror(yyscanner, NULL);
      YYERROR;
    }
}
| IDENTIFIER MATCHES pattern
{
  Expression*	expr;
  
  if ((expr = AttributeFactory::instance()->create(*$1)) != NULL)
    {
      delete $1;
      $$ = new MatchExpression(expr, $3);
    }
  else
    {
      delete $1;
      delete $3;
      yyerror(yyscanner, NULL);
      YYERROR;
    }
}
;

attribute_id : ATTRIBUTE { $$ = new NamedAttribute(*$1); delete $1; }
| IDENTIFIER
{
  $$ = AttributeFactory::instance()->create(*$1);
  delete $1;
  if ($$ == NULL)
    {
      yyerror(yyscanner, NULL);
      YYERROR;
    }
}
;

pattern : STRING 
{ 
  Search* s = new Search(*$1, Search::CaseInsensitive, Search::Fixed);
  delete $1;
  try
    {
      s->compile();
    }
  catch (std::string)
    {
      yyerror(yyscanner, NULL);
      YYERROR;
    }
  $$ = s;
}
| REGEXP 
{
  Search* s = new Search(*$1, Search::CaseInsensitive, Search::Regexp);
  try
    {
      s->compile();
    }
  catch (std::string)
    {
      yyerror(yyscanner, NULL);
      YYERROR;
    }
  $$ = s;
  delete $1;
}
| WILDCARD 
{
  Search* s = new Search(*$1, Search::CaseInsensitive, Search::Wildcard);
  try
    {
      s->compile();
    }
  catch (std::string)
    {
      yyerror(yyscanner, NULL);
      YYERROR;
    }
  $$ = s;
  delete $1;
}
| FUZZY
{
  Search* s = new Search(*$1, Search::CaseInsensitive, Search::Fuzzy);
  try
    {
      s->compile();
    }
  catch (std::string)
    {
      yyerror(yyscanner, NULL);
      YYERROR;
    }
  $$ = s;
  delete $1;
}
| search_function
{
  try
    {
      $1->compile();
    }
  catch (std::string)
    {
      yyerror(yyscanner, NULL);
      YYERROR;
    }
  $$ = $1;
}
;

/* | range_left_expression IN range_form  */
/* { */
/*   $$ = new_range_search(yyscanner, $1, IN_RANGE, $3); */
/*   if ($$ == NULL) */
/*     { */
/*       yyerror(yyscanner, NULL); */
/*       YYERROR; */
/*     } */
/* } */

/* | range_left_expression NOT IN range_form */
/* { */
/*   $$ = new_range_search(yyscanner, $1, NOT_IN_RANGE, $4); */
/*   if ($$ == NULL) */
/*     { */
/*       yyerror(yyscanner, NULL); */
/*       YYERROR; */
/*     } */
/* } */
;


/* range_expression : range_left_expression IN range_form { $$ = new RangeIn($1, $3); } */
/* | range_left_expression NOT IN range_form { $$ = new RangeNotIn($1, $3); } */
/* ; */

comparison_expression : expression LT expression 
{ 
  Expression*	num_to_ts;
  if ((num_to_ts = check_for_timestamp($1, $3)) != NULL)
    $$ = new ComparisonExpression($1, num_to_ts, LT);
  else
    $$ = new ComparisonExpression($1, $3, LT);
}
| expression LTE expression 
{ 
  Expression*	num_to_ts;
  if ((num_to_ts = check_for_timestamp($1, $3)) != NULL)
    $$ = new ComparisonExpression($1, num_to_ts, LTE);
  else
    $$ = new ComparisonExpression($1, $3, LTE);
}
| expression GT expression 
{ 
  Expression*	num_to_ts;
  if ((num_to_ts = check_for_timestamp($1, $3)) != NULL)
    $$ = new ComparisonExpression($1, num_to_ts, GT); 
  else
    $$ = new ComparisonExpression($1, $3, GT); 
}
| expression GTE expression 
{ 
  Expression*	num_to_ts;
  if ((num_to_ts = check_for_timestamp($1, $3)) != NULL)
    $$ = new ComparisonExpression($1, num_to_ts, GTE); 
  else
    $$ = new ComparisonExpression($1, $3, GTE); 
}
| expression EQ expression 
{ 
  Expression*	num_to_ts;
  if ((num_to_ts = check_for_timestamp($1, $3)) != NULL)
    $$ = new ComparisonExpression($1, num_to_ts, EQ); 
  else
    $$ = new ComparisonExpression($1, $3, EQ); 
}
| expression NEQ expression 
{ 
  Expression*	num_to_ts;
  if ((num_to_ts = check_for_timestamp($1, $3)) != NULL)
    $$ = new ComparisonExpression($1, num_to_ts, NEQ); 
  else
    $$ = new ComparisonExpression($1, $3, NEQ); 
}
;

/* range_left_expression : IDENTIFIER */
/* { */
/*   $$ = new_identifier(yyscanner, $1); */
/*   if ($$ == NULL) */
/*     { */
/*       yyerror(yyscanner, NULL); */
/*       YYERROR; */
/*     } */
/* } */
/* | ATTRIBUTE { $$ = new_attribute(yyscanner, $1); } */
/* ; */

expression : primary { $$ = $1; }
;

/* bitwise_expression : arith_expression { $$ = $1; } */
/* | bitwise_expression LSHIFT arith_expression { $$ = new_bitwise_expression(yyscanner, $1, $2, $3); } */
/* | bitwise_expression RSHIFT arith_expression { $$ = new_bitwise_expression(yyscanner, $1, $2, $3); } */
/* | bitwise_expression BIN_AND arith_expression { $$ = new_bitwise_expression(yyscanner, $1, $2, $3); } */
/* | bitwise_expression BIN_OR arith_expression { $$ = new_bitwise_expression(yyscanner, $1, $2, $3); } */
/* | bitwise_expression BIN_XOR arith_expression { $$ = new_bitwise_expression(yyscanner, $1, $2, $3); } */
/* ; */

/* arith_expression : primary { $$ = $1; } */
/* | arith_expression arith_operator primary  */
/* { */
/*   $$ = new_arith_expression(yyscanner, $1, $2, $3); */
/*   if ($$ == NULL) */
/*     { */
/*       yyerror(yyscanner, NULL); */
/*       YYERROR; */
/*     } */
/* } */
/* ; */

/* arith_operator : PLUS { $$ = PLUS; } */
/* | MINUS { $$ = MINUS; } */
/* | MUL { $$ = MUL; } */
/* | DIV { $$ = DIV; } */
/* | MOD { $$ = MOD; } */
/* | POW { $$ = POW; } */
/* ; */

primary : literal { $$ = $1; }
| '(' expression ')' { $$ = $2; }
;


literal : NUMBER { $$ = new Number($1); }
| ATTRIBUTE { $$ = new NamedAttribute(*$1); delete $1; }
| IDENTIFIER
{
  $$ = AttributeFactory::instance()->create(*$1);
  delete $1;
  if ($$ == NULL)
    {
      yyerror(yyscanner, NULL);
      YYERROR;
    }
}
| STRING { $$ = new String(*$1); delete $1; }
| TIMESTAMP { $$ = new Timestamp(*$1); delete $1; }
| _TRUE_ { $$ = new Boolean(true); }
| _FALSE_ { $$ = new Boolean(false); }
/*| REGEXP {$$ = new Regexp(*$1); delete $1; }
| FUZZY { $$ = new Fuzzy(*$1); delete $1; }
| WILDCARD { $$ = new Wildcard(*$1); delete $1; }*/
;


/* attributes_list_form : '[' attributes_list ']' { $$ = $2; } */
/* ; */

/* attributes_list : ATTRIBUTE { $$ = new_attributes_list(yyscanner, $1); } */
/* | attributes_list ',' ATTRIBUTE { push_attribute(yyscanner, $1, $3); } //check if attribute already exists... */
/* ; */

counter: NUMBER { $$ = $1; }
| ANY { $$ = 1; }
| ALL { $$ = UINT64_MAX; }
| NONE { $$ = 0; }
;

search_function : IDENTIFIER '(' search_func_params ')'
{
  Search*	s;
  std::string	pattern;
  Search::CaseSensitivity	cs;

  s = NULL;
  pattern = *($3->pattern);
  cs = $3->cs;
  delete $3->pattern;
  free($3);
  if (*$1 == "re")
    s = new Search(pattern, cs, Search::Regexp);
  else if (*$1 == "w")
    s = new Search(pattern, cs, Search::Wildcard);
  else if (*$1 == "fz")
    s = new Search(pattern, cs, Search::Fuzzy);
  else if (*$1 == "f")
    s = new Search(pattern, cs, Search::Fixed);
  else
    {
      yyerror(yyscanner, NULL);
      YYERROR;
    }
  $$ = s;
}
;

search_func_params : STRING 
{
  sfunc_params*	sfp;
  
  sfp = NULL;
  if ((sfp = (sfunc_params*)malloc(sizeof(sfunc_params))) == NULL)
    {
      yyerror(yyscanner, NULL);
      YYERROR;
    }
  else
    {
      sfp->pattern = $1;
      sfp->cs = Search::CaseSensitive;
    }
  $$ = sfp;
}
| search_func_params ',' IDENTIFIER 
{
  if (*$3 != "i")
    {
      yyerror(yyscanner, NULL);
      YYERROR;      
    }
  else
    $1->cs = Search::CaseInsensitive;
  $$ = $1;
} 
;

/* string_list_form : '[' string_list ']' { $$ = $2; } */
/* ; */

/* string_list : string_list_item { $$ = new StringList($1); } */
/* | string_list ',' string_list_item { $1->push_back($3); } */
/* ; */

/* string_list_item : STRING { $$ = new String(*$1); delete $1; } */
/* //| call_expression { $$ = $1; } */
/* ; */

/* /\* list_form : '[' expression_list ']' {}//{ $$ = $2; } *\/ */
/* /\* ; *\/ */

/* range_form : '(' expression DOTDOT expression ')' { $$ = new_range_form(yyscanner, $2, $4); } */
/* | '(' DOTDOT expression ')' { $$ = new_range_form(yyscanner, NULL, $3); } */
/* | '(' expression DOTDOT ')' { $$ = new_range_form(yyscanner, $2, NULL); } */
/* ; */

/* expression_list : { $$ = new_expression_list(yyscanner, NULL); } */
/* | expression { $$ = new_expression_list(yyscanner, $1); } */
/* | expression_list ',' expression { push_expression(yyscanner, $1, $3); } */
/* ; */


/* rules end here */

%% 

Expression*	check_for_timestamp(Expression* lhs, Expression* rhs)
{
  TimestampAttribute*	tsattr = dynamic_cast<TimestampAttribute*>(lhs);
  Number*		numattr = dynamic_cast<Number*>(rhs);
  Expression*		ts = NULL;

  if (tsattr != NULL && numattr != NULL)
    {
      Variant*	vptr;
      if ((vptr = numattr->evaluate()) != NULL)
	{
	  try
	    {
	      uint32_t	val = vptr->value<uint32_t>();
	      ts = new Timestamp(val);
	      delete numattr;
	    }
	  catch (std::string)
	    {	      
	    }
	}
    }
  return ts;
}
