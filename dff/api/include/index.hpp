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
 *  Romain Bertholon <rbe@digital-forensic.org>
 */

#ifndef __INDEX_H__
# define __INDEX_H__

#include <string>

#include <CLucene.h>
#include <CLucene/document/Field.h>
#include <CLucene/search/SearchHeader.h>
#include "../include/node.hpp"

namespace DFF
{

class	AttributeIndex : public AttributesHandler
{
public:
  AttributeIndex(std::string name, std::string query);

  virtual Attributes 	attributes(class Node*);

private:
  std::string	__query;
};

class	Index
{
  /*!
    \class Index
    \brief Indexing the content of Nodes.

    The purpose of this class is to create an index which will index the content
    of Nodes so reIndexSearch using key words can be performed.
  */

public:
  //! Create an index object.
  EXPORT Index();

  /*! 
    \brief Create an index object.
    \param location the path to the index file
  */
  EXPORT Index(const std::string & location);

  //! Destructor. Free resources.
  EXPORT ~Index();

  /*!
    \brief Create the index.
    If the location is empty, try to create it at the default location.
    \return true if the creattion did not met any errors, False otherwise.
  */
  EXPORT bool			createIndex();
  
  /*!
    \brief Close the open index.
    Optimize and close the IndexWriter. Does nothing if the index is not opened.
  */
  EXPORT void			closeIndex();

  //! \return the location of the index
  const std::string &	location() const;

  //! \param location the path to the index file
  void			setLocation(const std::string & location);

  /*!
    \brief Add a document to the index.
    Does nothing if the index is not opened.
    \param doc the document which must be added.
  */
  void			addDocument(lucene::document::Document * doc);

  /*! \brief Create a new document.
    The caller musts clean the document when he does not need it anymore.
    \return a pointer to the instance of the Document class, or NULL if something
    went wrong.
  */

  lucene::document::Document *	newDocument();

  /*! \brief Index data.

    Index the content of the Node ``data``.

    \param data the node which content musts be indexed.
    \return true if the indexing went fine, false otherwise.
  */
  EXPORT bool			indexData(Node * data);

  /*!
    \return a pointer to the Document instance associated with the Index.
  */
  lucene::document::Document *	document() const;

  /*!
    Associate a document with the Index.
    \param doc a pointer to the document instance.
  */
  void			setDocument(lucene::document::Document * doc);

  void	setIndexContent(bool index);
  void	setIndexAttr(bool index);

private:
  void			__indexContent(Node * data, lucene::document::Field * content);

  std::string			__location;
  lucene::index::IndexWriter *		__writer;
  lucene::document::Document *		__doc;
  lucene::analysis::standard::StandardAnalyzer *	__an;
  lucene::document::Field *		__content;
  bool	index_content, index_attr;

};

class	IndexSearch
{
  /*!
    \class IndexSearch
    \brief This class is used to search a keyword in an index.

  */
public:
  //! Constructor.
  IndexSearch();

  /*! 
    \brief Constructor
    \param location the path to the directory where the index file is located.
  */
  IndexSearch(const std::string & location);

  //! Descructor. Free resources.
  ~IndexSearch();

  /*!
    \brief Do the search.
    
    This method do the search within the indexed content. If params '''query''' and
    '''must_contain_query''' are empty, does nothing.

    Once the search is done, the result will be accessible through a node callled
    '''Search::<terms of the search>''', located in the node '''Searched Items''', itself
    located at the root of the VFS (this '''Searched Items''' node is always created when DFF
    is launched).
 
    The two parameters can be a word or a list of words separated by spaces. If '''query'''
    is not empty, the search will retrieved all data containing at least one of the word
    contained in query. It acts as a logical OR.

    If the parameter '''must_contain_query''' is not empty, the research will return the data
    where all the words of '''must_contain_query''' were found. It acts as a logical AND.
    
    \param query a basic query composed of a word or a list of word separated by spaces.
    \param must_contain_query a query composed of a words or a liste of words separated by spaces. All
    the world of the query will be in each found results.
  */
  void	exec_query(const std::string & query,
		   const std::string & must_contain_query = "");
  char*		narrow( const wstring& str );

  static bool	deleteDoc(std::string path, std::string location);

private:
  void		__displayResults(lucene::search::Hits *  h);
  Node *	__newIndexation(Node * root);
  lucene::search::Query * __getMultiSearchQuery(const std::string & query,
						lucene::analysis::standard::StandardAnalyzer * an);

  std::string	__query;
  std::string	__must;
  std::string	__location;
};

}
#endif /* __INDEX_H__*/
