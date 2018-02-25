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
 *  Solal Jacob <sja@digital-forensic.org>
 *  Christophe Malinge <cma@digital-forensic.org>
 */

#include "local.hpp"
#include "typesconv.hpp"

#include <String>
#include <windows.h>
#include <shlwapi.h>

#include "vfs.hpp"
#include "path.hpp"
#include "exceptions.hpp"

void        local::frec(const char *name, Node *rfv)
{
  HANDLE      hd;
  WIN32_FIND_DATAA  find;
  std::string    nname;
  std::string    searchPath = name;
  s_ull        sizeConverter;
  
  searchPath +=  "\\*";  
  
  if ((hd = FindFirstFileA(searchPath.c_str(), &find)) != INVALID_HANDLE_VALUE) 
  {
    do 
    {
      WLocalNode  *tmp;
   
      if (!strcmp(find.cFileName, ".") || !strcmp(find.cFileName, ".."))
        continue ;    
      nname = name;
      nname += "\\";
      nname += find.cFileName;

      if (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) 
      {
        tmp = new WLocalNode(std::string(find.cFileName), 0, rfv, this, WLocalNode::DIR, nname);
        this->frec((char *)nname.c_str(), tmp);
      }
      else 
      {
        sizeConverter.Low = find.nFileSizeLow;
        sizeConverter.High = find.nFileSizeHigh;
        tmp = new WLocalNode(std::string(find.cFileName), sizeConverter.ull, rfv, this, WLocalNode::FILE, nname);
      }
    } while (FindNextFileA(hd, &find));
    
    FindClose(hd);
  }
}

local::local(): fso("local"), nfd(0), parent(NULL)
{
}

local::~local()
{
}

void            local::start(std::map<std::string, Variant_p > args)
{
  std::list<Variant_p >              paths;
  std::map<std::string, Variant_p>::iterator        argit;

  if ((argit = args.find("parent")) != args.end())
    this->parent = argit->second->value<Node*>();
  else
    this->parent = VFS::Get().GetNode("/");
  if ((argit = args.find("path")) != args.end())
  {
    paths = argit->second->value<std::list < Variant_p > >();
      if (paths.size() == 0)
    throw (envError("local module requires at least one path parameter"));
  }
  else
    throw (envError("local modules requires path argument"));
  
  std::list<Variant_p >::iterator  path = paths.begin();
  for  (; path != paths.end(); ++path)
  {
    this->createPath(((*path)->value<Path*>())->path);
  }
}

std::string local::relativePath(std::string path)
{
  std::string relPath;

  while (path.find('/') != std::string::npos) 
  {
    path[path.find('/')] = '\\';
  }
  if ((path.rfind('/') + 1) == path.length())
    path.resize(path.rfind('/'));
  if ((path.rfind('\\') + 1) == path.length())
    path.resize(path.rfind('\\'));
  relPath = path;
  if (relPath.rfind("\\") <= relPath.size())
    relPath = relPath.substr(relPath.rfind("\\") + 1);
  else 
  relPath = relPath.substr(relPath.rfind("/") + 1);

  return (relPath);
}

void  local::createPath(std::string origPath)
{
  WIN32_FILE_ATTRIBUTE_DATA  info;
  s_ull            sizeConverter;


  int length = MultiByteToWideChar(CP_UTF8, 0, origPath.data(), origPath.length(), NULL, 0);
  std::wstring path;
  path.resize(length);
  MultiByteToWideChar(CP_UTF8, 0, origPath.data(), origPath.length(), &path[0], path.length());
  if(!GetFileAttributesEx((LPCWSTR)path.c_str(), GetFileExInfoStandard, &info))
    {
      // DWORD dw = GetLastError();
      // LPVOID	buffer = NULL;
      // FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dw, 0, (LPTSTR)&buffer, 0, NULL);
      // wprintf(L"%s\n", (LPCTSTR)buffer);
      res["error"] = Variant_p(new Variant(std::string("error stating file: " + origPath)));
      return ;
  }
  if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
  {  
    WLocalNode* node = new WLocalNode(this->relativePath(origPath), 0, NULL, this, WLocalNode::DIR, origPath);  
    this->frec(origPath.c_str(), node);
    this->registerTree(this->parent, node);
  }
  else 
  {
    sizeConverter.Low = info.nFileSizeLow;
    sizeConverter.High = info.nFileSizeHigh;
    WLocalNode* node = new WLocalNode(this->relativePath(origPath), sizeConverter.ull, NULL, this, WLocalNode::FILE, origPath);
    this->registerTree(this->parent, node);
  }
  
  return ;
}

int local::vopen(Node *wnode)
{
  WLocalNode*  node =  dynamic_cast<WLocalNode *>(wnode);
  if (node != NULL) 
  {
    std::string  filePath = node->originalPath;
    int length = MultiByteToWideChar(CP_UTF8, 0, filePath.data(), filePath.length(), NULL, 0);
    std::wstring path;
    path.resize(length);
    MultiByteToWideChar(CP_UTF8, 0, filePath.data(), filePath.length(), &path[0], path.length());
    return ((int)CreateFile((LPCWSTR)path.c_str(), GENERIC_READ, FILE_SHARE_READ,
			    0, OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL, 0));

  }
  else
    return (-1);
}

int local::vread(int fd, void *buff, unsigned int size)
{
  DWORD readed;
  
  if (ReadFile((HANDLE)fd, buff, size,  &readed ,0))
    return (readed);
  else
    return (0);
}

int local::vclose(int fd)
{
  return (!CloseHandle((HANDLE)fd));
}

uint64_t  local::vseek(int fd, uint64_t offset, int whence)
{ 
  s_ull        sizeConverter;
  sizeConverter.ull = offset;  
  
  if (whence == 0)
    whence = FILE_BEGIN;
  else if (whence == 1)
    whence = FILE_CURRENT;
  else if (whence == 2)
    whence = FILE_END; 
  return (SetFilePointer((HANDLE)fd, sizeConverter.Low, ((long*)&sizeConverter.High), whence)); 
}

uint64_t  local::vtell(int32_t fd)
{
  uint64_t  pos;

  pos = this->vseek(fd, 0, 1);
  return pos;
}

unsigned int local::status(void)
{
  return (nfd);
}

