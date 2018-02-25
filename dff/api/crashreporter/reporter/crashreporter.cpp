// DFF -- An Open Source Digital Forensics Framework
// Copyright (C) 2009-2015 ArxSys
// This program is free software, distributed under the terms of
// the GNU General Public License Version 2. See the LICENSE file
// at the top of the source tree.
 
// See http://www.digital-forensic.org for more information about this
// project. Please do not directly contact any of the maintainers of
// DFF for assistance; the project provides a web site, mailing lists
// and IRC channels for your use.

// Author(s):
//  Frederic Baguelin <fba@digital-forensic.org>


#include "crashreporter.hpp"
#include <string>
#include <map>
#include <iostream>


CrashReporter*	createCrashReporter()
{
#if defined(__gnu_linux__) || defined(__linux__) || defined(__unix__)
  return new LinuxCrashReporter();
#elif WIN32
  return new WindowsCrashReporter();
#else
  throw std::string("Not yet implemented");
#endif  
}


CrashReporter::CrashReporter() : __path(""), __version(""), __host(DEFAULT_CRASH_HOST), __email(""), __comment(""), __proxyHost(""), __proxyUser(""), __proxyPassword(""), _httpStatusCode(0), _httpResponseHeader(""), _httpResponseBody("")
{
}


CrashReporter::~CrashReporter()
{
}


void		CrashReporter::setMinidumpPath(std::string path)
{
  this->__path = path;
}


std::string	CrashReporter::minidumpPath()
{
  return this->__path;
}


void		CrashReporter::setVersion(std::string version)
{
  this->__version = version;
}


std::string	CrashReporter::version()
{
  return this->__version;
}


void		CrashReporter::setHostAddress(std::string host)
{
  this->__host = host;
}


std::string	CrashReporter::hostAddress()
{
  return this->__host;
}


std::string		CrashReporter::postAddress()
{
  std::string		postaddr;

  postaddr = "";
  if (this->__host.find("/post") == std::string::npos)
    postaddr = this->__host + "/post";
  else
    postaddr = this->__host;
  return postaddr;
}

void		CrashReporter::setEmail(std::string email)
{
  this->__email = email;
}


std::string	CrashReporter::email()
{
  return this->__email;
}


void		CrashReporter::setComment(std::string comment)
{
  this->__comment = comment;
}


std::string	CrashReporter::comment()
{
  return this->__comment;
}


void		CrashReporter::setProxyHost(std::string proxyhost)
{
  this->__proxyHost = proxyhost;
}


std::string	CrashReporter::proxyHost()
{
  return this->__proxyHost;
}


void		CrashReporter::setProxyUser(std::string proxyuser)
{
  this->__proxyUser = proxyuser;
}


std::string	CrashReporter::proxyUser()
{
  return this->__proxyUser;
}


void		CrashReporter::setProxyPassword(std::string proxypassword)
{
  this->__proxyPassword = proxypassword;
}


std::string	CrashReporter::proxyPassword()
{
  return this->__proxyPassword;
}


std::string	CrashReporter::proxyUserAndPassword()
{
  std::string	userpwd;

  userpwd = this->__proxyUser + ":" + this->__proxyPassword;
  return userpwd;
}


int			CrashReporter::httpStatusCode()
{
  return this->_httpStatusCode;
}


std::string		CrashReporter::httpResponseHeader()
{
  return this->_httpResponseHeader;
}


std::string		CrashReporter::httpResponseBody()
{
  return this->_httpResponseBody;
}


std::string		CrashReporter::viewUrl()
{
  std::string		vurl;

  vurl = DEFAULT_CRASH_HOST;
  return vurl + "/view/" + this->_httpResponseBody;
}


#if defined(__gnu_linux__) || defined(__linux__) || defined(__unix__)


LinuxCrashReporter::LinuxCrashReporter()
{
}


LinuxCrashReporter::~LinuxCrashReporter()
{
}


bool	LinuxCrashReporter::sendReport() throw (std::string)
{  
  google_breakpad::GoogleCrashdumpUploader g("DFF",
                                             this->version(),
                                             "0",
                                             "0",
                                             "0",
                                             this->email(),
                                             this->comment(),
                                             this->minidumpPath(),
					     this->postAddress(),
                                             this->proxyHost(),
					     this->proxyUserAndPassword());
  return g.Upload(&this->_httpStatusCode, &this->_httpResponseHeader, &this->_httpResponseBody);
}


bool	LinuxCrashReporter::deleteDump() throw (std::string)
{
  return false;
}


#elif defined(WIN32)

WindowsCrashReporter::WindowsCrashReporter()
{
}


WindowsCrashReporter::~WindowsCrashReporter()
{
}


std::wstring	stringToWstring(std::string input)
{
  std::wstring	output;
  
  return output.assign(input.begin(), input.end());
}


bool	WindowsCrashReporter::sendReport() throw (std::string)
{
  std::map<std::wstring, std::wstring>	params;
  std::wstring				rcode;
  bool					success;
  
  params[L"comments_"] = stringToWstring(this->comment());
  params[L"email"] = stringToWstring(this->email());
  params[L"ver"] = stringToWstring(this->version());
  params[L"prod"] = L"DFF";
  success = google_breakpad::HTTPUpload::SendRequest(stringToWstring(this->postAddress()),
						     params, stringToWstring(this->minidumpPath()), L"upload_file_minidump", NULL, &rcode,
						     &this->_httpStatusCode);
  if (success)
    this->_httpResponseBody = std::string(rcode.begin(), rcode.end());
  return success;
}  


bool	WindowsCrashReporter::deleteDump() throw (std::string)
{
  return false;
}

#endif
