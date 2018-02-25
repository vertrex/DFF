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


#ifndef __CRASHREPORTER_HPP__
#define __CRASHREPORTER_HPP__

#include <string>

#ifndef WIN32
  #include "common/linux/google_crashdump_uploader.h"
#else
  #include "common/windows/http_upload.h"
#endif

#define DEFAULT_CRASH_HOST "http://crash.arxsys.fr"

class CrashReporter
{
private:
  std::string	__path;
  std::string	__version;
  std::string	__host;
  std::string	__email;
  std::string	__comment;
  std::string	__proxyHost;
  std::string	__proxyUser;
  std::string	__proxyPassword;

protected:
  int		_httpStatusCode;
  std::string	_httpResponseHeader;
  std::string	_httpResponseBody;

public:
  CrashReporter();
  virtual ~CrashReporter();
  void			setMinidumpPath(std::string path);
  std::string		minidumpPath();
  void			setVersion(std::string version);
  std::string		version();
  void			setHostAddress(std::string host);
  std::string		hostAddress();
  std::string		postAddress();
  void			setEmail(std::string email);
  std::string		email();
  void			setComment(std::string comment);
  std::string		comment();
  void			setProxyHost(std::string proxyhost);
  std::string		proxyHost();
  void			setProxyUser(std::string proxyuser);
  std::string		proxyUser();
  void			setProxyPassword(std::string proxypassword);
  std::string		proxyPassword();
  std::string		proxyUserAndPassword();
  int			httpStatusCode();
  std::string		httpResponseHeader();
  std::string		httpResponseBody();
  std::string		viewUrl();
  virtual bool		sendReport() throw (std::string) = 0;
  virtual bool		deleteDump() throw (std::string) = 0;
};

#if defined(__gnu_linux__) || defined(__linux__) || defined(__unix__)

class LinuxCrashReporter : public CrashReporter
{
public:
  LinuxCrashReporter();
  ~LinuxCrashReporter();
  virtual bool	sendReport() throw (std::string);
  virtual bool	deleteDump() throw (std::string);
};

#elif _WIN32

class WindowsCrashReporter : public CrashReporter
{
public:
  WindowsCrashReporter();
  ~WindowsCrashReporter();
  virtual bool	sendReport() throw (std::string);
  virtual bool	deleteDump() throw (std::string);  
};

#endif

CrashReporter*	createCrashReporter();

#endif
