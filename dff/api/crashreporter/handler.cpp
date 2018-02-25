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
 *  Solal J. <sja@digital-forensic.org>
 */

#include "handler.hpp"

#include <iostream>
#include <string>

#ifndef WIN32
  #include "client/linux/handler/exception_handler.h"
#else
  #include "client/windows/handler/exception_handler.h"
#endif

#define ReportExecutable "CrashReporter"

#ifndef WIN32

#include <unistd.h>

static bool dumpCallback(const google_breakpad::MinidumpDescriptor& descriptor,
                         void* context,
                         bool succeeded)
{
  pid_t		pid;
  char**	cargs;

  pid = fork();
  if (pid == -1)
    {
      printf("Cannot fork. Please send the following crash report to contact@arxsys.fr:\n%s\n", descriptor.path());
      return false;
    }
  else if (pid == 0)
    {
      cargs = (char**)context;
      execl("dff/api/crashreporter/reporter/CrashReporter", "CrashReporter", "-p", descriptor.path(), "-v", cargs[0], "-s", cargs[1], NULL);
      exit(1);
    }
  return succeeded;
}

#else

#include <windows.h>
#include <stdio.h>
#include <tchar.h>	
	
bool	dumpCallback(const wchar_t* _dump_dir, const wchar_t* _minidump_id, void* context, EXCEPTION_POINTERS* exinfo, MDRawAssertionInfo* assertion, bool success)
{
  STARTUPINFO		si;
  PROCESS_INFORMATION	pi;
  
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));
  std::string* cargs = (std::string*)context;
  std::wstring args(L"CrashReporter -p ");
  args += std::wstring(_dump_dir);
  args += std::wstring(_minidump_id);
  args += std::wstring(L".dmp");
 args += std::wstring(cargs->begin(), cargs->end());
 std::wcout << args << std::endl;
 if (!CreateProcessW(L"dff\\api\\crashreporter\\reporter\\CrashReporter.exe",
		      (LPWSTR)args.c_str(),
		      NULL, NULL, FALSE, 0, NULL, NULL, (LPSTARTUPINFOW)&si, &pi))
    {
      printf("Create Process failed (%d)\n", GetLastError());
      TerminateProcess(GetCurrentProcess(), 1);
      return false;
    }
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return true;
}

#endif


CrashHandler::CrashHandler() : __silent(false), __version(""), __eh(NULL)
{
}


CrashHandler::~CrashHandler()
{
}


void	CrashHandler::setSilentReport(bool silent)
{
  this->__silent = silent;
}


void	CrashHandler::setVersion(std::string version)
{
  this->__version = version;
}

#ifndef WIN32
void	CrashHandler::setHandler()
{
    char**	cargs;

  cargs = NULL;
  if ((cargs = (char**)calloc(2, sizeof(char*))) != NULL)
    {
      if ((cargs[0] = (char*)calloc(this->__version.size()+1, sizeof(char))) != NULL)
	memcpy(cargs[0], this->__version.c_str(), this->__version.size());
      else
	return; //XXX No handler set
      if ((cargs[1] = (char*)calloc(2, sizeof(char))) != NULL)
	{
	  if (this->__silent)
	    *(cargs[1]) = '1';
	  else
	    *(cargs[1]) = '0';
	}
      else
	return; //XXX No handler set
    }
  else
    return; //XXX No handler set

  google_breakpad::MinidumpDescriptor descriptor("/tmp");
  this->__eh = new google_breakpad::ExceptionHandler(descriptor,
						     NULL,//DmpFilter,
						     dumpCallback,
						     (void*)cargs,
						     true,
						     -1);
}

#else 
void	CrashHandler::setHandler()
{
  TCHAR tempPath[1024];
  std::wstring wpath;
  std::string	*args = new std::string(" -v ");
  args->append(this->__version);
  if (this->__silent)
    args->append(" -s 1 ");
  else
    args->append(" -s 0 ");
  GetTempPath(1024, tempPath);
  wpath = std::wstring(tempPath);
  this->__eh = new google_breakpad::ExceptionHandler(wpath,
						     NULL,//DmpFilter,
						     dumpCallback,//DmpCallback
						     (void*)args,
						     true);
}
#endif


void	CrashHandler::unsetHandler()
{
}
