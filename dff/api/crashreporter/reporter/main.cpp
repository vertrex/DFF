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

#include <string.h>
#include <stdio.h>
#include <iostream>
#include <string>

#include "crashdialog.hpp"
#include "crashreporter.hpp"
#include "crashdumpinfo.hpp"

#include <QApplication>
#include <QDesktopWidget>
#include <QObject>

void		sendDump(int argc, char* argv[], char* version, char* path, char* silent);
void		usage();
void		parseArguments(int argc, char* argv[], char** version, char** path, char** silent);
void		silentReport(char* version, CrashDumpInfo* cinfo);
void		guiReport(int argc, char* argv[], char* version, CrashDumpInfo* cinfo);


int		main(int argc, char* argv[])
{
  char*		path;
  char*		version;
  char*		silent;
 
  path = NULL;
  version = NULL;
  silent = NULL;
  parseArguments(argc, argv, &version, &path, &silent);
  sendDump(argc, argv, version, path, silent);
}


void	parseArguments(int argc, char* argv[], char** version, char** path, char** silent)
{
  int	i;

  if (argc != 7)
    usage();
  for (i = 0; i != 7; i++)
    {
      if ((strncmp(argv[i], "-p", 2) == 0) && i < 7 && (strncmp(argv[i+1], "-v", 2) != 0) && (strncmp(argv[i+1], "-s", 2) != 0))
	*path = argv[i+1];
      if ((strncmp(argv[i], "-v", 2) == 0) && i < 7 && (strncmp(argv[i+1], "-p", 2) != 0) && (strncmp(argv[i+1], "-s", 2) != 0))
	*version = argv[i+1];
      if ((strncmp(argv[i], "-s", 2) == 0) && i < 7 && (strncmp(argv[i+1], "-p", 2) != 0) && (strncmp(argv[i+1], "-v", 2) != 0))
	*silent = argv[i+1];
    }
  if (version == NULL || path == NULL || silent == NULL)
    usage();
}


void	usage()
{
  std::cout << "usage: CrashReporter -v version -p path -s [0|1]" << std::endl;
  exit(1);
}


void			sendDump(int argc, char* argv[], char* version, char* path, char* silent)
{
  CrashDumpInfo*	cinfo;
  
  cinfo = new CrashDumpInfo();
  try
    {
      cinfo->process(path);
    }
  catch (std::string err)
    {
      std::cout << err << std::endl;
      exit(1);
    }
  if (strncmp(silent, "1", 1) == 0)
    silentReport(version, cinfo);
  else
    guiReport(argc, argv, version, cinfo);
}


void	silentReport(char* version, CrashDumpInfo* cinfo)
{
  CrashReporter*	reporter;
  std::string		msg;

  reporter = createCrashReporter();
  reporter->setMinidumpPath(cinfo->minidumpPath());
  reporter->setVersion(version);
  reporter->setComment("Silent report");
  if (!reporter->sendReport())
    { 
      msg = "Error while uploading dump " + reporter->minidumpPath();
      msg += "\nYou can send it by mail at the following address : contact@arxsys.fr";
      std::cout << msg << std::endl;
    }
  else
    {
      msg = "Dump " + reporter->minidumpPath() + " successfully uploaded";
      msg += "\nand is available at " + reporter->viewUrl();
      msg += "\n\nThanks for your support!";
      std::cout << msg << std::endl;
    }  
}


void	guiReport(int argc, char* argv[], char* version, CrashDumpInfo* cinfo)
{
  CrashDialog*		cdialog;
  CrashReporter*	reporter;
  std::string		msg;
  int			ret;
  
  QApplication app(argc, argv, true);
  cdialog = new CrashDialog();
  cdialog->setDetails(cinfo->details());
  cdialog->setVersion(version);
  cdialog->setMinidumpPath(cinfo->minidumpPath());
  ret = cdialog->exec();
  if (cdialog->reportEnabled())
    {
      reporter = createCrashReporter();
      reporter->setMinidumpPath(cinfo->minidumpPath());
      reporter->setVersion(version);
      reporter->setComment(cdialog->userComment());
      if (cdialog->proxyEnabled())
	{
	  reporter->setProxyHost(cdialog->proxyHost());
	  reporter->setProxyUser(cdialog->proxyUser());
	  reporter->setProxyPassword(cdialog->proxyPassword());
	}
      if (!reporter->sendReport())
	{ 
	  msg = "Error while uploading dump " + reporter->minidumpPath();
	  msg += "\nYou can send it by mail at the following address : contact@arxsys.fr";
	  QMessageBox::critical(QDesktopWidget().screen(), "Crash Reporter", QObject::tr(msg.c_str()));
	}
      else
	{
	  msg = "Dump " + reporter->minidumpPath() + " successfully uploaded";
	  msg += "\nand is available at " + reporter->viewUrl();
	  msg += "\n\nThanks for your support!";
	  QMessageBox::information(QDesktopWidget().screen(), "Crash Reporter", QObject::tr(msg.c_str()));
	}
    }
  if (ret == CrashDialog::Exit)
    exit(1);
}
