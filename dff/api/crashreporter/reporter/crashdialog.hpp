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


#ifndef __CRASHDIALOG_HPP__
#define __CRASHDIALOG_HPP__

#include <QDialog>
#include <QGroupBox>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QFrame>
#include <QCheckBox>
#include <QSizePolicy>
#include <Qt>
#include <QPushButton>
#include <QTextEdit>
#include <QLineEdit>
#include <QRegExp>
#include <QMessageBox>

class CrashDialog : public QDialog
{
  Q_OBJECT

private:
  std::string	__version;
  std::string	__minidumpPath;
  std::string	__details;
  QGridLayout*	__layout;
  QHBoxLayout*	__buttonsLayout;
  QLabel*	__crashLabel;
  QGroupBox*	__reportBox;
  QPushButton*	__reportDetails;
  QTextEdit*	__userComment;
  QGroupBox*	__contactBox;
  QLineEdit*	__email;
  QGroupBox*	__proxyBox;
  QLineEdit*	__proxyHost;
  QLineEdit*	__proxyUser;
  QLineEdit*	__proxyPassword;
  QPushButton*	__quit;
  QPushButton*	__restart;

  void		__createReportBox();
  void		__createContactBox();
  void		__createProxyBox();
  void		__createButtons();
  bool		__sanitize();
	     
public slots:
  void		quit(void);
  void		restart(void);
  void		showDetails(void);

public:
  enum
    {
      Exit = 0,
      Restart = 1
    } ExitType;
  CrashDialog();
  ~CrashDialog();
  void		setVersion(std::string);
  void		setMinidumpPath(std::string);
  std::string	details();
  void		setDetails(std::string);
  bool		reportEnabled();
  bool		contactEnabled();
  std::string	email();
  std::string	userComment();
  bool		proxyEnabled();
  std::string	proxyHost();
  std::string	proxyUser();
  std::string	proxyPassword();
};


#endif
