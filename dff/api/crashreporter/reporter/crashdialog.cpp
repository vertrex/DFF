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


#include "crashdialog.hpp"

#include <iostream>

CrashDialog::CrashDialog() : __version(""), __minidumpPath(""), __details(""), __layout(NULL),
			     __buttonsLayout(NULL), __crashLabel(NULL), __reportBox(NULL), 
			     __reportDetails(NULL), __userComment(NULL), __contactBox(NULL), 
			     __email(NULL), __proxyBox(NULL), __proxyHost(NULL), __proxyUser(NULL), 
			     __proxyPassword(NULL), __quit(NULL), __restart(NULL)
{
  this->__layout = new QGridLayout;
  this->setLayout(this->__layout);

  this->__crashLabel = new QLabel(this);
  this->__crashLabel->setText(tr("We are sorry!\n\nDFF had a problem and has unexpectedly quit. Please take a moment to send us this crash report.\n\nIt will help us diagnose and fix the problem to make DFF as stable and reliable as possible.\n"));
  this->__crashLabel->setAlignment(Qt::AlignTop | Qt::AlignLeft);
  this->__crashLabel->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Minimum);
  this->__crashLabel->setWordWrap(true);
  this->__layout->addWidget(this->__crashLabel, 0, 0);
  
  this->__createReportBox();
  this->__layout->addWidget(this->__reportBox, 1, 0);
  
  this->__createButtons();
  this->__layout->addLayout(this->__buttonsLayout, 2, 0, Qt::AlignRight);
}


CrashDialog::~CrashDialog()
{
}


void	CrashDialog::setVersion(std::string version)
{
  this->__version = version;
}


void	CrashDialog::setMinidumpPath(std::string path)
{
  this->__minidumpPath = path;
}


void	CrashDialog::setDetails(std::string details)
{
  this->__details = details;
}


std::string	CrashDialog::details()
{
  std::string	result;

  result = "Version: " + this->__version;
  result += "\nMinidump path: " + this->__minidumpPath;
  result += "\n" + this->__details;
  return result;
}


bool	CrashDialog::reportEnabled()
{
  return this->__reportBox->isChecked();
}


bool	CrashDialog::contactEnabled()
{
  return this->__contactBox->isChecked();
}


std::string	CrashDialog::email()
{
  return this->__email->text().toStdString();
}


std::string	CrashDialog::userComment()
{
  return this->__userComment->toPlainText().toStdString();
}


bool		CrashDialog::proxyEnabled()
{
  return this->__proxyBox->isChecked();
}


std::string		CrashDialog::proxyHost()
{
  return this->__proxyHost->text().toStdString();
}


std::string		CrashDialog::proxyUser()
{
  return this->__proxyUser->text().toStdString();
}


std::string		CrashDialog::proxyPassword()
{
  return this->__proxyPassword->text().toStdString();
}


void	CrashDialog::quit(void)
{
  if (this->__sanitize())
    this->done(CrashDialog::Exit);
}


void	CrashDialog::restart(void)
{
  if (this->__sanitize())
    this->done(CrashDialog::Restart);
}


void	CrashDialog::showDetails(void)
{
  QMessageBox::information(this, QString(tr("Details informations")), QString(this->details().c_str()));
}


void	CrashDialog::__createReportBox()
{
  QVBoxLayout*	vbox;
  QLabel*	commentLabel;

  vbox = new QVBoxLayout;
  this->__reportBox = new QGroupBox(tr("Tell ArxSys about this crash so they can fix it"), this);
  this->__reportBox->setCheckable(true);
  this->__reportBox->setChecked(true);
  this->__reportBox->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Minimum);
  this->__reportBox->setLayout(vbox);

  this->__reportDetails = new QPushButton(tr("Details..."), this);
  this->__reportDetails->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Preferred);
  this->__reportDetails->setMaximumWidth(100);
  connect(this->__reportDetails, SIGNAL(clicked(bool)), this, SLOT(showDetails(void)));  
  vbox->addWidget(this->__reportDetails);

  commentLabel = new QLabel(tr("Add a comment (comments are publicly visible)"), this);
  vbox->addWidget(commentLabel);
  this->__userComment = new QTextEdit(this);
  this->__userComment->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);
  this->__userComment->setAcceptRichText(false);
  vbox->addWidget(this->__userComment);

  this->__createContactBox();
  vbox->addWidget(this->__contactBox);

  this->__createProxyBox();
  vbox->addWidget(this->__proxyBox);
}


void	CrashDialog::__createContactBox()
{
  QHBoxLayout*	hbox;
  
  hbox = new QHBoxLayout;
  this->__contactBox = new QGroupBox(tr("Allow ArxSys to contact me about this report"), this);
  this->__contactBox->setCheckable(true);
  this->__contactBox->setChecked(false);
  this->__contactBox->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Minimum);
  this->__contactBox->setLayout(hbox);
  this->__email = new QLineEdit(this);
  this->__email->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Minimum);
  this->__email->setPlaceholderText(tr("Enter your email address (email is publicly visible)"));
  hbox->addWidget(this->__email);
}


void	CrashDialog::__createProxyBox()
{
  QGridLayout*	groupbox;
  QLabel*	hostLabel;
  QLabel*	userLabel;
  QLabel*	pwdLabel;

  groupbox = new QGridLayout;
  this->__proxyBox = new QGroupBox(tr("Proxy information"));
  this->__proxyBox->setCheckable(true);
  this->__proxyBox->setChecked(false);
  this->__proxyBox->setLayout(groupbox);

  hostLabel = new QLabel(tr("&Proxy host"));
  this->__proxyHost = new QLineEdit();
  hostLabel->setBuddy(this->__proxyHost);
  groupbox->addWidget(hostLabel, 0, 0);
  groupbox->addWidget(this->__proxyHost, 0, 1);

  userLabel = new QLabel(tr("&Username"));
  this->__proxyUser = new QLineEdit();
  userLabel->setBuddy(this->__proxyUser);
  groupbox->addWidget(userLabel, 1, 0);
  groupbox->addWidget(this->__proxyUser, 1, 1);

  pwdLabel = new QLabel(tr("Pass&word"));
  this->__proxyPassword = new QLineEdit();
  this->__proxyPassword->setEchoMode(QLineEdit::Password);
  pwdLabel->setBuddy(this->__proxyPassword);
  groupbox->addWidget(pwdLabel, 2, 0);
  groupbox->addWidget(this->__proxyPassword, 2, 1);  
}


void	CrashDialog::__createButtons()
{
  this->__buttonsLayout = new QHBoxLayout;
  
  this->__quit = new QPushButton(tr("Quit"));
  this->__quit->setMaximumWidth(100);
  connect(this->__quit, SIGNAL(clicked(bool)), this, SLOT(quit(void)));

  this->__restart = new QPushButton(tr("Restart"));
  this->__restart->setMaximumWidth(100);
  this->__restart->hide();
  connect(this->__restart, SIGNAL(clicked(bool)), this, SLOT(restart(void)));

  this->__buttonsLayout->addWidget(this->__quit);
  this->__buttonsLayout->addWidget(this->__restart);
}


bool	CrashDialog::__sanitize()
{
  if (this->reportEnabled())
    {
      if (this->contactEnabled() && (this->__email->text().isEmpty() || !this->__email->text().contains(QRegExp(".+@.+"))))
	{
	  QMessageBox::critical(this, tr("Invalid information"), tr("Please, provide valid email address."));
	  return false;
	}
      if (this->proxyEnabled())
	{
	  if (this->__proxyHost->text().isEmpty())
	    {
	      QMessageBox::critical(this, tr("Invalid information"), tr("Please provide valid proxy host address."));
	      return false;
	    }
	  if (this->__proxyUser->text().isEmpty())
	    {
	      QMessageBox::critical(this, tr("Invalid information"), tr("Please provide a proxy username."));
	      return false;
	    }
	  if (this->__proxyPassword->text().isEmpty())
	    {
	      QMessageBox::critical(this, tr("Invalid information"), tr("Please provide a proxy password."));
	      return false;
	    }
	}
    }
  return true;
}
