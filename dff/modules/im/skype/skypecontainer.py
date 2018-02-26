# -*- coding: utf-8 -*-
# DFF -- An Open Source Digital Forensics Framework
#
# This program is free software, distributed under the terms of
# the GNU General Public License Version 2. See the LICENSE file
# at the top of the source tree.
# 
# See http://www.digital-forensic.org for more information about this
# project. Please do not directly contact any of the maintainers of
# DFF for assistance; the project provides a web site, mailing lists
# and IRC channels for your use.
# 
# Author(s):
#  Solal Jacob <sja@arxsys.fr>
#
from abc import ABCMeta, abstractmethod

from dff.api.report.manager import ReportManager
from dff.api.report.fragments import TableFragment, ChatFragment

from dff.modules.analyse.analyse import Translator

from chatsync import ChatSync

class SkypeTranslator(Translator):
  def translationMap(self):
    return {
             "Chats" : unicode(self.tr("Chats")),
             "ChatFriendlyName" : unicode(self.tr("Chat name")),
             "ChatMembers" : unicode(self.tr("Chat members")),
             "Messages" : unicode(self.tr("Messages")),
             "FirstMessage" : unicode(self.tr("First message")),
             "LastMessage" : unicode(self.tr("Last message")),
             "Type" : unicode(self.tr("Type")),
             "date" : unicode(self.tr("date")),
             "messages" : unicode(self.tr("messages")),
             "Calls" : unicode(self.tr("Calls")),
             "Members" : unicode(self.tr("Members")),
             "begin_timestamp" : unicode(self.tr("Begin")),
             "is_incoming" : unicode(self.tr("Type")),
             "identity" : unicode(self.tr("Identity")),
             "dispname" : unicode(self.tr("Displayed name")),
             "start_timestamp" : unicode(self.tr("Start")),
             "call_duration" : unicode(self.tr("End")),
             "Details" : unicode(self.tr("Details")),
             "SMS(s)" : unicode(self.tr("SMS(s)")),
             "SMS" : unicode(self.tr("SMS")),
             "target_numbers" : unicode(self.tr("Send to")),
             "timestamp" : unicode(self.tr("Date")),
             "body" : unicode(self.tr("Content")),
             "Account" : unicode(self.tr("Account")),
             "fullname" : unicode(self.tr("Full name")),
             "skypename" : unicode(self.tr("Skype name")),
             "mood" : unicode(self.tr("Mood")),
             "emails" : unicode(self.tr("E-mails")),
             "profileTimestamp" : unicode(self.tr("Profile creation")),
             "country" : unicode(self.tr("Country")),
             "languages" : unicode(self.tr("Language")),
             "balance" : unicode(self.tr("Account balance")),
             "Description" : unicode(self.tr("Description")),
             "Value" : unicode(self.tr("Value")),
             "Unknown" : unicode(self.tr("Unknown")),
             "VoiceMails" : unicode(self.tr("Voice mails")),
             "partner_dispname" : unicode(self.tr("Partner name")),
             "duration" : unicode(self.tr("Duration")),
             "partner_handle" : unicode(self.tr("Partner handle")),
             "size" : unicode(self.tr("Size")),
             "path" : unicode(self.tr("Path")),
             "Contacts" : unicode(self.tr("Contacts")),
             "displayname" : unicode(self.tr("Name")),
             "phone" : unicode(self.tr("Phone")),
             "country" : unicode(self.tr("Country")),
             "languages" : unicode(self.tr("Languages")),
             "displayname" : unicode(self.tr("Display name")),
             "birthday" : unicode(self.tr("Birthday")),
             "gender" : unicode(self.tr("Gender")),
             "province" : unicode(self.tr("Province")),
             "city" : unicode(self.tr("City")),
             "pstnnumber" : unicode(self.tr("Phone number")),
             "phone_home" : unicode(self.tr("Home phone number")),
             "phone_office" : unicode(self.tr("Office phone number")),
             "emails" : unicode(self.tr("E-mails")),
             "profile_timestamp" : unicode(self.tr("Profil creation")),
             "about" : unicode(self.tr("About")),
             "timezone" : unicode(self.tr("Time zone")),
             "rich_mood_text" : unicode(self.tr("Mood")),
             "last_used_network_time" : unicode(self.tr("Last network usage")),
             "Transfers" : unicode(self.tr("Transfers")),
             "type" : unicode(self.tr("Type")),
             "filename" : unicode(self.tr("File name")),
             "filesize" : unicode(self.tr("File size")),
             "starttime" : unicode(self.tr("Start")),
             "endtime" : unicode(self.tr("End")),
             "transferduration" : unicode(self.tr("Transfer duration")),
             "status" : unicode(self.tr("Status")),
             "filepath" : unicode(self.tr("File path")),
             "bytestransferred" : unicode(self.tr("Bytes transferred")),
             "extprop_localfilename" : unicode(self.tr("Local file name")),
           }    

class SkypeContainers(object):
  ContainersType = ['Accounts', 'Contacts', 'Transfers', 'Messages', 'Chats', 'ChatMembers',
                    'Calls', 'CallMembers', 'SMSes', 'Voicemails']
  def __init__(self, node):
    self.translator = SkypeTranslator()
    self.__node = node
    self.__reportName = 'Skype'
    self.__containers = {}
    for each in self.ContainersType:
       self.__containers[each] = []

  def add(self, records):
    for record in records:
     try:
       self.__containers[record.SkypeType + 's'].append(record)
     except TypeError as e:
       pass

  def findChatByName(self, chatname):
    for chat in self.__containers['Chats']:
      if chatname == chat.name():
        return chat 
    return None

  def findChatMemberByChatName(self, chatname):
    members = set() 
    for chatMember in self.__containers['ChatMembers'] :
      if chatname == chatMember.chatname():
        members.add(chatMember.identity())
    return list(members)

  def correlate(self):
    self.__chats = {}
    for message in self.__containers['Messages']:
      try:
        self.__chats[message.chatname()].append(message)
      except KeyError:
        self.__chats[message.chatname()] = [message]
    for chatname, messages in self.__chats.iteritems():
      self.__chats[chatname] = sorted(messages, key=id)

  def report(self, name):
    self.__reportName += " (" + name + ")"
    self.__reportName = self.__reportName.translate(None, "!@#$%^&'\/?").encode('UTF-8', 'replace')
    self.reportManager = ReportManager()
    for containerName, container in self.__containers.iteritems():
      if len(container):
        if containerName =='Contacts':
          self.reportContacts(container)
        elif containerName == 'Transfers':
          self.reportTransfers(container)
        elif containerName == 'Accounts':
          self.reportAccount(container)
        elif containerName == 'SMSes':
          self.reportSMS(container)
        elif containerName == 'Voicemails':
          self.reportVoicemails(container)
    if len(self.__containers['Chats']):
      self.reportChats()
      #self.reportChatsRecovery()  
    if len(self.__containers['Calls']):
      self.reportCalls()

  def reportChats(self):
    page = self.reportManager.createPage(self.__reportName, self.translator.translate("Chats"))
    headersDescription = self.translator.translate(["ChatFriendlyName", "ChatMembers", "Messages", "FirstMessage", "LastMessage", "Type"])
    reportTable = page.addDetailTable(self.translator.translate("Chats"), headersDescription) 

    if len(self.__chats):
      for chatname, messages in self.__chats.iteritems():
        chat = self.findChatByName(chatname) 
        if chat:
          chatMember = self.findChatMemberByChatName(chatname)
          if len(chatMember):
            headers = [chat.friendlyname(), chatMember, len(messages), chat.timestamp(), chat.last_change(), chat._type()] 
          else:
            headers = [chat.friendlyname(), chat.activemembers(), len(messages), chat.timestamp(), chat.last_change(), chat._type()] 
          convChat = self.createChatFragment(chat, messages)
          reportTable.addRow(headers, convChat)
    self.reportManager.addPage(page)

  def findChild(self, node, name):
     children = node.children()
     for child in children:
       if child.name().lower() == name.lower():
         return child
     return None 

  def reportChatsRecovery(self):
     for chat in self.__containers['Chats']:
       datnode = None
       try:
         datname = chat.dbpath()
         datpath = chat.dbpath()[:2]
       except :
         continue 
       chatsync = self.findChild(self.__node.parent(), 'chatsync')
       if chatsync:
         dbpath = self.findChild(chatsync, datpath)
         if dbpath:
           datnode = self.findChild(dbpath, datname)
       if not datnode:
         continue  

       try: 
         chatSync = ChatSync(datnode)  
         #for message in chatSync.messages():
           #print message
       except:
         print "Can't parse ChatSync"

  def createChatFragment(self, chat, messages):
    messagesTable = []
    for message in messages:
      messagesTable.append([message.time(), message._from(), message.message()])
    chats = [{ self.translator.translate("date") : chat.timestamp(),
               self.translator.translate("messages") : messagesTable }]
    chatname = chat.friendlyname().replace('"', '')
    return ChatFragment(chatname, chats)

  def findUniqCallMembers(self, callMembers):
    cms = []
    for member in callMembers:
      flag = 1  
      for m in cms:
        if m.identity() == member.identity():
          flag = 0
          continue 
      if flag:
        cms.append(member)
    return cms

  def findCallMemberByName(self, callName):
    cms = []
    for callMember in self.__containers['CallMembers']:
      if callMember.call_name() == callName:
        cms.append(callMember)
    cms = self.findUniqCallMembers(cms)
    return cms            

  def reportCalls(self):
    page = self.reportManager.createPage(self.__reportName, self.translator.translate("Calls"))
    headersDescription = self.translator.translate(["Members", "begin_timestamp", "is_incoming"])
    reportTable = page.addDetailTable(self.translator.translate("Calls"), headersDescription)
    details = []
    for call in self.__containers['Calls']:
      callMembers = self.findCallMemberByName(call.name()) 

      memberName = []
      if callMembers:
        for member in callMembers:
          memberName.append(member.dispname())
      headerTable = [memberName, call.begin_timestamp(), call.is_incoming()]
   
      detailsTable = None 
      if callMembers:
        tempTable = []
        for member in callMembers:
          tempTable.append((member.identity(), member.dispname(), member.start_timestamp(), member.call_duration()),)
        detailsHeaders =  self.translator.translate(["identity", "dispname", "start_timestamp", "call_duration"])       
        detailsTable = TableFragment(self.translator.translate("Details"), detailsHeaders, tempTable)
      reportTable.addRow(headerTable, detailsTable)
    self.reportManager.addPage(page)

  def reportSMS(self, container):
    page = self.reportManager.createPage(self.__reportName, self.translator.translate("SMS(s)"))
    table = []
    for sms in container:
      row = (sms.target_numbers(), sms.timestamp(), sms.body())
      if row != (None, None, None):
        table.append(row) 

    if len(table):
      page.addTable(self.translator.translate('SMS'), self.translator.translate(['target_numbers', 'timestamp', 'body']), table)
      self.reportManager.addPage(page)

  def reportAccount(self, container):
    page = self.reportManager.createPage(self.__reportName, self.translator.translate("Account"))
    for account in container:
      table = [(self.translator.translate('fullname') , account.fullname()),
               (self.translator.translate('skypename'), account.skypename()),
               (self.translator.translate('mood') , account.mood()),
               (self.translator.translate('emails') , account.emails()),
               (self.translator.translate('profileTimestamp') , account.profileTimestamp()),
               (self.translator.translate('country') , account.country()),
               (self.translator.translate('languages') , account.languages()),
               (self.translator.translate('balance'), account.balance())]
      accountName = account.emails()
      if accountName == None:
        accountName = self.translator.translate('Unknown')
      page.addTable(accountName, self.translator.translate(['Description', 'Value']), table)

    self.reportManager.addPage(page)

  def reportVoicemails(self, container): 
     pageName = self.translator.translate("VoiceMails")
     headers = ['partner_dispname', 'timestamp', 'duration']
     headersDescription = self.translator.translate(headers)
     details = ['partner_handle', 'size', 'path']
     detailsTranslation = self.translator.translate(details)
     self.reportDetailsTable(pageName, container, headers, headersDescription, details, detailsTranslation, None)

  def reportContacts(self, container):
    pageName = self.translator.translate('Contacts')
    headers = 'displayname', 'phone', 'country', 'languages'
    headersDescription = self.translator.translate(headers) 
    details = ['displayname', 'skypename', 'fullname', 'birthday', 'gender', 'country', 'languages', 'province', 'city', 'pstnnumber', 'phone_home', 'phone_office', 'emails', 'profile_timestamp', 'about', 'timezone', 'rich_mood_text', 'last_used_network_time']
    detailsTranslation = self.translator.translate(details)
    self.reportDetailsTable(pageName, container, headers, headersDescription, details, detailsTranslation, ('skypename', 'avatar_image',))

  def reportTransfers(self, container):
    pageName = self.translator.translate('Transfers')
    headers = 'partner_dispname', 'type', 'filename', 'filesize'
    headersDescription = self.translator.translate(headers)
    details = ['partner_handle', 'starttime', 'endtime', 'transferduration', 'status', 'filepath', 'bytestransferred', 'extprop_localfilename',]
    detailsTranslation = self.translator.translate(details)
    self.reportDetailsTable(pageName, container, headers, headersDescription, details, detailsTranslation)

  def reportDetailsTable(self, pageName, container, headers, headersDescription, details, detailsTranslation, thumb = None):
    page = self.reportManager.createPage(self.__reportName, pageName)
    reportTable = page.addDetailTable(pageName, headersDescription)

    for record in container:    
      headersTable = () 
      flag = None
      for header in headers:
        res = getattr(record, header)()
        if res != None:
          flag = 1
        headersTable += (res,)
      if not flag:
        continue
      
      tempTable = []
      for idx in range(len(details)):
        try:
          res = getattr(record, details[idx])()
          if res:
             tempTable.append((detailsTranslation[idx], res,))
        except:
          pass
     
      thumbData = None 
      if thumb:
        thumbData = ()
        for f in thumb:
          try:
            res = getattr(record, f)() 
            if res:
              thumbData += (res,)
          except Exception as e:
            pass
        if len(thumbData) != len(thumb):
          thumbData = None
 
      detailsTable = TableFragment(self.translator.translate("Details"), self.translator.translate(['Description', "Value"]), tempTable)
      reportTable.addRow(headersTable, detailsTable, thumbData)

    self.reportManager.addPage(page)
