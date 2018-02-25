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
from skyperecord import SkypeMessage, SkypeChat, SkypeChatMember, SkypeCall, SkypeCallMember, SkypeContactGroup, SkypeAccount, SkypeTransfer, SkypeContact

class SkypeDBBRecord(object):
  def __init__(self, record):
     self.__record = record

  def __getattr__(self, name):
    def callRecord():
      return self.record(name)
    return callRecord 

  def record(self, name = None):
    if not name:
      return self.__record
    try:
      return self.__record[self.field[name]]
    except KeyError:
      return None

class SkypeMessageDBB(SkypeMessage, SkypeDBBRecord):
  field = { 'id'              :  -1,
            'pk_id'           :   3,
            'crc'             :   7,
            'remote_id'       :  11,
            'chatname'        : 480, 
            'timestamp'       : 485,
            'author'          : 488, 
            'from_dispname'   : 492,
            'chatmsg_type'    : 497, # 1 - addmembers, 2 - createchatwith, # 3 - said, 4- left, 5 - changetopic
            'users_added'     : 500,
            'leavereason'     : 505, # 6 - unsubdcribe
            'body_xml'        : 508,
            'chatmsg_status'  : 513, # 1 - sending, 2 - sent, 3 - recieved, 4 - read
            'body_is_rawxml'  : 517,
            'edited_by'       : 888,
            'edited_timestamp': 893,
            'dialog_partner'  : 3160,
            'guid'            : 3170 , # binary
           }

  def __init__(self, recordMessage):
    SkypeMessage.__init__(self)
    SkypeDBBRecord.__init__(self, recordMessage)

class SkypeAccountDBB(SkypeAccount, SkypeDBBRecord):
  field = { 'id'                       :   -1,
            'synced_email'             :    7,
            'skypename'                :   16,
            'birthday'                 :   29,
            'gender'                   :   33,
            'languages'                :   36,
            'country'                  :   40,
            'province'                 :   44,
            'city'                     :   48,
            'phone_home'               :   52,
            'phone_office'             :   56,
            'phone_mobile'             :   60,
            'emails'                   :   64,
            'homepage'                 :   68,
            'about'                    :   72,
            'profile_timestamp'        :   77,
            'profile_attachments'      :   91,
            'mood_text'                :  104,
            'timezone'                 :  109,
            'ipcountry'                :  116,
            'avatar_image'             :  150,
            'skypeout_balance_currency':  296,
            'skypeout_balance'         :  301,
            'rich_mood_text'           :  820,
            'registration_timestamp'   : 3205,
          }
  def __init__(self, record):
    SkypeAccount.__init__(self)
    SkypeDBBRecord.__init__(self, record)

class SkypeTransferDBB(SkypeDBBRecord, SkypeTransfer):
  field = { 'id'              :   -1,
            'pk_id'           :    3,
            'nodeid'          :   11,
            'last_activity'   :   15,
            'flags'           :   19,
            'type'            :  321,
            'partner_handle'  :  324,
            'partner_dispname':  328,
            'status'          :  333,
            'starttime'       :  341,
            'finishtime'      :  345,
            'filepath'        :  348, #not sure because appear also in extprop_localfilename with same value
            'filename'        :  352,
            'filesize'        :  356, #not sure because bytes transferred have same value in test files
            'bytestransferred':  360,
            'chatmsg_guid'    :  370,
          }
  def __init__(self, record):
     SkypeDBBRecord.__init__(self, record)
     SkypeTransfer.__init__(self)

class SkypeContactDBB(SkypeContact, SkypeDBBRecord):
  field = { 'id'                             :    -1,
            'authorization_certificate'      :     3,
            'certificate_send_count'         :    11,
            'account_modification_serial_nr' :    15,
            'skypename'                      :    16,
            'saved_directory_blob'           :    19,
            'fullname'                       :    20,
            'pstnnumber'                     :    24, #phone
            'server_synced'                  :    27,
            'birthday'                       :    29,
            'gender'                         :    33,
            'last_used_networktime'          :    35, 
            'languages'                      :    36, 
            'country'                        :    40,
            'province'                       :    44,
            'city'                           :    48,
            'phone_home'                     :    52,
            'senth_auth_request'             :    55, #or populairty order ?
            'phone_office'                   :    56,
            'unknownBlob'                    :    59, #not found in sql
            'phone_mobile'                   :    60,
            'emails'                         :    64,
            'homepage'                       :    68,
            'about'                          :    72,
            'profile_timestamp'              :    77,
            'give_authlevel'                 :    93,
            'nrof_authed_buddies'            :   113,
            'buddystatus'                    :   121,
            'isauthorized'                   :   125,
            'isblocked'                      :   129,
            'given_displayname'              :   132,
            'unknownTime'                    :   141, #not found in sql
            'unknownBlob'                    :   146,
            'avatar_image'                   :   150,
            'lastcalled_time'                :   157, #not found in sql
            'extprop_seen_birthday'          :  1019,
          }

  def __init__(self, record):
    SkypeContact.__init__(self)
    SkypeDBBRecord.__init__(self, record)

  def displayname(self):
    name = self.skypename()
    if not name:
      name = self.phone()
      if not name:
        return self.fullname() 
    return name

class SkypeContactGroupDBB(SkypeContactGroup, SkypeDBBRecord):
  field = { 'id'                  :   -1,
            'type'                :  621, 
            'extprop_is_expanded' : 1002,
          }
  def __init__(self, record):
    SkypeContactGroup.__init__(self)
    SkypeDBBRecord.__init__(self, record)

class SkypeChatDBB(SkypeChat, SkypeDBBRecord):
  field = { 'id'                 :   -1,
            'state_data'         :   15,
            'last_change'        :   23,
            'dbpath'             :   51,
            'unknown'            :   31, #not found in sqlite
            'unknownBlob'        :   39, 
            'pk_type'            :   59, #could be is_permanent too
            'name'               :  440,
            'timestamp'          :  445,
            'posters'            :  456,
            'topic'              :  464,
            'activemembers'      :  468,
            'friendlyname'       :  472,
            'is_bookmarked'      :  561,
            'activity_timestamp' :  565,
            'picture'            :  638,
            'unknown175'         : 1024, #appear twice set to 175
            'unknown0'           : 3105, #always set to 0
            'topic_xml'          : 3096,
          }

  def __init__(self, record):
     SkypeChat.__init__(self)
     SkypeDBBRecord.__init__(self, record)

class SkypeChatMemberDBB(SkypeChatMember, SkypeDBBRecord):
  field = { 'id'        :  -1,
            'chatname'  : 584,
            'role'      : 593,
            'identity'  : 588,
            'is_active' : 597,
          }
  def __init__(self, recordMessage):
    SkypeChatMember.__init__(self)
    SkypeDBBRecord.__init__(self, recordMessage)

class SkypeCallDBB(SkypeCall, SkypeDBBRecord):
  field = { 'id'                :  -1,
            'members'           :   3,
            'begin_timestamp'   : 161,
            'topic'             : 252,
            'is_incoming'       : 813,
            'host_identity'     : 840,
            'name'              : 868,
            'is_unseend_missed' : 917,
          } 
  def __init__(self, record):
     SkypeCall.__init__(self)
     SkypeDBBRecord.__init__(self, record)

class SkypeCallMemberDBB(SkypeCallMember, SkypeDBBRecord):
  field = { 'id'              :   -1,
            'call_db_id'      :    7,
            'call_name'       :  184,
            'price_precision' :  189,
            'identity'        :  920,
            'dispname'        :  924,
            'call_duration'   :  933,
            'price_per_minute':  937,
            'price_currency'  :  940,
            'type'            :  945,
            'status'          :  949,
            'failureason'     :  953,
            'sounderror_code' :  957,
            'pstn_statustext' :  964,
            'start_timestamp' : 3301,
          }
  def __init__(self, record):
     SkypeCallMember.__init__(self)
     SkypeDBBRecord.__init__(self, record)
