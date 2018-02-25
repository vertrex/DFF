# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
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
#  Romain Bertholon <rbe@digital-forensic.org>
# 

from datetime import datetime
from decoder import *
import unicodedata

from dff.api.types.libtypes import Variant, VList


EVENTLOGHEADER = {
    "headerSize" : [0x0, 0x4, UINT32_T],
    "Signature" :  [0x4, 0x4, STRING_T],
    "MajorVersion": [0x8, 0x4, UINT32_T],
    "MinorVersion": [12, 0x4, UINT32_T],
    "StartOffset":[16, 0x4, UINT32_T],
    "EndOffset": [20, 0x4, UINT32_T],
    "CurrentRecordNumber": [24, 0x4, UINT32_T],
    "OldestRecordNumber": [28, 0x4, UINT32_T],
    "MaxSize": [32, 0x4, UINT32_T],
    "Flags": [36, 0x4, UINT32_T],
    "Retention": [40, 0x4, UINT32_T],
    "EndHeaderSize": [44, 0x4, UINT32_T]
}

EVENTLOGRECORD = {
    "Length":[0x0, 0x4, UINT32_T],
    "Reserved":[0x4, 0x4, STRING_T],
    "RecordNumber":[0x8, 0x4, UINT32_T],
    "TimeGenerated":[12, 0x4, UINT32_T],
    "TimeWritten":[16, 0x4, UINT32_T],
    "EventID":[20, 0x4, UINT32_T],
    "EventType":[24, 0x2, UINT16_T],
    "NumStrings":[26, 0x2, UINT16_T],
    "EventCategory":[28, 0x2, UINT16_T],
    "ReservedFlags":[30, 0x2, UINT16_T],
    "ClosingRecordNumber":[32, 0x4, UINT32_T],
    "StringOffset":[36, 0x4, UINT32_T],
    "UserSidLength":[40, 0x4, UINT32_T],
    "UserSidOffset":[44, 0x4, UINT32_T],
    "DataLength":[48, 0x4, UINT32_T],
    "DataOffset":[52, 0x4, UINT32_T]
}

EVENTEOFRECORD = {
  "RecordSizeBeginning":[0x0, 0x4, UINT32_T],
  "One":[0x4, 0x4, UINT32_T],
  "Two":[0x8, 0x4, UINT32_T],
  "Three":[12, 0x4, UINT32_T],
  "Four":[16, 0x4, UINT32_T],
  "BeginRecord":[20, 0x4, UINT32_T],
  "EndRecord":[24, 0x4, UINT32_T],
  "CurrentRecordNumber":[28, 0x4, UINT32_T],
  "OldestRecordNumber":[32, 0x4, UINT32_T],
  "RecordSizeEnd":[36, 0x4, UINT32_T]
}

EVENTLOG_ERROR_TYPE = 0x0001#Error event
EVENTLOG_AUDIT_FAILURE = 0x0010 #Failure Audit event
EVENTLOG_AUDIT_SUCCESS = 0x0008 #Success Audit event
EVENTLOG_INFORMATION_TYPE = 0x0004 #Information event
EVENTLOG_WARNING_TYPE = 0x0002 #Warning event

event_types = {
    EVENTLOG_INFORMATION_TYPE:"Information Event (EVENTLOG_INFORMATION_TYPE)",
    EVENTLOG_WARNING_TYPE:"Warning Event (EVENTLOG_WARNING_TYPE)",
    EVENTLOG_AUDIT_SUCCESS:"Success Audit Event (EVENTLOG_AUDIT_SUCCESS)",
    EVENTLOG_AUDIT_FAILURE:"Failure Audit Event (EVENTLOG_AUDIT_FAILURE)",
    EVENTLOG_ERROR_TYPE:"Error Event (EVENTLOG_ERROR_TYPE)"
}

event_types_simple = {
    EVENTLOG_INFORMATION_TYPE:"Information",
    EVENTLOG_WARNING_TYPE:"Warning",
    EVENTLOG_AUDIT_SUCCESS:"Success",
    EVENTLOG_AUDIT_FAILURE:"Failure",
    EVENTLOG_ERROR_TYPE:"Error"
}

event_types_icons = {
    EVENTLOG_INFORMATION_TYPE:':/info',
    EVENTLOG_WARNING_TYPE:':/warning',
    EVENTLOG_AUDIT_SUCCESS:':/audit_success',
    EVENTLOG_AUDIT_FAILURE:'/audit_failure',
    EVENTLOG_ERROR_TYPE:':/error',
}

class Header(decoder):
    def __init__(self, vfile, offset = 0, template = EVENTLOGHEADER):
        decoder.__init__(self, vfile, offset=0, template=EVENTLOGHEADER)
        self.__valid = True

        # check validity
        if self.Signature != "LfLe":
            self.__valid = False
        if self.headerSize != 0x30:
            self.__valid = False
        if self.EndHeaderSize != 0x30:
            self.__valid = False

    def isValid(self):
        return self.__valid
 
class EofRecord(decoder):
    def __init__(self, vfile, offset = 0, template = EVENTEOFRECORD):
        decoder.__init__(self, vfile, offset, template)
        self.__corrupted = False

        # check validity
        if self.One != 0x11111111:
            self.__corrupted = True
        if self.Two != 0x22222222:
            self.__corrupted = True
        if self.Three != 0x33333333:
            self.__corrupted = True
        if self.Four != 0x44444444:
            self.__corrupted = True

    def isValid(self):
        """
        \return True if the record seems to be valide, False otherwise.
        """
        return not self.__corrupted

class Record(decoder):
    def __init__(self, vfile, offset = 0, template = EVENTLOGRECORD):
        decoder.__init__(self, vfile, offset, template)

        self.__valid = True
        if self.Reserved != "LfLe":
            self.__valid =  False

        self.__time_generated = ""
        self.__time_written = ""
        self.__pos = 0
        self.__event_type = ""
        self.__single_type = ""
        self.__buf = None # must be a bytearray
        self.__source_name = ""
        self.__computer_name = ""
        self.__user_sid = 0
        self.__log_strings = []

    def getIcon(self, evt_type=0x0000):
        """
        Get an icon accorfing to an event type.
        
        \param evt_type the type of event. If the value is 0x0000, the value of the attribute
        self.EventType is used.

        \return the icon corresponding to the type of event (error, info, warning, etc) or None
        if the type is unknown
        """
        try:
            return evt_type and event_types_icons[evt_type] or event_types_icons[self.EventType]
        except:
            return ":/info" 

    def parseContent(self):
        """
        Get the different fields of the record.
        """
        self.sourceName()
        self.computerName()
        self.eventType()
        self.getStrings()
        self.getTimeGenerated()
        self.getTimeWritten()

    def sourceName(self):
        """
        \return the name of the source which generated the event. If the sourceName was not yet parsed,
        get both the source name and the computer name and set the corresponding attributes before
        returning the sourceName. Returns None if the record was not read (i.e. self.__buff is None).
        """
        if self.__source_name != '' or self.__buf is None:
            return self.__source_name or None

        sources = map(lambda x : x.encode('UTF-8'), unicode(self.__buf[:self.UserSidOffset - self.templateSize()].decode('utf-16', 'replace')).split("\x00", 2))
        self.__source_name = str(sources[0])
        self.__computer_name = str(sources[1])
        return self.__source_name

    def computerName(self):
        """
        \return the name of the computer who generate the event
        """
        if self.__computer_name != "" or self.__buf is None:
            return self.__computer_name or None

        self.sourceName()
        return self.__computer_name

    def getStrings(self):
        """
        \return a py list [] (see Variant) containing the list of log strings present
        in the event, or an empty list if something wrong occured
        """

        if self.__buf is None or len(self.__log_strings):
            return self.__log_strings

        string_offset = self.StringOffset - self.templateSize()
        num_string = self.NumStrings

        # get the part of the buffer between index string_offset and DataOffset
        # (the position of the log strings), decode into utf-16 (replace unknown
        # chars) and split when \x00 is encoutered (the max number of split is
        # num_strings)
        tmp_buff = unicode(self.__buf[string_offset:self.DataOffset - self.templateSize()].decode('utf-16', 'replace')).split("\x00", num_string - 1)
        
        for i in tmp_buff:
            try:
                self.__log_strings.append(unicodedata.normalize('NFKD', i).encode('ascii', 'replace'))
            except:
                continue                      
        return self.__log_strings

    def eventType(self):
        """
        \return the full type of the event or 'Unknown' if the type is invalid
        """
        if self.__buf is None or self.__event_type != '':
            return self.__event_type
        
        try:
            self.__event_type = event_types[self.EventType]
            self.__single_type = event_types_simple[self.EventType]
            return event_types[self.EventType]
        except KeyError:
            self.__single_type = "Unknown"
            return "Unknown Event type (" + str(self.EventType) + ")"

    def getSingleType(self):
        """
        \return a simplified type (defined in 'event_types_simple') used
        to display the name of the node corresponding to the record or 'unknown'
        if the type is invalid.
        """

        # call event type if the __single_type is empty
        if self.__single_type == "":
            self.eventType()
        return self.__single_type

    def getTimeGenerated(self):
        """
        \return the time generated under the form of a string at ISO format :
        'YYYY-MM-DD HH:MM:SS' from a POSIX timestamp.
        """
        if self.__time_generated != "":
            return self.__time_generated
        gen_time = datetime.fromtimestamp(self.TimeGenerated)
        self.__time_generated = gen_time.isoformat(' ')
        return self.__time_generated

    def getTimeWritten(self):
        """
        \return the time written under the form of a string at ISO format :
        'YYYY-MM-DD HH:MM:SS' from a POSIX timestamp.
        """
        if self.__time_written != "":
            return self.__time_written
        written_time = datetime.fromtimestamp(self.TimeWritten)
        self.__time_written = written_time.isoformat(' ')
        return self.__time_written

    def getUserSid(self):
        pass

    def setBuff(self, buf):
        self.__buf = buf

    def isValid(self):
        """
        \return true if the record seems to be valid, false otherwise
        """
        return self.__valid
