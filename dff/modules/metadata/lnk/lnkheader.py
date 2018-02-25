# Copyright (C) 2009-2013 ArxSys
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
#  Solal Jacob <sja@digital-forensic.org>

from struct import unpack

from dff.api.vfs.libvfs import VLink
from dff.api.types.libtypes import MS64DateTime 

class LPWSTR():
  def __init__(self, data):
    size = unpack('I', data[0:4])[0]
    self.data = unicode(data[4:4+size*2].decode('UTF-16')).encode("UTF-8", "replace")
    self.length = 4 + (size * 2)

  def __str__(self):
     return self.data

  def __len__(self):
    return (self.length)


FileAttributesFlags = [
"FILE_ATTRIBUTE_READONLY", "FILE_ATTRIBUTE_HIDDEN", "FILE_ATTRIBUTE_SYSTEM", "Reserved1", "FILE_ATTRIBUTE_DIRECTORY", 
"FILE_ATTRIBUTE_ARCHIVE", "Reserved2", "FILE_ATTRIBUTE_NORMAL", "FILE_ATTRIBUTE_TEMPORARY", "FILE_ATTRIBUTE_SPARSE_FILE",
"FILE_ATTRIBUTE_REPARSE_POINT", "FILE_ATTRIBUTE_COMPRESSED", "FILE_ATTRIBUTE_OFFLINE", "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED",
"FILE_ATTRIBUTE_ENCRYPTED"]

LinkFlags = [
"HasLinkTargetIDList", "HasLinkInfo", "HasName", "HasRelativePath", "HasWorkingDir", "HasArguments", "HasIconLocation",
"IsUnicode", "ForceNoLinkInfo", "HasExpString", "RunInSeparateProcess", "Unused1", "HasDarwinID", "RunAsUser",
"HasExpIcon", "NoPidlAlias", "Unused2", "RunWithShimLayer", "ForceNoLinkTrack", "EnableTargetMetadata",
"DisableLinkPathTracking", "DisableKnownFolderTracking", "DisableKnownFolderAlias", "AllowLinkToLink",
"UnaliasOnSave", "PreferEnvironmentPath", "KeepLocalIDListForUNCTarget"
]			

ShowCommandFlagsMap = {
0x1 : "SW_SHOWNORMAL", 0x3 : "SW_SHOWMAXIMIZED", 0x7 : "SW_SHOWMINNOACTIVE"
}

HotKeysLowFlagsMap = {
0x30 : "0", 0x31 : "1", 0x32 : "2", 0x33 : "3", 0x34 : "4", 0x35 : "5", 0x36 : "6", 0x37 : "7", 0x38 : "8", 0x39 : "9",
0x41 : "A", 0x42 : "B", 0x43 : "C", 0x44 : "D", 0x45 : "E", 0x46 : "F", 0x47 :"G", 0x48 : "H", 0x49 : "I", 0x4A : "J",
0x4B : "K", 0x4C : "L", 0x4D : "M", 0x4E : "N", 0x4F : "O", 0x50 : "P", 0x51 : "Q", 0x52 : "R", 0x53 : "S", 0x54 : "T",
0x55 : "U", 0x56 : "V", 0x57 : "W", 0x58 : "X", 0x59 : "Y", 0x5A : "Z",
0x70 : "F1", 0x71 : "F2", 0x72 : "F3", 0x73 : "F4", 0x74 : "F5", 0x75 : "F6", 0x76 : "F7", 0x77 : "F8", 0x78 : "F9",
0x79 : "F10", 0x7A : "F11", 0x7B : "F12", 0x7C : "F13", 0x7D : "F14",  0x7E : "F15", 0x7F : "F16", 0x80 : "F17",
0x81 : "F18", 0x82 : "F19", 0x83 : "F20", 0x84 : "F21", 0x85 : "F22", 0x86 : "F23", 0x87 : "F24", 0x90 : "NUM LOCK",
0x91 : "SCROLL LOCK"
}

HotKeysHighFlagsMap = {
0x1 : "HOTKEYF_SHIFT", 0x2 : "HOTKEYF_CONTROL", 0x4 : "HOTKEYF_ALT"
}

LinkInfoFlags = [
"VolumeIDAndLocalBasePath", "CommonNetworkRelativeLinkAndPathSuffix"]

DriveTypeMaps = {
   0x0 : "DRIVE_UNKNOWN",
   0x1 : "DRIVE_NO_ROOT_DIR",
   0x2 : "DRIVE_REMOVABLE",
   0x3 : "DRIVE_FIXED",
   0x4 : "DRIVE_REMOTE",
   0x5 : "DRIVE_CDROM",
   0x6 : "DRIVE_RAMDISK",
}

NetworkProviderType = {
  0x001A0000 : "WNNC_NET_AVID",
  0x001B0000 : "WNNC_NET_DOCUSPACE",
  0x001C0000 : "WNNC_NET_MANGOSOFT",
  0x001D0000 : "WNNC_NET_SERNET",
  0X001E0000 : "WNNC_NET_RIVERFRONT1",
  0x001F0000 : "WNNC_NET_RIVERFRONT2",
  0x00200000 : "WNNC_NET_DECORB",
  0x00210000 : "WNNC_NET_PROTSTOR",
  0x00220000 : "WNNC_NET_FJ_REDIR",
  0x00230000 : "WNNC_NET_DISTINCT",
  0x00240000 : "WNNC_NET_TWINS",
  0x00250000 : "WNNC_NET_RDR2SAMPLE",
  0x00260000 : "WNNC_NET_CSC",
  0x00270000 : "WNNC_NET_3IN1",
  0x00290000 : "WNNC_NET_EXTENDNET",
  0x002A0000 : "WNNC_NET_STAC",
  0x002B0000 : "WNNC_NET_FOXBAT",
  0x002C0000 : "WNNC_NET_YAHOO",
  0x002D0000 : "WNNC_NET_EXIFS",
  0x002E0000 : "WNNC_NET_DAV",
  0x002F0000 : "WNNC_NET_KNOWARE",
  0x00300000 : "WNNC_NET_OBJECT_DIRE",
  0x00310000 : "WNNC_NET_MASFAX",
  0x00320000 : "WNNC_NET_HOB_NFS",
  0x00330000 : "WNNC_NET_SHIVA",
  0x00340000 : "WNNC_NET_IBMAL",
  0x00350000 : "WNNC_NET_LOCK",
  0x00360000 : "WNNC_NET_TERMSRV",
  0x00370000 : "WNNC_NET_SRT",
  0x00380000 : "WNNC_NET_QUINCY",
  0x00390000 : "WNNC_NET_OPENAFS",
  0x003A0000 : "WNNC_NET_AVID1",
  0x003B0000 : "WNNC_NET_DFS",
  0x003C0000 : "WNNC_NET_KWNP",
  0x003D0000 : "WNNC_NET_ZENWORKS",
  0x003E0000 : "WNNC_NET_DRIVEONWEB",
  0x003F0000 : "WNNC_NET_VMWARE",
  0x00400000 : "WNNC_NET_RSFX",
  0x00410000 : "WNNC_NET_MFILES",
  0x00420000 : "WNNC_NET_MS_NFS",
  0x00430000 : "WNNC_NET_GOOGLE",
}

CommonNetworkRelativeLinkFlags = [
"ValidDevice", "ValidNetType"] 

ExtraDataBlockMaps = {
  0xA0000001 : "EnvironmentVariableDataBlock",
  0xA0000002 : "ConsoleDataBlock",
  0xA0000003 : "TrackerDataBlock",
  0xA0000004 : "ConsoleFEDataBlock",
  0xA0000005 : "SpecialFolderDataBlock",
  0xA0000006 : "DarwinDataBlock",
  0xA0000007 : "IconEnvironmentDataBlock",
  0xA0000008 : "ShimDataBlock",
  0xA0000009 : "PropertyStoreDataBlock",
  0xA000000B : "KnownFolderDataBlock",
  0xA000000C : "VistaAndAboveIDListDataBlock",
}

FillAttributesFlags = ["FOREGROUND_BLUE", "FOREGROUND_GREEN", "FOREGROUND_RED", "FOREGROUND_INTENSITY", "BACKGROUND_BLUE",
"BACKGROUND_GREEN", "BACKGROUND_RED", "BACKGROUND_INTENSITY"]

FontFamily = {
0x0000 : "FF_DONTCARE",
0x0010 : "FF_ROMAN",
0x0020 : "FF_SWISS",
0x0030 : "FF_MODERN",
0x0040 : "FF_SCRIPT",
0x0050 : "FF_DECORATIVE",
}

PropertyType = {
0x0000 : "VT_EMPTY", 0x0001 : "VT_NULL", 0x0002 : "VT_I2", 0x0003 : "VT_I4", 0x0004 : "VT_R4", 0x0005 : "VT_R8", 0x0006 : "VT_CY",
0x0007 : "VT_DATE", 0x0008 : "VT_BSTR", 0x000A : "VT_ERROR", 0x000B : "VT_BOOL", 0x000E : "VT_DECIMAL", 0x0010 : "VT_I1",
0x0011 : "VT_UI1", 0x0012 : "VT_UI2", 0x0013 : "VT_UI4", 0x0014 : "VT_I8", 0x0015 : "VT_UI8", 0x0016 : "VT_INT", 0x0017 : "VT_UINT",
0x001E : "VT_LPSTR", 0x001F : "VT_LPWSTR", 0x0040 : "VT_FILETIME", 0x0041 : "VT_BLOB", 0x0042 : "VT_STREAM", 0x0043 : "VT_STORAGE",
0x0044 : "VT_STREAMED_OBJECT", 0x0045 : "VT_STORED_OBJECT", 0x0046 : "VT_BLOB_OBJECT", 0x0047 : "VT_CF", 0x0048 : "VT_CLSID",
0x0049 : "VT_VERSIONED_STREAM", 0x1002 : "VT_VECTOR_I2", 0x1000 : "VT_VECTOR", 0x1003 : "VT_VECTOR_I4", 0x1004 : "VT_VECTOR_R4", 0x1005 : "VT_VECTOR_R8", 
0x1006 : "VT_VECTOR_CY", 0x1007 : "VT_VECTOR_DATE", 0x1008 : "VT_VECTOR_BSTR", 0x100A : "VT_VECTOR_ERROR", 0x100B : "VT_VECTOR_BOOL",
0x100C : "VT_VECTOR_VARIANT", 0x1010 : "VT_VECTOR_I1", 0x1011 : "VT_VECTOR_U1", 0x1012 : "VT_VECTOR_UI2", 0x1013 : "VT_VECTOR_UI4",
0x1014 : "VT_VECTOR_I8", 0x1015 : "VT_VECTOR_UI8", 0x101E : "VT_VECTOR_LPSTR", 0x101F : "VT_VECTOR_LPWSTR", 0x1040 : "VT_VECTOR_FILETIME",
0x1047 : "VT_VECTOR_CF", 0x1048 : "VT_VECTOR_CLSID", 0x2002 : "VT_ARRAY_I2", 0x2003 : "VT_ARRAY_I4", 0x2004 : "VT_ARRAY_R4",
0x2005 : "VT_ARRAY_R8", 0x2006 : "VT_ARRAY_CY", 0x2007 : "VT_ARRAY_DATA", 0x2008 : "VT_ARRAY_BSTR", 0x200A : "VT_ARRAY_ERROR",
0x200B : "VT_ARRAY_BOOL", 0x200C : "VT_ARRAY_VARIANT", 0x200E : "VT_ARRAY_DECIMAL", 0x2010 : "VT_ARRAY_I1", 0x2011 : "VT_ARRAY_UI1",
0x2012 : "VT_ARRAY_UI2", 0x2013 : "VT_ARRAY_UI4", 0x2016 : "VT_ARRAY_INT", 0x2017 : "VT_ARRAY_UINT"
}

PropertyTypeConverter = {
  "VT_LPWSTR"  : LPWSTR,
  "VT_BSTR" : LPWSTR,
}

SerializedPropertyHeader = ({"info" : { "os":"windows", "arch":"x86", "name":"serialized" },
			"descr" : {
				    "IntegerName" : ((13),
				    {
				      "ValueSize" : (4, 0),
				      "Id" : (4, 4),
				      "Reserved" : (1, 8),
				      "TypedValue" : (4, 9, "TypedPropertyValue"),
				    }),
				    "StringName" : ((9),
				    {
				      "ValueSize" : (4, 0),
				      "NameSize" : (4, 4),
				    }),
				    "TypedPropertyValue" : ((4),
				    {
				      "Type" : (2, 0),
				      "Padding" : (2, 2),
				    }),
			 	  }
			})

DataBlockHeader = ({"info" : { "os":"windows", "arch":"x86", "name" : "lnkdatablock"},
		     "descr" : {
				 "DataBlockStandard" : ((8),
				 {
				   "BlockSize" : (4, 0),
				   "BlockSignature" : (4, 4),
				 }),
 				 "SpecialFolderDataBlock" : ((0x10),
				 {
				   "Standard" : (8, 0, "DataBlockStandard"),
				   "SpecialFolderID" : (4, 8),
				   "Offset" :  (4, 12)
				 }),
				 "TrackerDataBlock" : ((0x60),
				 {
				   "Standard" : (8, 0, "DataBlockStandard"),
				   "Length" : (4, 8),
				   "Version" : (4, 12),
				   "MachineID" : (16, 16),
				   "DroidVolume" : (16,  32),
				   "DroidFile" : (16, 48),	
				   "DroidBirthVolume" : (16, 64),
				   "DroidBirthFile" : (16, 80),
				 }),
				 "EnvironmentVariableDataBlock" : ((0x314),
				 {
				   "Standard" : (8, 0, "DataBlockStandard"),
				   "TargetAnsi" : (260, 8),
				   "TargetUnicode" : (520, 268)	
				 }),
				 "IconEnvironmentDataBlock" : ((0x314),
				 {
				   "Environment" : (0x314, 0, "EnvironmentVariableDataBlock")
				 }),
				 "DarwinDataBlock" : ((0x314),
				 {
				   "Standard" : (8, 0, "DataBlockStandard"),
				   "DataAnsi" : (260, 8),
				   "DataUnicode" : (520, 268),
				 }),
				 "PropertyStoreDataBlock" : ((32),
				 {
				   "Standard" : (8, 0, "DataBlockStandard"),
				   "Property" : (24, 8, "PropertyStorage"),
				 }),
				 "PropertyStorage" : ((24),
				 {
				   "StorageSize" : (4, 0),
				   "Version" : (4, 4),
				   "FormatID" : (16, 8), 
				 }),
				 "KnownFolderDataBlock" : ((28),
				 {
				   "Standard" : (8, 0, "DataBlockStandard"),
				   "ID" : (16, 8),
				   "Offset" : (4, 24),
				 }),
				 "ConsoleDataBlock" : ((0xcc),
				 {
				   "Standard" : (8, 0, "DataBlockStandard"),
				   "FillAttributes" : (2, 8),
				   "PopupFillAttributes" : (2, 10),
				   "ScreenBufferSizeX" : (2, 12),
				   "ScreenBufferSizeY" : (2, 14),
				   "WindowSizeX" : (2, 16),
				   "WindowSizeY" : (2, 18),
				   "WindowOriginX" : (2, 20),
				   "WindowOriginY" : (2, 22),
				   "Unused1" : (4, 24),
				   "Unused2" : (4, 28),
				   "FontSize" : (4, 32),
				   "FontFamily" : (4, 36),
				   "FontWeight" : (4, 40),
				   "FaceName" : (64, 44),
				   "CursorSize" : (4, 108),
				   "FullScreen" : (4, 112),
				   "QuickEdit" : (4, 116),
				   "InsertMode" : (4, 120),
				   "AutoPosition" : (4, 124),
				   "HistoryBufferSize" : (4, 128),
				   "NumberOfHistoryBuffers" : (4, 132),
				   "HistoryNoDup" : (4, 136),
				   "ColorTable" : (64, 140),
				 }),
		               }
		    })

ShellLinkHeader = ({"info" : { "os":"windows", "arch":"x86", "name" : "lnk"},
		     "descr" : {
				 "ShellLinkHeader" : ((0x4c),
				 {
				   "HeaderSize" : (4, 0),
				   "LinkCLSID" : (16, 4),
				   "LinkFlags" : (4, 20),
				   "FileAttributes" : (4, 24),
				   "CreationTime" : (8, 28),
				   "AccessTime" : (8, 36),
				   "WriteTime" : (8, 44),
				   "FileSize" : (4, 52),
				   "IconIndex" : (4, 56),
				   "ShowCommand" : (4, 60),
				   "HotKey" : (2, 64),
				   "Reserved1" : (2, 66),
				   "Reserved2" : (4, 68),
				   "Reserved3" : (4, 72)
				 }),
				 "LinkInfo" : ((0x1c),
				 {
				   "StructSize" : (4, 0),
				   "HeaderSize" : (4,4),
				   "Flags" : (4, 8),
				   "VolumeIDOffset" : (4, 12),
				   "LocalBasePathOffset" : (4, 16),
				   "CommonNetworkRelativeLinkOffset" : (4, 20),
				   "CommonPathSuffixOffset" : (4, 24)
				 }),
			         "VolumeID" : ((16),
				 {
				   "Size" : (4, 0),
				   "DriveType" : (4, 4),
				   "DriveSerialNumber" : (4, 8),
				   "LabelOffset" : (4, 12),
				 }),	
				 "CommonNetworkRelativeLink" : ((20),
				 {
				   "Size" : (4, 0),
				   "LinkFlags" : (4, 4),
				   "NetNameOffset" : (4,8),
				   "DeviceNameOffset" : (4, 12),
				   "NetworkProviderType" : (4, 16),
				 })
			      }
		    })

LnkAttributesMap = { 
       "Name" : ("Name", str),
       "RelativePath" : ("RelativePath", str),
       "RelativePathLink" : ("RelativePathLink", VLink),
       "WorkingDir" : ("WorkingDir", str),
       "Arguments" : ("Arguments", str),
       "IconLocation" : ("IconLocation", str),
       "HeaderSize": ("shellLink.HeaderSize", int),
       "LinkCLSID" : ("shellLink.LinkCLSID", str),
       "LinkFlags" : ("shellLink.LinkFlags", list),
       "FileAttributes": ("shellLink.FileAttributes", list),
       "CreationTime" : ("shellLink.CreationTime", MS64DateTime),
       "AccessTime" : ("shellLink.AccessTime", MS64DateTime),
       "WriteTime" : ("shellLink.WriteTime", MS64DateTime),
       "FileSize" : ("shellLink.FileSize", int),
       "IconIndex" : ("shellLink.IconIndex", int),
       "ShowCommand" : ("shellLink.ShowCommand", str),
       "HotKey": ("shellLink.HotKey", int),
       "Reserved1" : ("shellLink.Reserved1", int),
       "Reserved2" : ("shellLink.Reserved2", int),
       "Reserved3" : ("shellLink.Reserved3", int),
       "LinkTargetID" : ("linkTargetIDList", dict),
       "Link info" : ("linkInfoAttr", dict),
       "Special Folder Data Block": 
       {
	 "Special folder id" : ("SpecialFolderDataBlock.SpecialFolderID", int)
       },
       "Tracker Data Block": 
       {
         "Machine ID" : ("TrackerDataBlock.MachineID", str),
         "Droid Volume" : ("TrackerDataBlock.DroidVolume", str),
         "Droid File" : ("TrackerDataBlock.DroidFile", str),
         "Droid Birth Volume" : ("TrackerDataBlock.DroidBirthVolume", str),
         "Droid Birth File" : ("TrackerDataBlock.DroidBirthFile", str),
       },       
       "Environment Variable Data Block":
       {
         "Target Ansi" : ("EnvironmentVariableDataBlock.TargetAnsi", str),
         "Target Unicode" : ("EnvironmentVariableDataBlock.TargetUnicode", str),
       },
       "Icon Environment Data Block":
       {
         "Target Ansi" :  ("IconEnvironmentDataBlock.Environment.TargetAnsi", str),
         "Target Unicode": ("IconEnvironmentDataBlock.Environment.TargetUnicode", str),
       },
       "Dariwn Data Block":
       {
         "Darwin Data Ansi" :  ("DarwinDataBlock.DataAnsi", str),
         "Darwin Data Unicode" : ("DarwinDataBlock.DataUnicode", str),
       },
       "Property Store Data Block" : ("PropertyStoreSerializedAttr", dict),
       "Known Folder Data Block" :
       {
         "ID" : ("KnownFolderDataBlock.ID", str)	 
       },
       "Console Data Block" :
       { 
         "Fill Attributes" : ("ConsoleDataBlock.FillAttributes", list),
         "Popup Fill Attributes" : ("ConsoleDataBlock.PopupFillAttributes", list),
         "Screen Buffer Size X" : ("ConsoleDataBlock.ScreenBufferSizeX", int),	
         "Screen Buffer Size Y": ("ConsoleDataBlock.ScreenBufferSizeY", int),	
         "Window Size X" : ("ConsoleDataBlock.WindowSizeX", int),
         "Window Size Y" : ("ConsoleDataBlock.WindowSizeY", int),	
         "Window Origin X" : ("ConsoleDataBlock.WindowOriginX", int),
         "Window Origin Y" : ("ConsoleDataBlock.WindowOriginY", int),	
         "Font Size" : ("ConsoleDataBlock.FontSize", int),
         "Font Family" : ("ConsoleDataBlock.FontFamily", str),
         "Font Weight" : ("ConsoleDataBlock.FontWeight", int),
         "Face Name" : ("ConsoleDataBlock.FaceName", str),
         "Cursor Size" : ("ConsoleDataBlock.CursorSize", int),
         "Full Screen" : ("ConsoleDataBlock.FullScreen", int),
         "Quick Edit" : ("ConsoleDataBlock.QuickEdit", int),
         "Insert Mode" : ("ConsoleDataBlock.InsertMode", int),
         "Auto Position" : ("ConsoleDataBlock.AutoPosition", int),
         "History Buffer Size" : ("ConsoleDataBlock.HistoryBufferSize", int),
         "Number Of History Buffers" : ("ConsoleDataBlock.NumberOfHistoryBuffers", int),
         "History No Dup" : ("ConsoleDataBlock.HistoryNoDup", int),
       },
	  }
