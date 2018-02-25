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
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#ifndef __GPTTYPES_HPP__
#define __GPTTYPES_HPP__

const static struct gpt_map
{
  char	guid[37];
  char	fstype[128];
}	guid_map[] = {
  {"00000000-0000-0000-0000-000000000000", "Unused entry"},
  {"024DEE41-33E7-11D3-9D69-0008C781F39F", "MBR partition scheme"},
  {"C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "EFI System partition"},
  {"21686148-6449-6E6F-744E-656564454649", "BIOS Boot partition"},
  {"D3BFE2DE-3DAF-11DF-BA40-E3A556D89593", "Intel Fast Flash (iFFS) partition (for Intel Rapid Start technology)"},
  {"E3C9E316-0B5C-4DB8-817D-F92DF00215AE", "Windows - Microsoft Reserved Partition"},
  {"EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", "Windows - Basic data partition"},
  {"5808C8AA-7E8F-42E0-85D2-E1E90434CFB3", "Windows - Logical Disk Manager (LDM) metadata partition"},
  {"AF9B60A0-1431-4F62-BC68-3311714A69AD", "Windows - Logical Disk Manager data partition"},
  {"DE94BBA4-06D1-4D40-A16A-BFD50179D6AC", "Windows - Windows Recovery Environment"},
  {"37AFFC90-EF7D-4E96-91C3-2D7AE055B174", "Windows - IBM General Parallel File System (GPFS) partition"},
  {"75894C1E-3AEB-11D3-B7C1-7B03A0000000", "HP-UX - Data partition"},
  {"E2A1E728-32E3-11D6-A682-7B03A0000000", "HP-UX - Service Partition"},
  {"0FC63DAF-8483-4772-8E79-3D69D8477DE4", "Linux filesystem data"},
  {"A19D880F-05FC-4D3B-A006-743F0F84911E", "Linux - RAID partition"},
  {"0657FD6D-A4AB-43C4-84E5-0933C84B4F4F", "Linux - Swap partition"},
  {"E6D6D379-F507-44C2-A23C-238F2A3DF928", "Linux - Logical Volume Manager (LVM) partition"},
  {"8DA63339-0007-60C0-C436-083AC8230908", "Linux - Reserved"},
  {"83BD6B9D-7F41-11DC-BE0B-001560B84F0F", "FreeBSD - Boot partition"},
  {"516E7CB4-6ECF-11D6-8FF8-00022D09712B", "FreeBSD - Data partition"},
  {"516E7CB5-6ECF-11D6-8FF8-00022D09712B", "FreeBSD - Swap partition"},
  {"516E7CB6-6ECF-11D6-8FF8-00022D09712B", "FreeBSD - Unix File System (UFS) partition"},
  {"516E7CB8-6ECF-11D6-8FF8-00022D09712B", "FreeBSD - Vinum volume manager partition"},
  {"516E7CBA-6ECF-11D6-8FF8-00022D09712B", "FreeBSD - ZFS partition"},
  {"48465300-0000-11AA-AA11-00306543ECAC", "Mac OS X - Hierarchical File System Plus (HFS+) partition"},
  {"55465300-0000-11AA-AA11-00306543ECAC", "Mac OS X - Apple UFS"},
  {"6A898CC3-1DD2-11B2-99A6-080020736631", "Mac OS X - ZFS"},
  {"52414944-0000-11AA-AA11-00306543ECAC", "Mac OS X - Apple RAID partition"},
  {"52414944-5F4F-11AA-AA11-00306543ECAC", "Mac OS X - Apple RAID partition, offline"},
  {"426F6F74-0000-11AA-AA11-00306543ECAC", "Mac OS X - Apple Boot partition"},
  {"4C616265-6C00-11AA-AA11-00306543ECAC", "Mac OS X - Apple Label"},
  {"5265636F-7665-11AA-AA11-00306543ECAC", "Mac OS X - Apple TV Recovery partition"},
  {"53746F72-6167-11AA-AA11-00306543ECAC", "Mac OS X - Apple Core Storage (i.e. Lion FileVault) partition"},
  {"6A82CB45-1DD2-11B2-99A6-080020736631", "Solaris - Boot partition"},
  {"6A85CF4D-1DD2-11B2-99A6-080020736631", "Solaris - Root partition"},
  {"6A87C46F-1DD2-11B2-99A6-080020736631", "Solaris - Swap partition"},
  {"6A8B642B-1DD2-11B2-99A6-080020736631", "Solaris - Backup partition"},
  {"6A898CC3-1DD2-11B2-99A6-080020736631", "Solaris - /usr partition"},
  {"6A8EF2E9-1DD2-11B2-99A6-080020736631", "Solaris - /var partition"},
  {"6A90BA39-1DD2-11B2-99A6-080020736631", "Solaris - /home partition"},
  {"6A9283A5-1DD2-11B2-99A6-080020736631", "Solaris - Alternate sector"},
  {"6A945A3B-1DD2-11B2-99A6-080020736631", "Solaris - Reserved partition"},
  {"6A9630D1-1DD2-11B2-99A6-080020736631", "Solaris - Reserved partition"},
  {"6A980767-1DD2-11B2-99A6-080020736631", "Solaris - Reserved partition"},
  {"6A96237F-1DD2-11B2-99A6-080020736631", "Solaris - Reserved partition"},
  {"6A8D2AC7-1DD2-11B2-99A6-080020736631", "Solaris - Reserved partition"},
  {"49F48D32-B10E-11DC-B99B-0019D1879648", "NetBSD - Swap partition"},
  {"49F48D5A-B10E-11DC-B99B-0019D1879648", "NetBSD - FFS partition"},
  {"49F48D82-B10E-11DC-B99B-0019D1879648", "NetBSD - LFS partition"},
  {"49F48DAA-B10E-11DC-B99B-0019D1879648", "NetBSD - RAID partition"},
  {"2DB519C4-B10F-11DC-B99B-0019D1879648", "NetBSD - Concatenated partition"},
  {"2DB519EC-B10F-11DC-B99B-0019D1879648", "NetBSD - Encrypted partition"},
  {"FE3A2A5D-4F32-41A7-B725-ACCC3285A309", "ChromeOS - ChromeOS kernel"},
  {"3CB8E202-3B7E-47DD-8A3C-7FF2A13CFCEC", "ChromeOS - ChromeOS rootfs"},
  {"2E0A753D-9E48-43B0-8337-B15192CB1B5E", "ChromeOS future use"},
  {"42465331-3BA3-10F1-802A-4861696B7521", "Haiku - Haiku BFS"},
  {"85D5E45E-237C-11E1-B4B3-E89A8F7FC3A7", "MidnightBSD - Boot partition"},
  {"85D5E45A-237C-11E1-B4B3-E89A8F7FC3A7", "MidnightBSD - Data partition"},
  {"85D5E45B-237C-11E1-B4B3-E89A8F7FC3A7", "MidnightBSD - Swap partition"},
  {"0394EF8B-237E-11E1-B4B3-E89A8F7FC3A7", "MidnightBSD - Unix File System (UFS) partition"},
  {"85D5E45C-237C-11E1-B4B3-E89A8F7FC3A7", "MidnightBSD - Vinum volume manager partition"},
  {"85D5E45D-237C-11E1-B4B3-E89A8F7FC3A7", "MidnightBSD - ZFS partition"},
  {"\0", "\0"} //sentinel
};

#endif
