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


#include "crashdumpinfo.hpp"
#include "processor/symbolic_constants_win.h"
#include <sstream>
#include <string>
#ifdef WIN32
	#define snprintf _snprintf
#endif

CrashDumpInfo::CrashDumpInfo() : __minidump(NULL), __sysinfo(NULL), __rawSysinfo(NULL), __exception(NULL),
				 __rawException(NULL), __processorArchitecture(""), __cpuInformation(""),
				 __osName(""), __osVersion(""), __crashAddress(0), __crashReason("")
{
}


CrashDumpInfo::~CrashDumpInfo()
{
}


void	CrashDumpInfo::process(std::string minidumpPath) throw (std::string)
{
  this->process(minidumpPath.c_str());
}


void	CrashDumpInfo::process(char* minidumpPath) throw (std::string)
{
  std::string	err;

  this->__minidump = new google_breakpad::Minidump(minidumpPath);
  if (!this->__minidump->Read())
    {
      err = "Minidump " + this->__minidump->path() + " could not be read";
      throw err;
    }
  this->__sysinfo = this->__minidump->GetSystemInfo();
  if (!this->__sysinfo)
    throw std::string("Cannot get System Information");
  this->__rawSysinfo = this->__sysinfo->system_info();
  if (!this->__rawSysinfo)
    throw std::string("Cannot get raw System Information");
  this->__setCpuInformation();
  this->__setOsInformation();
  if (((this->__exception = this->__minidump->GetException()) != NULL) &&
      ((this->__rawException = this->__exception->exception()) != NULL))
      this->__setCrashReason();
}


void		CrashDumpInfo::print()
{
  std::cout << this->details();
}


std::string		CrashDumpInfo::minidumpPath()
{
  if (this->__minidump)
    return this->__minidump->path();
  else
    return std::string();
}


std::string		CrashDumpInfo::details()
{
  std::stringstream	details;

  details << "Operating system information:" << std::endl;
  details << "\tName: " << this->operatingSystemName() << std::endl;
  details << "\tVersion: " << this->operatingSystemVersion() << std::endl;
  details << "Processor information:" << std::endl;
  details << "\tArchitecture: " << this->processorArchitecture() << std::endl;
  details << "\tVendor, family: " << this->cpuInformation() << std::endl;
  details << "\tNumber of processors: " << this->numberOfProcessors() << std::endl;
  details << "Crash information:" << std::endl;
  details << "\taddress: " << this->crashAddress() << std::endl;
  details << "\treason: " << this->crashReason() << std::endl;
  return details.str();
}


std::string	CrashDumpInfo::processorArchitecture()
{
  return this->__processorArchitecture;
}


std::string	CrashDumpInfo::cpuInformation()
{
  return this->__cpuInformation;
}


std::string	CrashDumpInfo::numberOfProcessors()
{
  std::stringstream     nproc;
  nproc << (unsigned int)this->__rawSysinfo->number_of_processors;
  return nproc.str();
}


std::string	CrashDumpInfo::operatingSystemName()
{
  return this->__osName;
}


std::string	CrashDumpInfo::operatingSystemVersion()
{
  return this->__osVersion;
}


std::string	CrashDumpInfo::crashAddress()
{
  std::stringstream     address;
  address << (unsigned long long)this->__crashAddress;
  return address.str();
}


std::string	CrashDumpInfo::crashReason()
{
  return this->__crashReason;
}


//
// Most of the following code is based on google breakpad 
// minidump_processor.cc and adapted to suit our needs.
//


void		CrashDumpInfo::__armCpuInfo()
{
  // Write ARM architecture version.
  char cpu_string[32];
  snprintf(cpu_string, sizeof(cpu_string), "ARMv%d",
           this->__rawSysinfo->processor_level);
  this->__cpuInformation.append(cpu_string);

  // There is no good list of implementer id values, but the following
  // pages provide some help:
  //   http://comments.gmane.org/gmane.linux.linaro.devel/6903
  //   http://forum.xda-developers.com/archive/index.php/t-480226.html
  const struct 
  {
    uint32_t id;
    const char* name;
  } vendors[] = 
      {
	{ 0x41, "ARM" },
	{ 0x51, "Qualcomm" },
	{ 0x56, "Marvell" },
	{ 0x69, "Intel/Marvell" },
      };
  const struct 
  {
    uint32_t id;
    const char* name;
  } parts[] = 
      {
	{ 0x4100c050, "Cortex-A5" },
	{ 0x4100c080, "Cortex-A8" },
	{ 0x4100c090, "Cortex-A9" },
	{ 0x4100c0f0, "Cortex-A15" },
	{ 0x4100c140, "Cortex-R4" },
	{ 0x4100c150, "Cortex-R5" },
	{ 0x4100b360, "ARM1136" },
	{ 0x4100b560, "ARM1156" },
	{ 0x4100b760, "ARM1176" },
	{ 0x4100b020, "ARM11-MPCore" },
	{ 0x41009260, "ARM926" },
	{ 0x41009460, "ARM946" },
	{ 0x41009660, "ARM966" },
	{ 0x510006f0, "Krait" },
	{ 0x510000f0, "Scorpion" },
      };
  
  const struct 
  {
    uint32_t hwcap;
    const char* name;
  } features[] = 
      {
	{ MD_CPU_ARM_ELF_HWCAP_SWP, "swp" },
	{ MD_CPU_ARM_ELF_HWCAP_HALF, "half" },
	{ MD_CPU_ARM_ELF_HWCAP_THUMB, "thumb" },
	{ MD_CPU_ARM_ELF_HWCAP_26BIT, "26bit" },
	{ MD_CPU_ARM_ELF_HWCAP_FAST_MULT, "fastmult" },
	{ MD_CPU_ARM_ELF_HWCAP_FPA, "fpa" },
	{ MD_CPU_ARM_ELF_HWCAP_VFP, "vfpv2" },
	{ MD_CPU_ARM_ELF_HWCAP_EDSP, "edsp" },
	{ MD_CPU_ARM_ELF_HWCAP_JAVA, "java" },
	{ MD_CPU_ARM_ELF_HWCAP_IWMMXT, "iwmmxt" },
	{ MD_CPU_ARM_ELF_HWCAP_CRUNCH, "crunch" },
	{ MD_CPU_ARM_ELF_HWCAP_THUMBEE, "thumbee" },
	{ MD_CPU_ARM_ELF_HWCAP_NEON, "neon" },
	{ MD_CPU_ARM_ELF_HWCAP_VFPv3, "vfpv3" },
	{ MD_CPU_ARM_ELF_HWCAP_VFPv3D16, "vfpv3d16" },
	{ MD_CPU_ARM_ELF_HWCAP_TLS, "tls" },
	{ MD_CPU_ARM_ELF_HWCAP_VFPv4, "vfpv4" },
	{ MD_CPU_ARM_ELF_HWCAP_IDIVA, "idiva" },
	{ MD_CPU_ARM_ELF_HWCAP_IDIVT, "idivt" },
      };

  uint32_t cpuid = this->__rawSysinfo->cpu.arm_cpu_info.cpuid;
  if (cpuid != 0) 
    {
      // Extract vendor name from CPUID
      const char* vendor = NULL;
      uint32_t vendor_id = (cpuid >> 24) & 0xff;
      for (size_t i = 0; i < sizeof(vendors)/sizeof(vendors[0]); ++i) 
	{
	  if (vendors[i].id == vendor_id) 
	    {
	      vendor = vendors[i].name;
	      break;
	    }
	}
      this->__cpuInformation.append(" ");
    if (vendor) 
      {
	this->__cpuInformation.append(vendor);
      } 
    else 
      {
	snprintf(cpu_string, sizeof(cpu_string), "vendor(0x%x)", vendor_id);
	this->__cpuInformation.append(cpu_string);
    }

    // Extract part name from CPUID
    uint32_t part_id = (cpuid & 0xff00fff0);
    const char* part = NULL;
    for (size_t i = 0; i < sizeof(parts)/sizeof(parts[0]); ++i) 
      {
	if (parts[i].id == part_id) 
	  {
	    part = parts[i].name;
	    break;
	  }
      }
    this->__cpuInformation.append(" ");
    if (part != NULL) 
      {
	this->__cpuInformation.append(part);
      } 
    else 
      {
	snprintf(cpu_string, sizeof(cpu_string), "part(0x%x)", part_id);
	this->__cpuInformation.append(cpu_string);
      }
    }
  uint32_t elf_hwcaps = this->__rawSysinfo->cpu.arm_cpu_info.elf_hwcaps;
  if (elf_hwcaps != 0) 
    {
      this->__cpuInformation.append(" features: ");
      const char* comma = "";
      for (size_t i = 0; i < sizeof(features)/sizeof(features[0]); ++i) 
	{
	  if (elf_hwcaps & features[i].hwcap) 
	    {
	      this->__cpuInformation.append(comma);
	      this->__cpuInformation.append(features[i].name);
	      comma = ",";
	    }
	}
    }
}


void		CrashDumpInfo::__setCpuInformation()
{
  switch (this->__rawSysinfo->processor_architecture) 
    {
    case MD_CPU_ARCHITECTURE_X86:
    case MD_CPU_ARCHITECTURE_AMD64: 
      {
	if (this->__rawSysinfo->processor_architecture == MD_CPU_ARCHITECTURE_X86)
	  this->__processorArchitecture = "x86";
	else
	  this->__processorArchitecture = "amd64";

	const string *cpu_vendor = this->__sysinfo->GetCPUVendor();
	if (cpu_vendor) 
	  {
	    this->__cpuInformation = *cpu_vendor;
	    this->__cpuInformation.append(" ");
	  }


      char x86_info[36];
      snprintf(x86_info, sizeof(x86_info), "family %u model %u stepping %u",
               this->__rawSysinfo->processor_level,
               this->__rawSysinfo->processor_revision >> 8,
               this->__rawSysinfo->processor_revision & 0xff);
      this->__cpuInformation.append(x86_info);
      break;
    }

    case MD_CPU_ARCHITECTURE_PPC: 
      {
	this->__processorArchitecture = "ppc";
	break;
      }

    case MD_CPU_ARCHITECTURE_PPC64: 
      {
	this->__processorArchitecture = "ppc64";
	break;
      }

    case MD_CPU_ARCHITECTURE_SPARC: 
      {
	this->__processorArchitecture = "sparc";
	break;
      }

    case MD_CPU_ARCHITECTURE_ARM: 
      {
	this->__processorArchitecture = "arm";
	this->__armCpuInfo();
	break;
      }

    case MD_CPU_ARCHITECTURE_ARM64: 
      {
	this->__processorArchitecture = "arm64";
	break;
      }

    case MD_CPU_ARCHITECTURE_MIPS: 
      {
	this->__processorArchitecture = "mips";
	break;
      }
      
    default: 
      {
	// Assign the numeric architecture ID into the CPU string.
	char cpu_string[7];
	snprintf(cpu_string, sizeof(cpu_string), "0x%04x",
		 this->__rawSysinfo->processor_architecture);
	this->__processorArchitecture = cpu_string;
	break;
      }
    }
}


void		CrashDumpInfo::__setOsInformation()
{
  switch (this->__rawSysinfo->platform_id) 
    {
    case MD_OS_WIN32_NT: 
      {
	this->__osName = "Windows NT";
	break;
      }
      
    case MD_OS_WIN32_WINDOWS: 
      {
	this->__osName = "Windows";
	break;
      }

    case MD_OS_MAC_OS_X: 
      {
	this->__osName = "Mac OS X";
	break;
      }

    case MD_OS_IOS: 
      {
	this->__osName = "iOS";
	break;
      }

    case MD_OS_LINUX: 
      {
	this->__osName = "Linux";
	break;
      }

    case MD_OS_SOLARIS: 
      {
	this->__osName = "Solaris";
	break;
      }

    case MD_OS_ANDROID: 
      {
	this->__osName = "Android";
	break;
      }

    case MD_OS_PS3: 
      {
	this->__osName = "PS3";
	break;
      }
      
    case MD_OS_NACL: 
      {
	this->__osName = "NaCl";
	break;
      }

    default: 
      {
	// Assign the numeric platform ID into the OS string.
	char os_string[11];
	snprintf(os_string, sizeof(os_string), "0x%08x",
		 this->__rawSysinfo->platform_id);
	this->__osName = os_string;
	break;
      }
    }
  
  char os_version_string[33];
  snprintf(os_version_string, sizeof(os_version_string), "%u.%u.%u",
           this->__rawSysinfo->major_version,
           this->__rawSysinfo->minor_version,
           this->__rawSysinfo->build_number);
  this->__osVersion = os_version_string;
  const std::string* csd_version = this->__sysinfo->GetCSDVersion();
  if (csd_version) 
    {
      this->__osVersion.append(" ");
      this->__osVersion.append(*csd_version);
    }
}


void		CrashDumpInfo::__setCrashReason()
{
  this->__crashAddress = this->__rawException->exception_record.exception_address;

  // The reason value is OS-specific and possibly CPU-specific.  Set up
  // sensible numeric defaults for the reason string in case we can't
  // map the codes to a string (because there's no system info, or because
  // it's an unrecognized platform, or because it's an unrecognized code.)
  char reason_string[24];
  uint32_t exception_code = this->__rawException->exception_record.exception_code;
  uint32_t exception_flags = this->__rawException->exception_record.exception_flags;
  snprintf(reason_string, sizeof(reason_string), "0x%08x / 0x%08x",
           exception_code, exception_flags);
  string reason = reason_string;

  switch (this->__rawSysinfo->platform_id) {
    case MD_OS_MAC_OS_X:
    case MD_OS_IOS: {
      char flags_string[11];
      snprintf(flags_string, sizeof(flags_string), "0x%08x", exception_flags);
      switch (exception_code) {
        case MD_EXCEPTION_MAC_BAD_ACCESS:
          reason = "EXC_BAD_ACCESS / ";
          switch (exception_flags) {
            case MD_EXCEPTION_CODE_MAC_INVALID_ADDRESS:
              reason.append("KERN_INVALID_ADDRESS");
              break;
            case MD_EXCEPTION_CODE_MAC_PROTECTION_FAILURE:
              reason.append("KERN_PROTECTION_FAILURE");
              break;
            case MD_EXCEPTION_CODE_MAC_NO_ACCESS:
              reason.append("KERN_NO_ACCESS");
              break;
            case MD_EXCEPTION_CODE_MAC_MEMORY_FAILURE:
              reason.append("KERN_MEMORY_FAILURE");
              break;
            case MD_EXCEPTION_CODE_MAC_MEMORY_ERROR:
              reason.append("KERN_MEMORY_ERROR");
              break;
            default:
              // arm and ppc overlap
              if (this->__rawSysinfo->processor_architecture ==
                  MD_CPU_ARCHITECTURE_ARM ||
                  this->__rawSysinfo->processor_architecture ==
                  MD_CPU_ARCHITECTURE_ARM64) {
                switch (exception_flags) {
                  case MD_EXCEPTION_CODE_MAC_ARM_DA_ALIGN:
                    reason.append("EXC_ARM_DA_ALIGN");
                    break;
                  case MD_EXCEPTION_CODE_MAC_ARM_DA_DEBUG:
                    reason.append("EXC_ARM_DA_DEBUG");
                    break;
                  default:
                    reason.append(flags_string);
                    break;
                }
              } else if (this->__rawSysinfo->processor_architecture ==
                         MD_CPU_ARCHITECTURE_PPC) {
                switch (exception_flags) {
                  case MD_EXCEPTION_CODE_MAC_PPC_VM_PROT_READ:
                    reason.append("EXC_PPC_VM_PROT_READ");
                    break;
                  case MD_EXCEPTION_CODE_MAC_PPC_BADSPACE:
                    reason.append("EXC_PPC_BADSPACE");
                    break;
                  case MD_EXCEPTION_CODE_MAC_PPC_UNALIGNED:
                    reason.append("EXC_PPC_UNALIGNED");
                    break;
                  default:
                    reason.append(flags_string);
                    break;
                }
              } else {
                reason.append(flags_string);
              }
              break;
          }
          break;
        case MD_EXCEPTION_MAC_BAD_INSTRUCTION:
          reason = "EXC_BAD_INSTRUCTION / ";
          switch (this->__rawSysinfo->processor_architecture) {
            case MD_CPU_ARCHITECTURE_ARM:
            case MD_CPU_ARCHITECTURE_ARM64: {
              switch (exception_flags) {
                case MD_EXCEPTION_CODE_MAC_ARM_UNDEFINED:
                  reason.append("EXC_ARM_UNDEFINED");
                  break;
                default:
                  reason.append(flags_string);
                  break;
              }
              break;
            }
            case MD_CPU_ARCHITECTURE_PPC: {
              switch (exception_flags) {
                case MD_EXCEPTION_CODE_MAC_PPC_INVALID_SYSCALL:
                  reason.append("EXC_PPC_INVALID_SYSCALL");
                  break;
                case MD_EXCEPTION_CODE_MAC_PPC_UNIMPLEMENTED_INSTRUCTION:
                  reason.append("EXC_PPC_UNIPL_INST");
                  break;
                case MD_EXCEPTION_CODE_MAC_PPC_PRIVILEGED_INSTRUCTION:
                  reason.append("EXC_PPC_PRIVINST");
                  break;
                case MD_EXCEPTION_CODE_MAC_PPC_PRIVILEGED_REGISTER:
                  reason.append("EXC_PPC_PRIVREG");
                  break;
                case MD_EXCEPTION_CODE_MAC_PPC_TRACE:
                  reason.append("EXC_PPC_TRACE");
                  break;
                case MD_EXCEPTION_CODE_MAC_PPC_PERFORMANCE_MONITOR:
                  reason.append("EXC_PPC_PERFMON");
                  break;
                default:
                  reason.append(flags_string);
                  break;
              }
              break;
            }
            case MD_CPU_ARCHITECTURE_X86: {
              switch (exception_flags) {
                case MD_EXCEPTION_CODE_MAC_X86_INVALID_OPERATION:
                  reason.append("EXC_I386_INVOP");
                  break;
                case MD_EXCEPTION_CODE_MAC_X86_INVALID_TASK_STATE_SEGMENT:
                  reason.append("EXC_INVTSSFLT");
                  break;
                case MD_EXCEPTION_CODE_MAC_X86_SEGMENT_NOT_PRESENT:
                  reason.append("EXC_SEGNPFLT");
                  break;
                case MD_EXCEPTION_CODE_MAC_X86_STACK_FAULT:
                  reason.append("EXC_STKFLT");
                  break;
                case MD_EXCEPTION_CODE_MAC_X86_GENERAL_PROTECTION_FAULT:
                  reason.append("EXC_GPFLT");
                  break;
                case MD_EXCEPTION_CODE_MAC_X86_ALIGNMENT_FAULT:
                  reason.append("EXC_ALIGNFLT");
                  break;
                default:
                  reason.append(flags_string);
                  break;
              }
              break;
            }
            default:
              reason.append(flags_string);
              break;
          }
          break;
        case MD_EXCEPTION_MAC_ARITHMETIC:
          reason = "EXC_ARITHMETIC / ";
          switch (this->__rawSysinfo->processor_architecture) {
            case MD_CPU_ARCHITECTURE_PPC: {
              switch (exception_flags) {
                case MD_EXCEPTION_CODE_MAC_PPC_OVERFLOW:
                  reason.append("EXC_PPC_OVERFLOW");
                  break;
                case MD_EXCEPTION_CODE_MAC_PPC_ZERO_DIVIDE:
                  reason.append("EXC_PPC_ZERO_DIVIDE");
                  break;
                case MD_EXCEPTION_CODE_MAC_PPC_FLOAT_INEXACT:
                  reason.append("EXC_FLT_INEXACT");
                  break;
                case MD_EXCEPTION_CODE_MAC_PPC_FLOAT_ZERO_DIVIDE:
                  reason.append("EXC_PPC_FLT_ZERO_DIVIDE");
                  break;
                case MD_EXCEPTION_CODE_MAC_PPC_FLOAT_UNDERFLOW:
                  reason.append("EXC_PPC_FLT_UNDERFLOW");
                  break;
                case MD_EXCEPTION_CODE_MAC_PPC_FLOAT_OVERFLOW:
                  reason.append("EXC_PPC_FLT_OVERFLOW");
                  break;
                case MD_EXCEPTION_CODE_MAC_PPC_FLOAT_NOT_A_NUMBER:
                  reason.append("EXC_PPC_FLT_NOT_A_NUMBER");
                  break;
                case MD_EXCEPTION_CODE_MAC_PPC_NO_EMULATION:
                  reason.append("EXC_PPC_NOEMULATION");
                  break;
                case MD_EXCEPTION_CODE_MAC_PPC_ALTIVEC_ASSIST:
                  reason.append("EXC_PPC_ALTIVECASSIST");
                default:
                  reason.append(flags_string);
                  break;
              }
              break;
            }
            case MD_CPU_ARCHITECTURE_X86: {
              switch (exception_flags) {
                case MD_EXCEPTION_CODE_MAC_X86_DIV:
                  reason.append("EXC_I386_DIV");
                  break;
                case MD_EXCEPTION_CODE_MAC_X86_INTO:
                  reason.append("EXC_I386_INTO");
                  break;
                case MD_EXCEPTION_CODE_MAC_X86_NOEXT:
                  reason.append("EXC_I386_NOEXT");
                  break;
                case MD_EXCEPTION_CODE_MAC_X86_EXTOVR:
                  reason.append("EXC_I386_EXTOVR");
                  break;
                case MD_EXCEPTION_CODE_MAC_X86_EXTERR:
                  reason.append("EXC_I386_EXTERR");
                  break;
                case MD_EXCEPTION_CODE_MAC_X86_EMERR:
                  reason.append("EXC_I386_EMERR");
                  break;
                case MD_EXCEPTION_CODE_MAC_X86_BOUND:
                  reason.append("EXC_I386_BOUND");
                  break;
                case MD_EXCEPTION_CODE_MAC_X86_SSEEXTERR:
                  reason.append("EXC_I386_SSEEXTERR");
                  break;
                default:
                  reason.append(flags_string);
                  break;
              }
              break;
            }
            default:
              reason.append(flags_string);
              break;
          }
          break;
        case MD_EXCEPTION_MAC_EMULATION:
          reason = "EXC_EMULATION / ";
          reason.append(flags_string);
          break;
        case MD_EXCEPTION_MAC_SOFTWARE:
          reason = "EXC_SOFTWARE / ";
          switch (exception_flags) {
            case MD_EXCEPTION_CODE_MAC_ABORT:
              reason.append("SIGABRT");
              break;
            case MD_EXCEPTION_CODE_MAC_NS_EXCEPTION:
              reason.append("UNCAUGHT_NS_EXCEPTION");
              break;
            // These are ppc only but shouldn't be a problem as they're
            // unused on x86
            case MD_EXCEPTION_CODE_MAC_PPC_TRAP:
              reason.append("EXC_PPC_TRAP");
              break;
            case MD_EXCEPTION_CODE_MAC_PPC_MIGRATE:
              reason.append("EXC_PPC_MIGRATE");
              break;
            default:
              reason.append(flags_string);
              break;
          }
          break;
        case MD_EXCEPTION_MAC_BREAKPOINT:
          reason = "EXC_BREAKPOINT / ";
          switch (this->__rawSysinfo->processor_architecture) {
            case MD_CPU_ARCHITECTURE_ARM:
            case MD_CPU_ARCHITECTURE_ARM64: {
              switch (exception_flags) {
                case MD_EXCEPTION_CODE_MAC_ARM_DA_ALIGN:
                  reason.append("EXC_ARM_DA_ALIGN");
                  break;
                case MD_EXCEPTION_CODE_MAC_ARM_DA_DEBUG:
                  reason.append("EXC_ARM_DA_DEBUG");
                  break;
                case MD_EXCEPTION_CODE_MAC_ARM_BREAKPOINT:
                  reason.append("EXC_ARM_BREAKPOINT");
                  break;
                default:
                  reason.append(flags_string);
                  break;
              }
              break;
            }
            case MD_CPU_ARCHITECTURE_PPC: {
              switch (exception_flags) {
                case MD_EXCEPTION_CODE_MAC_PPC_BREAKPOINT:
                  reason.append("EXC_PPC_BREAKPOINT");
                  break;
                default:
                  reason.append(flags_string);
                  break;
              }
              break;
            }
            case MD_CPU_ARCHITECTURE_X86: {
              switch (exception_flags) {
                case MD_EXCEPTION_CODE_MAC_X86_SGL:
                  reason.append("EXC_I386_SGL");
                  break;
                case MD_EXCEPTION_CODE_MAC_X86_BPT:
                  reason.append("EXC_I386_BPT");
                  break;
                default:
                  reason.append(flags_string);
                  break;
              }
              break;
            }
            default:
              reason.append(flags_string);
              break;
          }
          break;
        case MD_EXCEPTION_MAC_SYSCALL:
          reason = "EXC_SYSCALL / ";
          reason.append(flags_string);
          break;
        case MD_EXCEPTION_MAC_MACH_SYSCALL:
          reason = "EXC_MACH_SYSCALL / ";
          reason.append(flags_string);
          break;
        case MD_EXCEPTION_MAC_RPC_ALERT:
          reason = "EXC_RPC_ALERT / ";
          reason.append(flags_string);
          break;
      }
      break;
    }

    case MD_OS_WIN32_NT:
    case MD_OS_WIN32_WINDOWS: {
      switch (exception_code) {
        case MD_EXCEPTION_CODE_WIN_CONTROL_C:
          reason = "DBG_CONTROL_C";
          break;
        case MD_EXCEPTION_CODE_WIN_GUARD_PAGE_VIOLATION:
          reason = "EXCEPTION_GUARD_PAGE";
          break;
        case MD_EXCEPTION_CODE_WIN_DATATYPE_MISALIGNMENT:
          reason = "EXCEPTION_DATATYPE_MISALIGNMENT";
          break;
        case MD_EXCEPTION_CODE_WIN_BREAKPOINT:
          reason = "EXCEPTION_BREAKPOINT";
          break;
        case MD_EXCEPTION_CODE_WIN_SINGLE_STEP:
          reason = "EXCEPTION_SINGLE_STEP";
          break;
        case MD_EXCEPTION_CODE_WIN_ACCESS_VIOLATION:
          // For EXCEPTION_ACCESS_VIOLATION, Windows puts the address that
          // caused the fault in exception_information[1].
          // exception_information[0] is 0 if the violation was caused by
          // an attempt to read data, 1 if it was an attempt to write data,
          // and 8 if this was a data execution violation.
          // This information is useful in addition to the code address, which
          // will be present in the crash thread's instruction field anyway.
          if (this->__rawException->exception_record.number_parameters >= 1) {
            MDAccessViolationTypeWin av_type =
                static_cast<MDAccessViolationTypeWin>
                (this->__rawException->exception_record.exception_information[0]);
            switch (av_type) {
              case MD_ACCESS_VIOLATION_WIN_READ:
                reason = "EXCEPTION_ACCESS_VIOLATION_READ";
                break;
              case MD_ACCESS_VIOLATION_WIN_WRITE:
                reason = "EXCEPTION_ACCESS_VIOLATION_WRITE";
                break;
              case MD_ACCESS_VIOLATION_WIN_EXEC:
                reason = "EXCEPTION_ACCESS_VIOLATION_EXEC";
                break;
              default:
                reason = "EXCEPTION_ACCESS_VIOLATION";
                break;
            }
          } else {
            reason = "EXCEPTION_ACCESS_VIOLATION";
          }
          if (this->__rawException->exception_record.number_parameters >= 2) 
	    this->__crashAddress = this->__rawException->exception_record.exception_information[1];
          break;
        case MD_EXCEPTION_CODE_WIN_IN_PAGE_ERROR:
          // For EXCEPTION_IN_PAGE_ERROR, Windows puts the address that
          // caused the fault in exception_information[1].
          // exception_information[0] is 0 if the violation was caused by
          // an attempt to read data, 1 if it was an attempt to write data,
          // and 8 if this was a data execution violation.
          // exception_information[2] contains the underlying NTSTATUS code,
          // which is the explanation for why this error occured.
          // This information is useful in addition to the code address, which
          // will be present in the crash thread's instruction field anyway.
          if (this->__rawException->exception_record.number_parameters >= 1) {
            MDInPageErrorTypeWin av_type =
                static_cast<MDInPageErrorTypeWin>
                (this->__rawException->exception_record.exception_information[0]);
            switch (av_type) {
              case MD_IN_PAGE_ERROR_WIN_READ:
                reason = "EXCEPTION_IN_PAGE_ERROR_READ";
                break;
              case MD_IN_PAGE_ERROR_WIN_WRITE:
                reason = "EXCEPTION_IN_PAGE_ERROR_WRITE";
                break;
              case MD_IN_PAGE_ERROR_WIN_EXEC:
                reason = "EXCEPTION_IN_PAGE_ERROR_EXEC";
                break;
              default:
                reason = "EXCEPTION_IN_PAGE_ERROR";
                break;
            }
          } else {
            reason = "EXCEPTION_IN_PAGE_ERROR";
          }
          if (this->__rawException->exception_record.number_parameters >= 2)
            this->__crashAddress = this->__rawException->exception_record.exception_information[1];
          if (this->__rawException->exception_record.number_parameters >= 3) {
            uint32_t ntstatus =
                static_cast<uint32_t>
                (this->__rawException->exception_record.exception_information[2]);
            reason.append(" / ");
            reason.append(google_breakpad::NTStatusToString(ntstatus));
          }
          break;
        case MD_EXCEPTION_CODE_WIN_INVALID_HANDLE:
          reason = "EXCEPTION_INVALID_HANDLE";
          break;
        case MD_EXCEPTION_CODE_WIN_ILLEGAL_INSTRUCTION:
          reason = "EXCEPTION_ILLEGAL_INSTRUCTION";
          break;
        case MD_EXCEPTION_CODE_WIN_NONCONTINUABLE_EXCEPTION:
          reason = "EXCEPTION_NONCONTINUABLE_EXCEPTION";
          break;
        case MD_EXCEPTION_CODE_WIN_INVALID_DISPOSITION:
          reason = "EXCEPTION_INVALID_DISPOSITION";
          break;
        case MD_EXCEPTION_CODE_WIN_ARRAY_BOUNDS_EXCEEDED:
          reason = "EXCEPTION_BOUNDS_EXCEEDED";
          break;
        case MD_EXCEPTION_CODE_WIN_FLOAT_DENORMAL_OPERAND:
          reason = "EXCEPTION_FLT_DENORMAL_OPERAND";
          break;
        case MD_EXCEPTION_CODE_WIN_FLOAT_DIVIDE_BY_ZERO:
          reason = "EXCEPTION_FLT_DIVIDE_BY_ZERO";
          break;
        case MD_EXCEPTION_CODE_WIN_FLOAT_INEXACT_RESULT:
          reason = "EXCEPTION_FLT_INEXACT_RESULT";
          break;
        case MD_EXCEPTION_CODE_WIN_FLOAT_INVALID_OPERATION:
          reason = "EXCEPTION_FLT_INVALID_OPERATION";
          break;
        case MD_EXCEPTION_CODE_WIN_FLOAT_OVERFLOW:
          reason = "EXCEPTION_FLT_OVERFLOW";
          break;
        case MD_EXCEPTION_CODE_WIN_FLOAT_STACK_CHECK:
          reason = "EXCEPTION_FLT_STACK_CHECK";
          break;
        case MD_EXCEPTION_CODE_WIN_FLOAT_UNDERFLOW:
          reason = "EXCEPTION_FLT_UNDERFLOW";
          break;
        case MD_EXCEPTION_CODE_WIN_INTEGER_DIVIDE_BY_ZERO:
          reason = "EXCEPTION_INT_DIVIDE_BY_ZERO";
          break;
        case MD_EXCEPTION_CODE_WIN_INTEGER_OVERFLOW:
          reason = "EXCEPTION_INT_OVERFLOW";
          break;
        case MD_EXCEPTION_CODE_WIN_PRIVILEGED_INSTRUCTION:
          reason = "EXCEPTION_PRIV_INSTRUCTION";
          break;
        case MD_EXCEPTION_CODE_WIN_STACK_OVERFLOW:
          reason = "EXCEPTION_STACK_OVERFLOW";
          break;
        case MD_EXCEPTION_CODE_WIN_POSSIBLE_DEADLOCK:
          reason = "EXCEPTION_POSSIBLE_DEADLOCK";
          break;
        case MD_EXCEPTION_CODE_WIN_STACK_BUFFER_OVERRUN:
          reason = "EXCEPTION_STACK_BUFFER_OVERRUN";
          break;
        case MD_EXCEPTION_CODE_WIN_HEAP_CORRUPTION:
          reason = "EXCEPTION_HEAP_CORRUPTION";
          break;
        case MD_EXCEPTION_CODE_WIN_UNHANDLED_CPP_EXCEPTION:
          reason = "Unhandled C++ Exception";
          break;
        default:
          break;
      }
      break;
    }

    case MD_OS_ANDROID:
    case MD_OS_LINUX: {
      switch (exception_code) {
        case MD_EXCEPTION_CODE_LIN_SIGHUP:
          reason = "SIGHUP";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGINT:
          reason = "SIGINT";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGQUIT:
          reason = "SIGQUIT";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGILL:
          reason = "SIGILL";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGTRAP:
          reason = "SIGTRAP";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGABRT:
          reason = "SIGABRT";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGBUS:
          reason = "SIGBUS";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGFPE:
          reason = "SIGFPE";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGKILL:
          reason = "SIGKILL";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGUSR1:
          reason = "SIGUSR1";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGSEGV:
          reason = "SIGSEGV";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGUSR2:
          reason = "SIGUSR2";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGPIPE:
          reason = "SIGPIPE";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGALRM:
          reason = "SIGALRM";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGTERM:
          reason = "SIGTERM";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGSTKFLT:
          reason = "SIGSTKFLT";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGCHLD:
          reason = "SIGCHLD";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGCONT:
          reason = "SIGCONT";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGSTOP:
          reason = "SIGSTOP";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGTSTP:
          reason = "SIGTSTP";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGTTIN:
          reason = "SIGTTIN";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGTTOU:
          reason = "SIGTTOU";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGURG:
          reason = "SIGURG";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGXCPU:
          reason = "SIGXCPU";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGXFSZ:
          reason = "SIGXFSZ";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGVTALRM:
          reason = "SIGVTALRM";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGPROF:
          reason = "SIGPROF";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGWINCH:
          reason = "SIGWINCH";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGIO:
          reason = "SIGIO";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGPWR:
          reason = "SIGPWR";
          break;
        case MD_EXCEPTION_CODE_LIN_SIGSYS:
          reason = "SIGSYS";
          break;
      case MD_EXCEPTION_CODE_LIN_DUMP_REQUESTED:
          reason = "DUMP_REQUESTED";
          break;
        default:
          break;
      }
      break;
    }

    case MD_OS_SOLARIS: {
      switch (exception_code) {
        case MD_EXCEPTION_CODE_SOL_SIGHUP:
          reason = "SIGHUP";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGINT:
          reason = "SIGINT";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGQUIT:
          reason = "SIGQUIT";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGILL:
          reason = "SIGILL";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGTRAP:
          reason = "SIGTRAP";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGIOT:
          reason = "SIGIOT | SIGABRT";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGEMT:
          reason = "SIGEMT";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGFPE:
          reason = "SIGFPE";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGKILL:
          reason = "SIGKILL";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGBUS:
          reason = "SIGBUS";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGSEGV:
          reason = "SIGSEGV";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGSYS:
          reason = "SIGSYS";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGPIPE:
          reason = "SIGPIPE";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGALRM:
          reason = "SIGALRM";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGTERM:
          reason = "SIGTERM";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGUSR1:
          reason = "SIGUSR1";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGUSR2:
          reason = "SIGUSR2";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGCLD:
          reason = "SIGCLD | SIGCHLD";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGPWR:
          reason = "SIGPWR";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGWINCH:
          reason = "SIGWINCH";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGURG:
          reason = "SIGURG";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGPOLL:
          reason = "SIGPOLL | SIGIO";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGSTOP:
          reason = "SIGSTOP";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGTSTP:
          reason = "SIGTSTP";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGCONT:
          reason = "SIGCONT";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGTTIN:
          reason = "SIGTTIN";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGTTOU:
          reason = "SIGTTOU";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGVTALRM:
          reason = "SIGVTALRM";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGPROF:
          reason = "SIGPROF";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGXCPU:
          reason = "SIGXCPU";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGXFSZ:
          reason = "SIGXFSZ";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGWAITING:
          reason = "SIGWAITING";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGLWP:
          reason = "SIGLWP";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGFREEZE:
          reason = "SIGFREEZE";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGTHAW:
          reason = "SIGTHAW";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGCANCEL:
          reason = "SIGCANCEL";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGLOST:
          reason = "SIGLOST";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGXRES:
          reason = "SIGXRES";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGJVM1:
          reason = "SIGJVM1";
          break;
        case MD_EXCEPTION_CODE_SOL_SIGJVM2:
          reason = "SIGJVM2";
          break;
        default:
          break;
      }
      break;
    }

    case MD_OS_PS3: {
      switch (exception_code) {
        case MD_EXCEPTION_CODE_PS3_UNKNOWN:
          reason = "UNKNOWN";
          break;
        case MD_EXCEPTION_CODE_PS3_TRAP_EXCEP:
          reason = "TRAP_EXCEP";
          break;
        case MD_EXCEPTION_CODE_PS3_PRIV_INSTR:
          reason = "PRIV_INSTR";
          break;
        case MD_EXCEPTION_CODE_PS3_ILLEGAL_INSTR:
          reason = "ILLEGAL_INSTR";
          break;
        case MD_EXCEPTION_CODE_PS3_INSTR_STORAGE:
          reason = "INSTR_STORAGE";
          break;
        case MD_EXCEPTION_CODE_PS3_INSTR_SEGMENT:
          reason = "INSTR_SEGMENT";
          break;
        case MD_EXCEPTION_CODE_PS3_DATA_STORAGE:
          reason = "DATA_STORAGE";
          break;
        case MD_EXCEPTION_CODE_PS3_DATA_SEGMENT:
          reason = "DATA_SEGMENT";
          break;
        case MD_EXCEPTION_CODE_PS3_FLOAT_POINT:
          reason = "FLOAT_POINT";
          break;
        case MD_EXCEPTION_CODE_PS3_DABR_MATCH:
          reason = "DABR_MATCH";
          break;
        case MD_EXCEPTION_CODE_PS3_ALIGN_EXCEP:
          reason = "ALIGN_EXCEP";
          break;
        case MD_EXCEPTION_CODE_PS3_MEMORY_ACCESS:
          reason = "MEMORY_ACCESS";
          break;
        case MD_EXCEPTION_CODE_PS3_COPRO_ALIGN:
          reason = "COPRO_ALIGN";
          break;
        case MD_EXCEPTION_CODE_PS3_COPRO_INVALID_COM:
          reason = "COPRO_INVALID_COM";
          break;
        case MD_EXCEPTION_CODE_PS3_COPRO_ERR:
          reason = "COPRO_ERR";
          break;
        case MD_EXCEPTION_CODE_PS3_COPRO_FIR:
          reason = "COPRO_FIR";
          break;
        case MD_EXCEPTION_CODE_PS3_COPRO_DATA_SEGMENT:
          reason = "COPRO_DATA_SEGMENT";
          break;
        case MD_EXCEPTION_CODE_PS3_COPRO_DATA_STORAGE:
          reason = "COPRO_DATA_STORAGE";
          break;
        case MD_EXCEPTION_CODE_PS3_COPRO_STOP_INSTR:
          reason = "COPRO_STOP_INSTR";
          break;
        case MD_EXCEPTION_CODE_PS3_COPRO_HALT_INSTR:
          reason = "COPRO_HALT_INSTR";
          break;
        case MD_EXCEPTION_CODE_PS3_COPRO_HALTINST_UNKNOWN:
          reason = "COPRO_HALTINSTR_UNKNOWN";
          break;
        case MD_EXCEPTION_CODE_PS3_COPRO_MEMORY_ACCESS:
          reason = "COPRO_MEMORY_ACCESS";
          break;
        case MD_EXCEPTION_CODE_PS3_GRAPHIC:
          reason = "GRAPHIC";
          break;
        default:
          break;
      }
      break;
    }

    default: {
      break;
    }
  }
  this->__crashReason = reason;
}
