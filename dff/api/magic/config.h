/* #undef HAVE_ASCTIME_R */

#define HAVE_ASPRINTF 1

#define HAVE_SNPRINTF 1

#define HAVE_CTIME_R 1

/* #undef HAVE_FMTCHECK */

#define HAVE_FORK 1

#define HAVE_FREELOCALE 1

#define HAVE_GETLINE 1 

#define HAVE_GMTIME_R 1

#define HAVE_INTTYPES_H 1

#define HAVE_LIMITS_H 1

#define HAVE_LOCALE_H 1

#define HAVE_LOCALTIME_R 1

#define HAVE_MMAP 1

#define HAVE_NEWLOCALE 1

#define HAVE_PREAD 1

#define HAVE_STDDEF_H 1

#define HAVE_STDINT_H 1

#define HAVE_STDLIB_H 1

#define HAVE_STRCASESTR 1

#define HAVE_STRERROR 1

/* #undef HAVE_STRLCAT */

/* #undef HAVE_STRLCPY */

#define HAVE_STRNDUP 1

#define HAVE_STRTOF 1

#define HAVE_STRTOUL 1

#define HAVE_SYS_MMAN_H 1

#define HAVE_UNISTD_H 1

#define HAVE_USELOCALE 1

#define HAVE_UTIME 1

#define HAVE_UTIMES 1

#define HAVE_VASPRINTF 1

#define HAVE_WCHAR_H 1

#define HAVE_WCTYPE_H 1

#define HAVE_WCWIDTH 1

/* #undef HAVE_XLOCALE_H */

#define VERSION "5.25"

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif


/* Version number of package */
#define VERSION "5.25"

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Enable large inode numbers on Mac OS X 10.5.  */
#ifndef _DARWIN_USE_64_BIT_INODE
# define _DARWIN_USE_64_BIT_INODE 1
#endif


