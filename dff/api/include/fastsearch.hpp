/* fastsearch implementation 
   this implementation comes from Python. This implementation is faster
   than the one provided in DFF until version 1.0.
   The algorithm has been kept untouched, only types have been changed to
   reflect base type and coding style too:
   STRINGLIB_CHAR --> unsigned char*
   Py_ssize_t --> int32_t
   Py_LOCAL_INLINE --> inline
*/

#ifndef __FASTSEARCH_HPP__
#define __FASTSEARCH_HPP__

/* fast search/count implementation, based on a mix between boyer-
   moore and horspool, with a few more bells and whistles on the top.
   for some more background, see: http://effbot.org/zone/stringlib.htm */

/* note: fastsearch may access s[n], which isn't a problem when using
   Python's ordinary string types, but may cause problems if you're
   using this code in other contexts.  also, the count mode returns -1
   if there cannot possible be a match in the target string, and 0 if
   it has actually checked for matches, but didn't find any.  callers
   beware! */

#define FAST_COUNT 0
#define FAST_SEARCH 1
#define FAST_RSEARCH 2

#define LONG_SIZE (8 * CMAKE_SIZEOF_VOID_P)

#ifdef SWIGWORDSIZE64
#define BLOOM_WIDTH 64
#else
#define BLOOM_WIDTH 32
#endif

#define BLOOM_ADD(mask, ch) \
    ((mask |= (1UL << ((ch) & (BLOOM_WIDTH -1)))))
#define BLOOM(mask, ch)     \
    ((mask &  (1UL << ((ch) & (BLOOM_WIDTH -1)))))

namespace DFF
{

inline int32_t fastsearch(const unsigned char* s, int32_t n,
			  const unsigned char* p, int32_t m,
			  int32_t maxcount, int mode)
{
    unsigned long mask;
    int32_t skip, count = 0;
    int32_t i, j, mlast, w;

    w = n - m;

    if (w < 0 || (mode == FAST_COUNT && maxcount == 0))
        return -1;

    /* look for special cases */
    if (m <= 1) 
      {
        if (m <= 0)
	  return -1;
        /* use special case for 1-character strings */
        if (mode == FAST_COUNT) 
	  {
            for (i = 0; i < n; i++)
	      if (s[i] == p[0]) 
		{
		  count++;
		  if (count == maxcount)
		    return maxcount;
                }
            return count;
	  }
	else if (mode == FAST_SEARCH) 
	  {
            for (i = 0; i < n; i++)
	      if (s[i] == p[0])
		return i;
	  } 
	else 
	  {    /* FAST_RSEARCH */
            for (i = n - 1; i > -1; i--)
	      if (s[i] == p[0])
		return i;
	  }
        return -1;
      }
    
    mlast = m - 1;
    skip = mlast - 1;
    mask = 0;

    if (mode != FAST_RSEARCH) 
      {
	
        /* create compressed boyer-moore delta 1 table */
	
        /* process pattern[:-1] */
        for (i = 0; i < mlast; i++) 
	  {
            BLOOM_ADD(mask, p[i]);
            if (p[i] == p[mlast])
	      skip = mlast - i - 1;
	  }
        /* process pattern[-1] outside the loop */
        BLOOM_ADD(mask, p[mlast]);
	
        for (i = 0; i <= w; i++) 
	  {
            /* note: using mlast in the skip path slows things down on x86 */
            if (s[i+m-1] == p[m-1]) 
	      {
                /* candidate match */
                for (j = 0; j < mlast; j++)
		  if (s[i+j] != p[j])
		    break;
                if (j == mlast)
		  {
                    /* got a match! */
                    if (mode != FAST_COUNT)
		      return i;
                    count++;
                    if (count == maxcount)
		      return maxcount;
                    i = i + mlast;
                    continue;
		  }
                /* miss: check if next character is part of pattern */
                if (!BLOOM(mask, s[i+m]))
		  i = i + m;
                else
		  i = i + skip;
	      } 
	    else 
	      {
                /* skip: check if next character is part of pattern */
                if (!BLOOM(mask, s[i+m]))
		  i = i + m;
	      }
	  }
      } 
    else 
      {    /* FAST_RSEARCH */
	
        /* create compressed boyer-moore delta 1 table */
	
        /* process pattern[0] outside the loop */
	BLOOM_ADD(mask, p[0]);
        /* process pattern[:0:-1] */
        for (i = mlast; i > 0; i--) 
	  {
            BLOOM_ADD(mask, p[i]);
            if (p[i] == p[0])
	      skip = i - 1;
	  }
	
        for (i = w; i >= 0; i--) 
	  {
            if (s[i] == p[0]) 
	      {
                /* candidate match */
                for (j = mlast; j > 0; j--)
		  if (s[i+j] != p[j])
		    break;
                if (j == 0)
		  /* got a match! */
		  return i;
                /* miss: check if previous character is part of pattern */
                if (i > 0 && !BLOOM(mask, s[i-1]))
		  i = i - m;
                else
		  i = i - skip;
	      } 
	    else 
	      {
                /* skip: check if previous character is part of pattern */
                if (i > 0 && !BLOOM(mask, s[i-1]))
		  i = i - m;
	      }
	  }
      }
    
    if (mode != FAST_COUNT)
      return -1;
    return count;
}


inline int32_t wfastsearch(const unsigned char* s, int32_t n,
			   const unsigned char* p, int32_t m,
			   unsigned char wildcard,
			   int32_t maxcount, int mode)
{
    unsigned long mask;
    int32_t skip, count = 0;
    int32_t i, j, mlast, w;

    w = n - m;

    if (w < 0 || (mode == FAST_COUNT && maxcount == 0))
        return -1;

    /* look for special cases */
    if (m <= 1) 
      {
        if (m <= 0)
	  return -1;
        /* use special case for 1-character strings */
        if (mode == FAST_COUNT) 
	  {
            for (i = 0; i < n; i++)
	      if ((s[i] == p[0]) || (s[i] == wildcard))
		{
		  count++;
		  if (count == maxcount)
		    return maxcount;
                }
            return count;
	  }
	else if (mode == FAST_SEARCH) 
	  {
            for (i = 0; i < n; i++)
	      if ((s[i] == p[0]) || (s[i] == wildcard))
		return i;
	  } 
	else 
	  {    /* FAST_RSEARCH */
            for (i = n - 1; i > -1; i--)
	      if ((s[i] == p[0]) || (s[i] == wildcard))
		return i;
	  }
        return -1;
      }
    
    mlast = m - 1;
    skip = mlast - 1;
    mask = 0;

    if (mode != FAST_RSEARCH) 
      {
	
        /* create compressed boyer-moore delta 1 table */
	
        /* process pattern[:-1] */
        for (i = 0; i < mlast; i++) 
	  {
	    if (p[i] != wildcard)
	      BLOOM_ADD(mask, p[i]);
            if ((p[i] == p[mlast]) || (p[i] == wildcard))
	      skip = mlast - i - 1;
	  }
        /* process pattern[-1] outside the loop */
	if (p[mlast] != wildcard)
	  BLOOM_ADD(mask, p[mlast]);
        for (i = 0; i <= w; i++) 
	  {
            /* note: using mlast in the skip path slows things down on x86 */
            if ((s[i+m-1] == p[m-1]) || (p[m-1] == wildcard))
	      {
                /* candidate match */
                for (j = 0; j < mlast; j++)
		  if ((s[i+j] != p[j]) && (p[j] != wildcard))
		    break;
                if (j == mlast)
		  {
                    /* got a match! */
                    if (mode != FAST_COUNT)
		      return i;
                    count++;
                    if (count == maxcount)
		      return maxcount;
                    i = i + mlast;
                    continue;
		  }
                /* miss: check if next character is part of pattern */
		i = i + skip;
	      }
	    else 
	      {
                /* skip: check if next character is part of pattern */
                if (!BLOOM(mask, s[i+m]))
		  i = i + m;
	      }
	  }
      } 
    else 
      {    /* FAST_RSEARCH */
	
        /* create compressed boyer-moore delta 1 table */
	
        /* process pattern[0] outside the loop */
	if (p[0] != wildcard)
	  BLOOM_ADD(mask, p[0]);
        /* process pattern[:0:-1] */
        for (i = mlast; i > 0; i--)
	  {
	    if (p[i] != wildcard)
	      BLOOM_ADD(mask, p[i]);
            if ((p[i] == p[0]) || (p[i] == wildcard))
	      skip = i - 1;
	  }
	
        for (i = w; i >= 0; i--) 
	  {
            if ((s[i] == p[0]) || (p[0] == wildcard)) 
	      {
                /* candidate match */
                for (j = mlast; j > 0; j--)
		  if ((s[i+j] != p[j]) && (p[j] != wildcard))
		    break;
                if (j == 0)
		  /* got a match! */
		  return i;
                /* miss: check if previous character is part of pattern */
                if (i > 0)
		  i = i - skip;
	      }
	    else 
	      {
                /* skip: check if previous character is part of pattern */
                if (i > 0 && !BLOOM(mask, s[i-1]))
		  i = i - m;
	      }
	  }
      }
    
    if (mode != FAST_COUNT)
      return -1;
    return count;
}



#include <stdio.h>

inline unsigned char	upper(unsigned char c)
{
  if ((c >= 'a') && (c <= 'z'))
    return (c - 32);
  else
    return c;
}

inline char	cicmp(unsigned char c1, unsigned char c2)
{
  return (upper(c1) == upper(c2));
}

inline int32_t cifastsearch(const unsigned char* s, int32_t n,
			    const unsigned char* p, int32_t m,
			    int32_t maxcount, int mode)
{
    unsigned long mask;
    int32_t skip, count = 0;
    int32_t i, j, mlast, w;

    w = n - m;

    if (w < 0 || (mode == FAST_COUNT && maxcount == 0))
        return -1;

    /* look for special cases */
    if (m <= 1) 
      {
        if (m <= 0)
	  return -1;
        /* use special case for 1-character strings */
        if (mode == FAST_COUNT) 
	  {
            for (i = 0; i < n; i++)
	      if (cicmp(s[i], p[0])) 
		{
		  count++;
		  if (count == maxcount)
		    return maxcount;
                }
            return count;
	  }
	else if (mode == FAST_SEARCH) 
	  {
            for (i = 0; i < n; i++)
	      if (cicmp(s[i], p[0]))
		return i;
	  } 
	else 
	  {    /* FAST_RSEARCH */
            for (i = n - 1; i > -1; i--)
	      if (cicmp(s[i], p[0]))
		  return i;
	  }
        return -1;
      }
    
    mlast = m - 1;
    skip = mlast - 1;
    mask = 0;

    if (mode != FAST_RSEARCH) 
      {	
        /* create compressed boyer-moore delta 1 table */
	
        /* process pattern[:-1] */
        for (i = 0; i < mlast; i++) 
	  {
            BLOOM_ADD(mask, p[i]);
            BLOOM_ADD(mask, upper(p[i]));
            if (cicmp(p[i], p[mlast]))
	      skip = mlast - i - 1;
	  }
        /* process pattern[-1] outside the loop */
        BLOOM_ADD(mask, upper(p[mlast]));
        BLOOM_ADD(mask, p[mlast]);
        for (i = 0; i <= w; i++) 
	  {
            /* note: using mlast in the skip path slows things down on x86 */
            if (cicmp(s[i+m-1], p[m-1]) == 1) 
	      {
                /* candidate match */
                for (j = 0; j < mlast; j++)
		  if (!cicmp(s[i+j], p[j]))
		    break;
                if (j == mlast)
		  {
                    /* got a match! */
                    if (mode != FAST_COUNT)
		      return i;
                    count++;
                    if (count == maxcount)
		      return maxcount;
                    i = i + mlast;
                    continue;
		  }
                /* miss: check if next character is part of pattern */
                if (!(BLOOM(mask, s[i+m]) || !BLOOM(mask, upper(s[i+m]))))
		  i = i + m;
                else
		  i = i + skip;
	      } 
	    else 
	      {
		//printf("  SKIPPING check if %c in pattern \n", s[i+m]);
                /* skip: check if next character is part of pattern */
                if (!(BLOOM(mask, s[i+m]) || BLOOM(mask, upper(s[i+m]))))
		  i = i + m;
	      }
	  }
      } 
    else 
      {    /* FAST_RSEARCH */
	
        /* create compressed boyer-moore delta 1 table */
	
        /* process pattern[0] outside the loop */
	BLOOM_ADD(mask, p[0]);
	BLOOM_ADD(mask, upper(p[0]));
        /* process pattern[:0:-1] */
        for (i = mlast; i > 0; i--) 
	  {
            BLOOM_ADD(mask, p[i]);
            BLOOM_ADD(mask, upper(p[i]));
            if (cicmp(p[i], p[0]))
	      skip = i - 1;
	  }
	
        for (i = w; i >= 0; i--)
	  {
            if (cicmp(s[i], p[0]))
	      {
                /* candidate match */
                for (j = mlast; j > 0; j--)
		  if (!cicmp(s[i+j], p[j]))
		    break;
                if (j == 0)
		  /* got a match! */
		  return i;
                /* miss: check if previous character is part of pattern */
                if (i > 0 && !(BLOOM(mask, s[i-1]) || BLOOM(mask, upper(s[i-1]))))
		  i = i - m;
                else
		  i = i - skip;
	      } 
	    else 
	      {
                /* skip: check if previous character is part of pattern */
                if (i > 0 && !(BLOOM(mask, s[i-1]) || BLOOM(mask, upper(s[i-1]))))
		  i = i - m;
	      }
	  }
      }
    
    if (mode != FAST_COUNT)
      return -1;
    return count;
}

}
#endif
