/*
 * mod_fastcgi.h
 *
 * This is a header file which defines certain features needed
 * -- by the mod_fastcgi module.  It should include information 
 * -- pertinent only to the mod_fastcgi.c
 *
 * $Id: mod_fastcgi.h,v 1.6 1998/07/28 17:02:43 roberts Exp $
 */

#ifndef _MOD_FASTCGI_H_
#define _MOD_FASTCGI_H_

#include "fcgivers.h"
#include <assert.h>

/* general defines */
#ifndef TRUE
#define TRUE  (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#define ASSERT assert

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

/* dynamic string definitions */
#define DString                 Tcl_DString
#define DStringAppend           Tcl_DStringAppend
#define DStringTrunc            Tcl_DStringSetLength
#define DStringValue            Tcl_DStringValue
#define DStringFree             Tcl_DStringFree
#define DStringLength           Tcl_DStringLength
#define DStringInit             Tcl_DStringInit

/* function prototypes - needed by other files */
void *fcgi_Malloc(size_t size);
void fcgi_Free(void *ptr);

#endif




