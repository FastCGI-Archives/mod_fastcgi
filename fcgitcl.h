/*
 * fcgitcl.h
 * 
 * This file provides interfaces for the Tcl Dynamic String library
 */

#ifndef _FCGITCL_H_
#define _FCGITCL_H_

/*
 *  Copyright (c) 1987-1994 The Regents of the University of California.
 *  Copyright (c) 1994-1995 Sun Microsystems, Inc.
 *
 * This software is copyrighted by the Regents of the University of
 * California, Sun Microsystems, Inc., and other parties.  The following
 * terms apply to all files associated with the software unless explicitly
 * disclaimed in individual files.
 *
 * The authors hereby grant permission to use, copy, modify, distribute,
 * and license this software and its documentation for any purpose, provided
 * that existing copyright notices are retained in all copies and that this
 * notice is included verbatim in any distributions. No written agreement,
 * license, or royalty fee is required for any of the authorized uses.
 * Modifications to this software may be copyrighted by their authors
 * and need not follow the licensing terms described here, provided that
 * the new terms are clearly indicated on the first page of each file where
 * they apply.
 * 
 * IN NO EVENT SHALL THE AUTHORS OR DISTRIBUTORS BE LIABLE TO ANY PARTY
 * FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE, ITS DOCUMENTATION, OR ANY
 * DERIVATIVES THEREOF, EVEN IF THE AUTHORS HAVE BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * THE AUTHORS AND DISTRIBUTORS SPECIFICALLY DISCLAIM ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.  THIS SOFTWARE
 * IS PROVIDED ON AN "AS IS" BASIS, AND THE AUTHORS AND DISTRIBUTORS HAVE
 * NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 * 
 * RESTRICTED RIGHTS: Use, duplication or disclosure by the government
 * is subject to the restrictions as set forth in subparagraph (c) (1) (ii)
 * of the Rights in Technical Data and Computer Software Clause as DFARS
 * 252.227-7013 and FAR 52.227-19.
 *
 */

/*
 *  Tcl has a nice dynamic string library, but we want to insulate ourselves
 *  from the library names (we might not always be linked with Tcl, and we
 *  may want to implement our own dynamic string library in the future.)
 */
/*
 * The structure defined below is used to hold dynamic strings.  The only
 * field that clients should use is the string field, and they should
 * never modify it.
 */

#define TCL_DSTRING_STATIC_SIZE 200
typedef struct Tcl_DString {
    char *string;               /* Points to beginning of string:  either
                                 * staticSpace below or a malloc'ed array. */
    int length;                 /* Number of non-NULL characters in the
                                 * string. */
    int spaceAvl;               /* Total number of bytes available for the
                                 * string and its terminating NULL char. */
    char staticSpace[TCL_DSTRING_STATIC_SIZE];
                                /* Space to use in common case where string
                                 * is small. */
} Tcl_DString;

#define Tcl_DStringLength(dsPtr) ((dsPtr)->length)
#define Tcl_DStringValue(dsPtr) ((dsPtr)->string)
#define Tcl_DStringTrunc Tcl_DStringSetLength

/* function definitions */
void Tcl_DStringInit(Tcl_DString *dsPtr);
char *Tcl_DStringAppend(Tcl_DString *dsPtr, char *string, int length);
void Tcl_DStringSetLength(Tcl_DString *dsPtr, int length);
void Tcl_DStringFree(Tcl_DString *dsPtr);

#endif
