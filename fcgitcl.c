/*
 * fcgitcl.c
 *
 * Tcl dynamic string library definition.
 */

#include "conf.h"                       /* apache code */
#include "mod_fastcgi.h"
#include "fcgitcl.h"

/*
 *----------------------------------------------------------------------
 *
 * Tcl_DStringInit --
 *
 *      Initializes a dynamic string, discarding any previous contents
 *      of the string (Tcl_DStringFree should have been called already
 *      if the dynamic string was previously in use).
 * Input: dsptr 
 *              Pointer to structure for dynamic string. 
 * 
 * Results:
 *      None.
 *
 * Side effects:
 *      The dynamic string is initialized to be empty.
 *
 *----------------------------------------------------------------------
 */

void
Tcl_DStringInit(Tcl_DString *dsPtr)

{
    dsPtr->string = dsPtr->staticSpace;
    dsPtr->length = 0;
    dsPtr->spaceAvl = TCL_DSTRING_STATIC_SIZE;
    dsPtr->staticSpace[0] = 0;
}

/*
 *----------------------------------------------------------------------
 *
 * Tcl_DStringAppend --
 *
 *      Append more characters to the current value of a dynamic string.
 * Input
 *   Tcl_DString *dsPtr;        Structure describing dynamic
 *                              string.
 *   char *string;               String to append.  If length is
 *                               -1 then this must be
 *                               null-terminated.
 *   int length;                 Number of characters from string
 *                              to append.  If < 0, then append all
 *                               of string, up to null at end.
 *
 *
 * Results:
 *      The return value is a pointer to the dynamic string's new value.
 *
 * Side effects:
 *      Length bytes from string (or all of string if length is less
 *      than zero) are added to the current value of the string.  Memory
 *      gets reallocated if needed to accomodate the string's new size.
 *
 *----------------------------------------------------------------------
 */

char *
Tcl_DStringAppend(Tcl_DString *dsPtr, char *string, int length)
{
    int newSize;
    char *newString, *dst, *end;

    if (length < 0) {
        length = strlen(string);
    }
    newSize = length + dsPtr->length;

    /*
     * Allocate a larger buffer for the string if the current one isn't
     * large enough.  Allocate extra space in the new buffer so that there
     * will be room to grow before we have to allocate again.
     */

    if (newSize >= dsPtr->spaceAvl) {
        dsPtr->spaceAvl = newSize*2;
        newString = (char *) Malloc((unsigned) dsPtr->spaceAvl);
        memcpy((void *)newString, (void *) dsPtr->string,
                (size_t) dsPtr->length);
        if (dsPtr->string != dsPtr->staticSpace) {
            free(dsPtr->string);
        }
        dsPtr->string = newString;
    }

    /*
     * Copy the new string into the buffer at the end of the old
     * one.
     */

    for (dst = dsPtr->string + dsPtr->length, end = string+length;
            string < end; string++, dst++) {
        *dst = *string;
    }
    *dst = 0;
    dsPtr->length += length;
    return dsPtr->string;
}

/*
 *----------------------------------------------------------------------
 *
 * Tcl_DStringSetLength --
 *
 *      Change the length of a dynamic string.  This can cause the
 *      string to either grow or shrink, depending on the value of
 *      length.
 *
 * Input:
 *      Tcl_DString *dsPtr;     Structure describing dynamic string
 *      int length;             New length for dynamic string.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      The length of dsPtr is changed to length and a null byte is
 *      stored at that position in the string.  If length is larger
 *      than the space allocated for dsPtr, then a panic occurs.
 *
 *----------------------------------------------------------------------
 */

void
Tcl_DStringSetLength(Tcl_DString *dsPtr, int length)
{
    if (length < 0) {
        length = 0;
    }
    if (length >= dsPtr->spaceAvl) {
        char *newString;

        dsPtr->spaceAvl = length+1;
        newString = (char *) Malloc((unsigned) dsPtr->spaceAvl);

        /*
         * SPECIAL NOTE: must use memcpy, not strcpy, to copy the string
         * to a larger buffer, since there may be embedded NULLs in the
         * string in some cases.
         */

        memcpy((void *) newString, (void *) dsPtr->string,
                (size_t) dsPtr->length);
        if (dsPtr->string != dsPtr->staticSpace) {
            free(dsPtr->string);
        }
        dsPtr->string = newString;
    }
    dsPtr->length = length;
    dsPtr->string[length] = 0;
}

/*
 *----------------------------------------------------------------------
 *
 * Tcl_DStringFree --
 *
 *      Frees up any memory allocated for the dynamic string and
 *      reinitializes the string to an empty state.
 *
 * Input:
 *     Tcl_DString *dsPtr;      Structure describing dynamic string
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      The previous contents of the dynamic string are lost, and
 *      the new value is an empty string.
 *
 *----------------------------------------------------------------------
 */

void
Tcl_DStringFree(Tcl_DString *dsPtr)
{
    if (dsPtr->string != dsPtr->staticSpace) {
        free(dsPtr->string);
    }
    dsPtr->string = dsPtr->staticSpace;
    dsPtr->length = 0;
    dsPtr->spaceAvl = TCL_DSTRING_STATIC_SIZE;
    dsPtr->staticSpace[0] = 0;
}





