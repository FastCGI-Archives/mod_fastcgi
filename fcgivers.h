/*
 * fcgivers.h
 *
 * This is a header file that is used to track down the version 
 * -- history of the fastcgi module.
 */

/* 
 * version id string - to be used in error reporting 
 *
 * FORMAT: server_name[VV.RR.UU]/module[VV.RR.UU] date notes 
 * --- where
 * --------- server_name = Apache
 * --------- [VV.RR.UU]  = version id string
 * --------- where
 * --------------- VV    = major version - use "X" as first letter 
 * --------------------------------------- for the beta releases
 * --------------- RR    = minor version
 * --------------- UU    = update/bugfix - or beta version number
 * --------- module      = mod_fastcgi 
 * --------- date        = yyyymmdd
 * --------- notes       = [whatever]
 */ 

/* Added two missing Free() calls, added alarm(0). */
#define _FASTCGI_MODULE_VERSION_ID_STRING_ \
	"Apache[X1.03.01]/mod_fastcgi[02.00.06] 19970915 unsupported"

	/*
	 *  OLD VERSIONS OF THE FASTCGI MODULE
	 */
#if 0

/* separated out dynamic string and buffer libraries */
#define _FASTCGI_MODULE_VERSION_ID_STRING_ \
	"Apache[X1.03.01]/mod_fastcgi[02.00.05] 19970909 unsupported"

/* more installation script fixes */
#define _FASTCGI_MODULE_VERSION_ID_STRING_ \
	"Apache[X1.03.01]/mod_fastcgi[02.00.04] 19970908 unsupported"

/* source reorg #3 <stanleyg@cs.bu.edu> - makefile created */
#define _FASTCGI_MODULE_VERSION_ID_STRING_ \
        "Apache[X1.03.01]/mod_fastcgi[02.00.03] 19970905 unsupported" 

/* source reorg #2 <stanleyg@cs.bu.edu> - header files */
#define _FASTCGI_MODULE_VERSION_ID_STRING_ \
        "Apache[01.02.04]/mod_fastcgi[02.00.02] 19970903 unsupported" 

/* source reorg #1 <stanleyg@cs.bu.edu> */
#define _FASTCGI_MODULE_VERSION_ID_STRING_ \
        "Apache[01.02.04]/mod_fastcgi[02.00.01] 19970902 unsupported" 

/* fixes from David MacKenzie <djm@va.pubnix.com> */
#define _FASTCGI_MODULE_VERSION_ID_STRING_ \
        "Apache[01.02.04]/mod_fastcgi[02.00.00] 19970902 unsupported" 

#endif
