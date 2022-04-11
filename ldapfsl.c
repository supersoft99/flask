/************************************************
# $Id: ldapfsl.c.rca 1.7 Fri Jul  4 09:48:37 2014 B35201 Experimental B35201 $
# $Author: B35201 $
# $Date: Fri Jul  4 09:48:37 2014 $
# $Source: /sync/vault/8000/sv/Projects/piams/dev/Ldap/ldapfsl.c.rca $
#
# (C) Copyright 2012, Freescale, all rights reserved.
#
# Procedures list :
#
************************************************
*$Log: ldapfsl.c.rca $
*
* Revision: 1.7 Fri Jul  4 09:48:37 2014 B35201
* converted to use OpenLDAP and compatible with Qt5
*
* Revision: 1.6 Tue Oct  1 07:07:53 2013 B35201
* fixed cppcheck issues
*
* Revision: 1.5 Fri May 17 13:02:53 2013 B35201
* removed unnecesary check
*
* Revision: 1.3 Mon Apr  1 18:53:55 2013 b35201
* missing XML handling
*
* Revision: 1.2 Thu Mar 14 13:26:45 2013 b35201
* improved debug
*
* Revision: 1.1 Mon Feb 18 20:38:59 2013 b35201
* Adding LDAP stuff
*
************************************************/


/********************************* ACKNOWLEDGMENT ***********************************************
 *
 *
 *    Many of the code of this file and certificates were provided by RENEE CARTER
 *
 *                              RXFH80@freescale.com
 *
 ************************************************************************************************/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <crypt.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/timeb.h>
#include <time.h>


/**
 * This code is supposed to work using both OpenLDAP and MozillaLDAP apis
 *
 *  see ldapfsl.h which uses defines: USING_MOZILLA_LDAP  and USING_OPEN_LDAP
 *
 *  Linking:
 *     USING_OPEN_LDAP:
                  Linux:      -L/usr/lib64 -lldap -lssl -lcrypto -llber
 *
 *                Solaris:     suppose "LDAP=/proj/dmisw/pipadev/work/b35201/git/openldap-2.4.44" and "OPENSSL=/_TOOLS_/dist/OSS-openssl-/1.0.1g/sparc-sun-solaris2.8/"

                               -I$LDAP_AREA/include
                                $LDAP_AREA/lib/liblunicode.a
                                $LDAP_AREA/lib/libldap.a
                                $LDAP_AREA/lib/liblber.a
                                $OPENSSL/lib/libssl.a
                                $OPENSSL/lib/libcrypto.a
                                -lnsl -lsocket -lm -lz -lresolv

 *     USING_MOZILLA_LDAP:
                  Linux :       -I/usr/include/mozldap -L/usr/lib64 -lldap60 -lssldap60 -lssl -lcrypto

                  Solaris:   (which seems to NOT work using version 5.1.7)

                  LDAP_PATH=/proj/dmisw/mdsdev/work/b35201/MDS_repository/transcend/m2server/ldap/solaris/ldapcsdk-5.1.7
                  LDAP_LIB_PATH=$LDAP_PATH/lib

                  LIBS="$LDAP_LIB_PATH/libssldap50.so \
                  $LDAP_LIB_PATH/libssl3.so \
                  $LDAP_LIB_PATH/libplc4.so \
                  $LDAP_LIB_PATH/libnss3.so \
                  $LDAP_LIB_PATH/libnspr4.so \
                  $LDAP_LIB_PATH/libplds4.so \
                  $LDAP_LIB_PATH/libsoftokn3.so \
                  $LDAP_LIB_PATH/libprldap50.so \
                  $LDAP_LIB_PATH/libldap50.so  \
                  $LDAP_LIB_PATH/liblber50.a \
                  -lnsl -lsocket -lm -lz

                  gcc -DSOLARIS -DUSING_MOZILLA_LDAP -I$LDAP_PATH/include $LIBS
**/

#define LDAPFSL_SOURCE 1

#include "ldapfsl.h"


#if USING_OPEN_LDAP
# include <ldap.h>
//declaring deprecated functions
char ** ldap_get_values(LDAP*, LDAPMessage *, const char *);
int     ldap_unbind(LDAP*);
int     ldap_simple_bind_s(LDAP*, const char *, const char *);
int     ldap_value_free(char **);
int     ldap_search_s(LDAP *, const char *, int, const char*, const char *, int, LDAPMessage **);
#else  // using MOZILLA_LDAP
# include <ldap.h>
# include <ldap_ssl.h>
#endif


//--------------------------------------------------------------------------------

#define MAX_SPLIT_STRINGS  20

struct SplitString
{
    int      current;
    int      counter;
    char  *  array [MAX_SPLIT_STRINGS];
    int      length[MAX_SPLIT_STRINGS];
    char     result[256];
};

/** functions split_string()  and split_getString() are used to split and work
    with sub strings in core_id_alternative
 */
struct SplitString *
split_string(char* string, const char delimiter)
{
    static struct SplitString  split;
    split.current    = 0;
    split.counter    = 0;
    split.length[0]  = 0;
    split.array[0]   = NULL;
    if (*string != '\0' && strchr(string, delimiter) == NULL )
    {
        split.array[0]   = string;
        split.length[0]  = strlen(string);
        split.counter  = 1;
        split.array[1] = NULL;
    }
    else
    {
        char *pt = string;
        char *end = string + strlen(string) -1;
        while (pt < end)
        {
            int length = 0;
            while (*pt   == delimiter) {++pt;}
            while (*end == delimiter) {--end;}
            if (pt < end)
            {
                split.array[split.counter]    = pt;
                while (pt <= end && *pt != delimiter)
                {
                       pt++;
                       length++;
                }
                split.length[split.counter++] = length;
            }
        }
    }
    return &split;
}

char *split_getString(struct SplitString *split)
{
    char *ret = NULL;
    if (split->current < split->counter)
    {
        int length =  split->length[split->current];
        ret = split->result;
        strncpy(ret, split->array[split->current], length);
        ret[length] = 0;
        split->current++;
    }
    return ret;
}
//---------------------------------------------------------------------------------

static LDAP_CONFIG   ldapNXPcoreidConfig =
{
 /*system*/       LDAP_CONFIG_SYSTEM_API, //direct
 /*serviceDN*/    "CN=srv_rdapps01,OU=SRV Accounts,OU=Accounts,OU=Service Delivery,DC=wbi,DC=nxp,DC=com",
 /*servicePWD*/   "bU]Q_M!f_)M2WPWq",
 /*searchString*/ "DC=wbi,DC=nxp,DC=com",
 /*host*/         "us-ldap.nxp.com",
 /*emailSuffix*/  "@nxp.com",
 /*normal_port*/   0,
 /*ssl_port*/      636,

 {
    /*firstName*/  "",
    /*lastName*/   "",
    /*fullName*/   "displayName",
    /*location*/   "l",
    /*mail*/       "mail",
    /*core_id*/    "cn",
    /*core_id_alternative*/ "extensionAttribute12",
    /*extra_info_1*/ "cn",
    /*extra_info_2*/ "extensionAttribute12",
    /*extra_info_3*/ "extensionAttribute7",  // alternative_email, friendly_email at @freescale.com
    /*extra_info_4*/ "telephoneNumber",
    /*extra_info_5*/ "extensionAttribute11",
    /*extra_info_6*/ "manager",       // CN=nxa09194,OU=Developers,OU=Managed Users,OU=U   CN is the coreid of the manager
    /*extra_info_7*/ "employeeType",
    /*extra_info_8*/ "",
    /*extra_info_9*/ ""
 }
};



static LDAP_CONFIG   ldapNXPwbiidConfig =
{
 /*system*/       LDAP_CONFIG_SYSTEM_API, //direct
 /*serviceDN*/    "CN=srv_rdapps01,OU=SRV Accounts,OU=Accounts,OU=Service Delivery,DC=wbi,DC=nxp,DC=com",
 /*servicePWD*/   "bU]Q_M!f_)M2WPWq",
 /*searchString*/ "DC=wbi,DC=nxp,DC=com",
 /*host*/         "us-ldap.nxp.com",
 /*emailSuffix*/  "@nxp.com",
 /*normal_port*/   0,
 /*ssl_port*/      636,

  {
       /*firstName*/  "",
       /*lastName*/   "",
       /*fullName*/   "displayName",
       /*location*/   "l",
       /*mail*/       "mail",
       /*core_id*/    "cn",
       /*core_id_alternative*/ "",
       /*extra_info_1*/ "",
       /*extra_info_2*/ "",
       /*extra_info_3*/ "",   // alternative_email  empty
       /*extra_info_4*/ "telephoneNumber",
       /*extra_info_5*/ "department",
       /*extra_info_6*/ "manager",         // CN=nxa09194,OU=Developers,OU=Managed Users,OU=U   CN is the coreid of the manager
       /*extra_info_7*/ "employeeType",
       /*extra_info_8*/ "",
       /*extra_info_9*/ ""
    }
};




static LDAP_CONFIG   ldapNXPextranetLdapConfig =
{
     /*system*/       LDAP_CONFIG_SYSTEM_API, //direct
     /*serviceDN*/    "cn=fss_query,ou=service accounts,ou=applications,ou=extranet,dc=motorola,dc=com",
     /*servicePWD*/   "F55prod2",
     /*searchString*/ "ou=People,ou=extranet,dc=Motorola,dc=com",
     /*host*/         "eldap.nxp.com",
     /*emailSuffix*/  "@nxp.com",
     /*normal_port*/   0,
     /*ssl_port*/      636,

     {
         /*firstName*/  "givenName",
         /*lastName*/   "sn",
          /*fullName*/   "",
          /*location*/   "l",
          /*mail*/       "mail",
          /*core_id*/    "cn",
          /*core_id_alternative*/ "uid extensionAttribute12",
          /*extra_info_1*/ "cn",
          /*extra_info_2*/ "extensionAttribute12",
          /*extra_info_3*/ "",  // extensionAttribute7 set it later, alternative_email, friendly_email at @freescale.com
          /*extra_info_4*/ "telephoneNumber",
          /*extra_info_5*/ "extensionAttribute11",
          /*extra_info_6*/ "manager",       // CN=nxa09194,OU=Developers,OU=Managed Users,OU=U   CN is the coreid of the manager
          /*extra_info_7*/ "employeeType",
          /*extra_info_8*/ "",
          /*extra_info_9*/ ""
     }
};



static LDAP_CONFIG   ldapFSLintranetLdapConfig =
{
 /*system*/       LDAP_CONFIG_SYSTEM_API, //direct
 /*serviceDN*/    "cn=mso_service,ou=application users,ou=applications,ou=intranet,dc=motorola,dc=com",
 /*servicePWD*/   "My007Service",
 /*searchString*/ "ou=People,ou=Intranet,dc=Motorola,dc=com",
 /*host*/         "fsl-ids.freescale.net",
 /*emailSuffix*/  "@freescale.com",
 /*normal_port*/   0,
 /*ssl_port*/      636,

  {
       /*firstName*/  "givenName",
       /*lastName*/   "sn",
       /*fullName*/   "",
       /*location*/   "motLocationCode",
       /*mail*/       "mail",
       /*core_id*/    "uid",
       /*core_id_alternative*/ "",
       /*extra_info_1*/ "",
       /*extra_info_2*/ "",
       /*extra_info_3*/ "",   // alternative_email
       /*extra_info_4*/ "telephoneNumber",
       /*extra_info_5*/ "department",
       /*extra_info_6*/ "motSupervisorID",    // motcommerceID value, example: 40000765 of the manager requires a search by 'motcommerceID'
       /*extra_info_7*/ "employeeType",
       /*extra_info_8*/ "motcommerceID",      // the comercial employee ID
       /*extra_info_9*/ ""
    }
};


static LDAP_CONFIG   ldapFSLextranetLdapConfig =
{
 /*system*/       LDAP_CONFIG_SYSTEM_API, //direct
 /*serviceDN*/    "cn=fss_query,ou=service accounts,ou=applications,ou=extranet,dc=motorola,dc=com",
 /*servicePWD*/   "F55prod2",
 /*searchString*/ "ou=People,ou=Extranet,dc=Motorola,dc=com",
 /*host*/         "fsl-eds.freescale.net",
 /*emailSuffix*/  "@freescale.com",
 /*normal_port*/   0,
 /*ssl_port*/      636,

  {
       /*firstName*/  "givenName",
       /*lastName*/   "sn",
       /*fullName*/   "",
       /*location*/   "l",
       /*mail*/       "nxpemail",
       /*core_id*/    "nxpwbi",
       /*core_id_alternative*/ "uid",
       /*extra_info_1*/ "applicationid",
       /*extra_info_2*/ "motextranetapplication000008",
       /*extra_info_3*/ "mail",  // alternative_email
       /*extra_info_4*/ "telephoneNumber",
       /*extra_info_5*/ "departmentNumber",
       /*extra_info_6*/ "motSupervisorID",    // motcommerceID value, example: 40000765 of the manager requires a search by 'motcommerceID'
       /*extra_info_7*/ "mail",
       /*extra_info_8*/ "motcommerceID",      // the comercial employee ID
       /*extra_info_9*/ ""
    }
};


/*!
   it contains all the LDAP information to access the server

   ldapNXPcoreidConfig -> access NXP Ldap but keeping freescale coreID for xFSL employees
                       -> searches and authentication work for both 'xFSL coreid' and 'NXP WBI id'

   ldapNXPwbiidConfig  -> searches and authenticates for 'NXP WBI id' only

   ldapFSLintranetLdapConfig -> old xFSL Ldap only coreid

   ldapFSLextranetLdapConfig -> external LDAP used on DMZ (dropbox8)

   ldapNXPextranetLdapConfig -> external NXP with ALL (everyone) (nxp employees and xFSL extranet users)
*/

static LDAP_CONFIG  * ldapConfig = & ldapNXPcoreidConfig;  // defaults to ldapNXPcoreidConfig

#define SAFE_STRCPY(destination, source) strncpy(destination, source, sizeof(destination) -1)


/* debug stuff */

#if defined(USING_OPEN_LDAP) && !defined(LDAP_DEBUG_ANY)
#define LDAP_DEBUG_ANY               (-1)
#endif

#define  PERMITION_ALLOWED_CODE   50 // this error can be considered OK

#define IS_GOOD_LDAP_SEARCH(ret)   (ret == LDAP_SUCCESS || ret == PERMITION_ALLOWED_CODE)

#if (defined(DEBUG) && defined(STANDALONE)) || defined(REGRESSION_TEST_LDAP)
# define debug(format, ...)    printf("[debug][%s] %s:%03d "#format, _debug_date(), __FILE__, __LINE__, ##__VA_ARGS__);\
                               printf("\n")
static const char* _debug_date()
{
    struct timeb   timeb;
    static char m_currentDatetime[32] = {0};
    timeb.time         = 0;
    if (ftime(&timeb) == 0)
    {
        struct tm* tm = localtime(&timeb.time);
        if (tm)
        {
            unsigned len = snprintf(m_currentDatetime, sizeof(m_currentDatetime) -1,
                                     "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                                     tm->tm_year + 1900,
                                     tm->tm_mon  + 1,
                                     tm->tm_mday,
                                     tm->tm_hour,
                                     tm->tm_min,
                                     tm->tm_sec,
                                     timeb.millitm);
            if (len >= sizeof(m_currentDatetime))
            {
                snprintf(m_currentDatetime, sizeof(m_currentDatetime) -1, "buffer overflow");
            }
        }
    }
    return m_currentDatetime;
}
#else
# define debug(x, ...)       /**/
#endif

#if USING_OPEN_LDAP
const int debug_mode_option=LDAP_DEBUG_ANY;
#endif
int   using_debug_mode=0;


#if REGRESSION_TEST_LDAP
static char regression_test_ldapsearch_file[512];

void set_regression_test_ldapsearch_file(const char *file)
{
    SAFE_STRCPY(regression_test_ldapsearch_file, file);
}
#endif


#define    DO_SEARCH_COREID   0
#define    DO_SEARCH_NAME     1
#define    DO_SEARCH_FILTER   2
#define    DO_AUTHENTICATE    3

/* DBYES and DBNO are transcend defines, no transcend are included here to avoid dependency */
#if !defined(DBYES)
# define DBYES 1
#endif

#if !defined(DBNO)
# define DBNO 2   // like transcend
#endif

static LDAP_RETURN_DATA *ldapfsl_lookup(const char *searchData, int type, const char *password);

static char cert7db[PATH_MAX];

/* used to keep the last CoreId search value  */
static const char * gl_lastSearchByCoreId = 0;

#if defined(SOLARIS)
static int  setenv(const char *var, const char *value, int x)
{
   char string[256];
   sprintf(string, "%s=%s", var,value);
   x = putenv(string);
   debug("setenv(): string=%s return=%d\n", string, x);
   return 0;
}
#endif

/* convert s string lower case characters */
static char * strlower(char *str)
{
    char *pt = str;
    while (pt && *pt)
    {
         *pt = tolower(*pt);
         pt++;
    }
    return str;
}


//-------------------------------------------------------
/*!
 *   Private function setOpenLdapTimeoutTimeLimit(), sets a new value for LDAP_OPT_TIMELIMIT
 *
 *   It is used to help to avoid the LDAP timeout LDAP_TIMELIMIT_EXCEEDED, openLDAP only
 */
int setOpenLdapTimeoutTimeLimit(LDAP * connection, int timelimit)
{
#if defined(USING_OPEN_LDAP)
    return ldap_set_option(connection, LDAP_OPT_TIMELIMIT, (void *)&timelimit);
#else
    return 0;
#endif
}


//-------------------------------------------------------
/*!
 *    Private function list_all_attributes(), debug purpose only, define REGRESSION_TEST_LDAP to use that
 */

#if REGRESSION_TEST_LDAP
static void list_all_attributes(LDAP *ld, LDAPMessage *user_result)
{
    BerElement *ber = 0;
    char	   *a = ldap_first_attribute( ld, user_result, &ber );
    int        i = 0;

    for ( ;  a != NULL;    a = ldap_next_attribute( ld, user_result, ber ) ) {
        char	  	    **vals = 0;
        if (( vals = ldap_get_values( ld, user_result, a )) != NULL ) {
            for ( i = 0; vals[ i ] != NULL; i++ ) {
                printf( "[%s:%d] attribute [%s]: %s\n",__FILE__, __LINE__, a, vals[ i ] );
            }
            ldap_value_free( vals );
        }
        ldap_memfree( a );
    }
    if ( ber != NULL ) {
        ber_free( ber, 0 );
    }
    printf( "\n" );
}
#endif


//--------------------------------------------------------
/*!
 *   Private function create_return_data()
 *
 *   Creates an empty LDAP_RETURN_DATA structure and initializes it.
 */
static LDAP_RETURN_DATA * create_return_data()
{
    LDAP_RETURN_DATA *data = (LDAP_RETURN_DATA *) malloc(sizeof(LDAP_RETURN_DATA));
    if (data)
    {
        data->errorMessage[0] = 0;
        data->entries         = 0;
        data->result          = LDAP_SUCCESS;
        data->info            = (LDAP_USER_INFORMATION **)0;
        data->connected_code  = 0;
    }
    return data;
}


//--------------------------------------------------------
/*!
 *   Private function alocate_return_data_entries()
 *
 *   Allocates \a entries of LDAP_USER_INFORMATION to fit user information
 */
static void alocate_return_data_entries(int entries, LDAP_RETURN_DATA *data)
{
    data->entries = entries;
    data->info    = (LDAP_USER_INFORMATION **) malloc(entries * sizeof(LDAP_USER_INFORMATION *));
    while (entries--)
    {
        data->info[entries] = (LDAP_USER_INFORMATION *) malloc(sizeof(LDAP_USER_INFORMATION) );
        data->info[entries]->coreId[0] = '\0';
        data->info[entries]->corporate_email[0] = '\0';
        data->info[entries]->name[0] = '\0';
        data->info[entries]->friendly_email[0] = '\0';
        data->info[entries]->site[0]  = '\0';
        data->info[entries]->alternative_coreId[0]  = '\0';
        data->info[entries]->extra_info_1[0]  = '\0';
        data->info[entries]->extra_info_2[0]  = '\0';
        data->info[entries]->extra_info_3[0]  = '\0';
        data->info[entries]->extra_info_4[0]  = '\0';
        data->info[entries]->extra_info_5[0]  = '\0';
        data->info[entries]->extra_info_6[0]  = '\0';
        data->info[entries]->extra_info_7[0]  = '\0';
        data->info[entries]->extra_info_8[0]  = '\0';
        data->info[entries]->extra_info_9[0]  = '\0';
    }
}


//--------------------------------------------------------
/*!
 * Private function set_ldap_error()
 *
 * Sets the error code and the error message
 */
static void set_ldap_error(int ret, LDAP_RETURN_DATA *data)
{
#if USING_OPEN_LDAP
    strncpy(data->errorMessage, ldap_err2string(ret), sizeof(data->errorMessage) -1);
#else // using USING_MOZILLA_LDAP
    strncpy(data->errorMessage, ldapssl_err2string(ret), sizeof(data->errorMessage) -1);
#endif
    data->result = ret;
}


//--------------------------------------------------------
/*!
 *  Private function ldap_connect()
 *
 */
static LDAP *ldap_connect(LDAP_RETURN_DATA *data)
{
    LDAP             *ld = NULL;
    int              ret = -1;
    int              version = LDAP_VERSION3;
#if USING_OPEN_LDAP
    int              no_certificate = LDAP_OPT_X_TLS_NEVER;
#endif

    char             uri[1024];
    if (ldapConfig->ssl_port == 636)
    {
    sprintf(uri, "ldaps://%s:%d", ldapConfig->host, ldapConfig->ssl_port);
    }
    else
    {
        sprintf(uri, "ldap://%s:%d", ldapConfig->host, ldapConfig->ssl_port);
    }

#if USING_OPEN_LDAP
    setenv("LDAPTLS_REQCERT", "never", 1);

    if (using_debug_mode)
    {
       int ret = ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &debug_mode_option);
       debug ("ret of setting debug_mode=%d\n", ret);
       (void)(ret);
    }
    debug("ldap_set_option(LDAP_OPT_X_TLS_REQUIRE_CERT)\n");
    if ((ret =  ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &no_certificate)) < 0 )
    {
            set_ldap_error(ret, data);
            return(NULL);
    }

    debug("ldap_initialize(): uri=%s", uri);
    if ((ret = ldap_initialize(&ld, uri)) < 0)
    {
        set_ldap_error(ret, data);
        data->connected_code = ret;
        return(NULL);
    }
#else
    /*
     * Mozilla LDAP needs a certificate even it is not good or not valid
     *
     */
    if ( (ret =  ldapssl_client_init( cert7db, NULL )) < 0 )
    {
        set_ldap_error(ret, data);
        return(NULL);
    }
    if ( (ld = ldapssl_init( ldapConfig->host, ldapConfig->ssl_port, 1 )) == NULL )
    {
        set_ldap_error(ret, data);
        return( NULL );
    }
    ldapssl_set_strength(ld, LDAPSSL_AUTH_WEAK);
#endif

    // used to see same parameters
    //  printdse(ld);
    //  return NULL;

    debug("ldap_set_option(LDAP_OPT_PROTOCOL_VERSION): ld=0x%p", ld);
    if ((ret  = ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version )) < 0 )
    {
        set_ldap_error(ret, data);
        return(NULL);
    }

    if ((ret = ldap_set_option(ld, LDAP_OPT_REFERRALS, 0)) < 0)
    {
         debug("ERROR:  ldap_set_option(ld, LDAP_OPT_REFERRALS( ret=%d)", ret);
         set_ldap_error(ret, data);
         debug("message=%s" , data->errorMessage);
    }

    // Authenticating service account */
    debug("ldap_simple_bind_s(): ld=0x%p", ld);
    ret = ldap_simple_bind_s(ld, ldapConfig->serviceDN, ldapConfig->servicePassword);
    if (ret != 0)
    {
        debug("ERROR: in ldap_simple_bind_s(ret=%d)", ret);
        set_ldap_error(ret, data);
        data->connected_code = ret;
        return(NULL);
    }
    debug("OK: in ldap_simple_bind_s()");
    return(ld);
}


//--------------------------------------------------------
/*!
 *  Private function populate_user_info()
 */
static void populate_user_info(LDAP *ld, LDAPMessage *user_result, LDAP_RETURN_DATA *data, int index)
{
    int len = 0;
    char *attribute = 0;
    char **vals     = 0;
    int  has_core_id_alternative = 0;  // default does not have
    char *token  = NULL;
    struct SplitString *result = NULL;

#define SAFETY_COPY_SAME_ATTRIBUTE_RESULT(index, field)  \
               attribute = ldapConfig->result_attributes.field;\
               if (*attribute && (vals = ldap_get_values(ld, user_result, attribute)))\
               {\
                   strncpy(data->info[index]->field, vals[0], MAX_LDAP_SITE_SIZE -1);\
                   ldap_value_free(vals);\
               }


#define SAFETY_COPY_DIFF_ATTRIBUTE_RESULT(index, name_attr, field)  \
               attribute = ldapConfig->result_attributes.name_attr;\
               if (*attribute && (vals = ldap_get_values(ld, user_result, attribute)))\
               {\
                   strncpy(data->info[index]->field, vals[0], MAX_LDAP_SITE_SIZE -1);\
                   ldap_value_free(vals);\
               }


    /* Initialize name for later use */
    data->info[index]->name[0] = '\0';

    // is there a "first name" parameter in the result string?
    attribute = ldapConfig->result_attributes.firstName;
    if (*attribute)
    {
        vals = ldap_get_values(ld, user_result, attribute);
        if( vals != NULL ) {
            len = sprintf(data->info[index]->name, "%s", vals[0]);
            ldap_value_free( vals );
        }
    }

    // is there a "last name" parameter in the result string?
    attribute = ldapConfig->result_attributes.lastName;
    if (*attribute)
    {
        vals = ldap_get_values(ld, user_result,attribute );
        if( vals != NULL ) {
            len += sprintf(data->info[index]->name+len, " %s", vals[0]);
            ldap_value_free( vals );
        }
    }

    SAFETY_COPY_DIFF_ATTRIBUTE_RESULT(index, fullName, name);

    // If the name was not found, assign default */
    if (data->info[index]->name[0] == '\0')
    {
        strcpy(data->info[index]->name, "Customer");
    }

    attribute = ldapConfig->result_attributes.core_id;
    if (*attribute)
    {
        vals = ldap_get_values(ld, user_result, attribute);
        if( vals != NULL ) {
            strcpy(data->info[index]->coreId, vals[0]);
            ldap_value_free( vals );
        }
    }

    result = split_string(ldapConfig->result_attributes.core_id_alternative, ' ');
    token = split_getString(result);
    while (token != NULL)
    {
    //first check for an alternative core_id not empty
        attribute = token;
    if ( *attribute != '\0' && (vals = ldap_get_values(ld, user_result, attribute)) != NULL)
    {
        // there is an alternative core_id, save it
        strcpy(data->info[index]->alternative_coreId, vals[0]);
        has_core_id_alternative = 1;
        ldap_value_free( vals );
            /*
              * workaround to get the right field for external UID
            */
            if (strcmp(token,  "uid") == 0)
    {
                strcpy(data->info[index]->coreId,  data->info[index]->alternative_coreId);
        }
    }
        token = split_getString(result);
    }


    // a valid core_id or alternative  core_id
    if(data->info[index]->coreId[0] || has_core_id_alternative)
    {
        len = sprintf(data->info[index]->corporate_email, "%s%s", data->info[index]->coreId,
                           ldapConfig->emailSuffix);
        if (len >= MAX_LDAP_INFO_SIZE)
        {
            strncpy(data->errorMessage, "corporate_email buffer overflow",
                            sizeof(data->errorMessage) -1);
            data->result = -1;
            return;
        }
        // if there is an alternative_coreId decide which to keep as real coreID
        // default keep current 'core_id' field content defined in LDAP_RESULT_STRING struct
        if (has_core_id_alternative)
        {
#if defined(LDAP_UID_FORCE_FSL_COREID)
            strcpy(data->info[index]->coreId, data->info[index]->alternative_coreId);
#else
#if defined(LDAP_UID_EQUAL_SEARCH_OR_LOGIN)
            if (gl_lastSearchByCoreId != 0 &&
                strcasecmp(gl_lastSearchByCoreId, data->info[index]->alternative_coreId) == 0)
            {
                strcpy(data->info[index]->coreId, data->info[index]->alternative_coreId);
            }
#endif
#endif
        } // if (has_core_id_alternative)
    }

    // is there a "mail" parameter in the result string?
    SAFETY_COPY_DIFF_ATTRIBUTE_RESULT(index, mail, friendly_email);

    // is there a "location" parameter in the result string?
    SAFETY_COPY_DIFF_ATTRIBUTE_RESULT(index, location, site);

    SAFETY_COPY_SAME_ATTRIBUTE_RESULT(index, extra_info_1);
    SAFETY_COPY_SAME_ATTRIBUTE_RESULT(index, extra_info_2);
    SAFETY_COPY_SAME_ATTRIBUTE_RESULT(index, extra_info_3);
    SAFETY_COPY_SAME_ATTRIBUTE_RESULT(index, extra_info_4);
    SAFETY_COPY_SAME_ATTRIBUTE_RESULT(index, extra_info_5);
    SAFETY_COPY_SAME_ATTRIBUTE_RESULT(index, extra_info_6);
    SAFETY_COPY_SAME_ATTRIBUTE_RESULT(index, extra_info_7);
    SAFETY_COPY_SAME_ATTRIBUTE_RESULT(index, extra_info_8);
    SAFETY_COPY_SAME_ATTRIBUTE_RESULT(index, extra_info_9);

    /* special check for email */
    if (    data->info[index]->friendly_email[0] == '\0'
         && data->info[index]->extra_info_3[0] != '\0'
         && strchr(data->info[index]->extra_info_3, '@') != NULL)
    {
         strcpy(data->info[index]->friendly_email, data->info[index]->extra_info_3);
    }
}



//--------------------------------------------------------
/*!
 *  Private function populate_ldapfsl_lookup()
 */
static void populate_ldapfsl_lookup(LDAP *ld, LDAPMessage *search_result, LDAP_RETURN_DATA *data)
{
    if (ld && search_result && data)
    {
        LDAPMessage      *user_result   = 0;
        data->entries = ldap_count_entries( ld, search_result );
        alocate_return_data_entries(data->entries, data);
        if ((user_result = ldap_first_entry( ld, search_result )) == NULL)
        {
            data->result = -1;
            strncpy(data->errorMessage , "Could not get data from ldap_first_entry()", sizeof(data->errorMessage) -1);
        }
        else
        {
           int index = 0;
           while( index < data->entries && data->result == LDAP_SUCCESS && user_result)
           {
               populate_user_info(ld, user_result, data, index++);
               user_result = ldap_next_entry( ld, user_result );
           }
        }
    }
}



//--------------------------------------------------------
/*!
 *  Private function authenticate_ldapfsl_lookup()
 *
 *  It does the authentication, it is called by ldapfsl_lookup() when type is \ref DO_AUTHENTICATE
 */
static void authenticate_ldapfsl_lookup(LDAP* ld, LDAPMessage *search_result, LDAP_RETURN_DATA *data, const char *password)
{
    char        * name_ptr    = NULL;
    LDAPMessage * user_result = NULL;

    if (data->result == LDAP_SUCCESS)
    {
        /* Get the first entry so can retrieve specific attributes */
        if ((user_result = ldap_first_entry( ld, search_result )) == NULL)
        {
            data->result = -1;
        }
    }

    if (data->result == LDAP_SUCCESS)
    {
        /* Get the full name needed for the authentication command */
        if ((name_ptr = ldap_get_dn(ld, user_result)) == NULL)
        {
            data->result = -1;
        }
    }

    if (data->result == LDAP_SUCCESS)
    {
        if (!password || password[0] == '\0')
        {
            data->result = -1;
            strcpy(data->errorMessage, "empty password");
        }
        else
        {
            /* Authenticate user */
            int ret = ldap_simple_bind_s(ld, name_ptr, password);
            if ( ret != LDAP_SUCCESS)
            {
                data->result = ret;
                strcpy(data->errorMessage, "bad password");
            }
        }
    }

    if (name_ptr)
    {
        ldap_memfree(name_ptr);
    }
}


/*!
 *  Private function
 */
static void make_lookup_filter_by_name(const char *searchData, char* filter /*out*/)
{
    const char *last_name = strchr(searchData, ' ');
    char *space  = 0;
    if (last_name != 0)
    {
        space = (char *)last_name++;
        *space = 0;
        while (*last_name && *last_name == ' ') { last_name++; }
    }
    if (ldapConfig->result_attributes.fullName[0])
    {
        if (space && last_name != 0 && last_name[0] != 0)
        {
                *space =  '*'; /* make the space a wildcard */
        }
        sprintf(&filter[strlen(filter)], "(%s=*%s*)", ldapConfig->result_attributes.fullName, searchData);
    }
    else
    {
        if (last_name == 0 || last_name[0] == 0)
        {
            last_name = searchData;
            strcpy(filter, "(|");
        }
        else
        {
                strcpy(filter, "(&");
        }

        if (ldapConfig->result_attributes.firstName[0])
        {
            sprintf(&filter[strlen(filter)], "(%s=*%s*)", ldapConfig->result_attributes.firstName, searchData);
        }
        if (ldapConfig->result_attributes.lastName[0] && last_name && last_name[0])
        {
            sprintf(&filter[strlen(filter)], "(%s=*%s*)", ldapConfig->result_attributes.lastName, last_name);
        }
        strcat(filter, ")");
    }
    // it is expected: (|(givenname=name)(sn=%s))"
    if (space)
    {
        *space =  ' ';
    }
}


/*!
 *  Private function
 */
static void make_lookup_filter_by_uid(const char *searchData, char *alternative_coreid, char* filter /*out*/)
{
    if (searchData && strcmp(searchData, "*") == 0)
    {
        sprintf(filter, "(objectClass=person)");
    }
    // else if there is an alternative core_id field use OR
    else if (alternative_coreid != NULL && alternative_coreid[0] != '\0')
    {
        sprintf(filter, "(|(%s=%s)(%s=%s))",
                ldapConfig->result_attributes.core_id,
                searchData,
                alternative_coreid,
                searchData);
    }
    else // normal case there is no core_id_alternative
    {
        sprintf(filter, "(%s=%s)",
                ldapConfig->result_attributes.core_id,
                searchData);
    }
}

//--------------------------------------------------------
/*!ldapfsl_do_search
*  Private function ldapfsl_do_serach()
*/
//---------------------------------------------------------
static int ldapfsl_do_search(LDAP             ** ld,            // reference of pointer
                             LDAP_RETURN_DATA ** return_data,   // reference of pointer
                             LDAPMessage      ** search_result, // reference of pointer
                             char* filter)
{
    int ret  = -1;
    int              time_limit_attempts = 2;
    debug("ldapfsl_do_search(): calling ldap_search_s() filter=%s", filter);
    ret = ldap_search_s(*ld, ldapConfig->searchString, LDAP_SCOPE_SUBTREE,
                        filter, NULL, 0, search_result);
    debug("returned from ldap_search_s() ret=%d\n", ret);

    /*
    * Work around for LDAP_TIMELIMIT_EXCEEDED, the default timeout is 120 seconds
    * that means, it has already used 120 seconds.
    * trying a second connection using a short time for this timeout.
    */
    while (ret == LDAP_TIMELIMIT_EXCEEDED && ld != NULL && time_limit_attempts--)
    {
        ldap_unbind(*ld);   // shutdown  current connection
        *ld = ldap_connect(*return_data); // create a new one
        if (*ld != NULL)
        {
            int timelimit = 64;
            int ret_timeLimit = setOpenLdapTimeoutTimeLimit(*ld, timelimit);
            // avoid warning
            (void) ret_timeLimit;
            debug("return of setOpenLdapTimeoutTimeLimit(%d)=%d", timelimit, ret_timeLimit);
            debug("LDAP_TIMELIMIT_EXCEEDED: calling ldap_search_s() again");
            ret = ldap_search_s(*ld, ldapConfig->searchString, LDAP_SCOPE_SUBTREE,
                                filter, NULL, 0, search_result);
                                debug("LDAP_TIMELIMIT_EXCEEDED returned from ldap_search_s() ret=%d", ret);
        }
    }
    debug("returned from ldapfsl_do_search() ret=%d", ret);
    return ret;
}
//--------------------------------------------------------
/*!
 *  Private function ldapfsl_lookup()
 */
static LDAP_RETURN_DATA *ldapfsl_lookup(const char *searchData, int type, const char *password)
{
   // char *ptr;
    LDAPMessage      *search_result = 0;
    LDAP             *ld = NULL;
    int              ret = -1;
    char             filter[512] = {0};

    LDAP_RETURN_DATA * return_data = create_return_data();

    if ((ld = ldap_connect(return_data)) == NULL)
    {
        return return_data;
    }
    gl_lastSearchByCoreId = 0;
    switch (type)
    {
       case DO_SEARCH_NAME:
                               make_lookup_filter_by_name(searchData, filter);
                               ret = ldapfsl_do_search(&ld, &return_data,  &search_result, filter);
       break;
       case DO_AUTHENTICATE:
       case DO_SEARCH_COREID:
                              gl_lastSearchByCoreId = searchData;
                              if (ldapConfig->result_attributes.core_id_alternative[0] == '\0')
                              {
                                  make_lookup_filter_by_uid(searchData, NULL, filter);
                                  ret = ldapfsl_do_search(&ld, &return_data,  &search_result, filter);
    }
                              else
                              {
                                   /** it is possible to have more than one field in
                                         ldapConfig->result_attributes.core_id_alternative separated by space,
                                         then split that string and loop searching by different filters
     */
                                   struct SplitString *result = split_string(ldapConfig->result_attributes.core_id_alternative, ' ');
                                   char *token = split_getString(result);
                                   do
    {
                                        make_lookup_filter_by_uid(searchData, token, filter);
                                        ret = ldapfsl_do_search(&ld, &return_data,  &search_result, filter);
                                        token = split_getString(result);
                                        if (token != NULL && IS_GOOD_LDAP_SEARCH(ret) && search_result != NULL)
        {
                                            if (ldap_count_entries(ld, search_result) <= 0)
                                            {
                                                  ret = -1;  // force it to keep trying
                                            }
        }
                                   } while ((!IS_GOOD_LDAP_SEARCH(ret)) && token != NULL);
                              }
       break;
       case DO_SEARCH_FILTER:
                              strcpy(filter, searchData);
                              ret = ldapfsl_do_search(&ld, &return_data, &search_result, filter);
       break;
       default:  return return_data;
    }

    if (!IS_GOOD_LDAP_SEARCH(ret))
    {
        set_ldap_error(ret, return_data);
    }

    if (return_data->result == LDAP_SUCCESS && type == DO_AUTHENTICATE && password != NULL )
    {
        authenticate_ldapfsl_lookup(ld, search_result, return_data, password);
    }

    if (return_data->result == LDAP_SUCCESS)
    {
#if REGRESSION_TEST_LDAP
        if (type == DO_SEARCH_COREID || type == DO_SEARCH_NAME)
        {
           list_all_attributes(ld, search_result);
        }
#endif
        populate_ldapfsl_lookup(ld, search_result, return_data);
    }

    //now release allocated data

    if (search_result)
    {
        ldap_msgfree(search_result);
    }
    if (ld != NULL)
    {
        ldap_unbind(ld);
    }
    return return_data;
}

/*!
 *  Private function ldapsearch_content_from_line()
 */
static const char *ldapsearch_content_from_line(const char *line, const char *fieldName)
{
    const char *pt = NULL;
    int len = strlen(fieldName);
    if (len > 0 && strncmp(line, fieldName, len) == 0 && line[len] == ':' )
    {
        pt = line + len + 2;
    }
    return pt;
}


/*!
 *  Private function
 */
static void populate_ldapsearch_from_tempfile(const char * tempFilName, int entries, LDAP_RETURN_DATA *return_data)
{
#define LINE_STARTS_WITH(x, content) (strncmp(line, x, strlen(x)) == 0)

    const char *results_file = tempFilName;
    int  myEntry = -1;

    FILE *result = fopen(results_file, "r");
    if (result == NULL)
    {
        printf("ERROR: %s:%d could not open the file %s\n", __FILE__, __LINE__, results_file);
    }
    else
    {
        char line [512];
        alocate_return_data_entries(entries, return_data);
        return_data->result = LDAP_SUCCESS;
        const char *content = 0;
        char my_name[128];
        while ( fgets(line, sizeof(line) -1, result) )
        {
            int len = strlen(line);
            if (len == 1 ) {continue;}  // maybe an empty line
            if (line [len -1] == '\n') {
                line [len -1] = 0;
            }
            my_name[0] = 0;
            if (strncmp(line, "dn:", 3) == 0 && myEntry < entries) {
                myEntry++;
            }
            else if ((content = ldapsearch_content_from_line(line, ldapConfig->result_attributes.core_id)))
            {
                strcpy(return_data->info[myEntry]->coreId, content);
                sprintf(return_data->info[myEntry]->corporate_email, "%s@%s", content, ldapConfig->emailSuffix);
            }
            else if ((content = ldapsearch_content_from_line(line, ldapConfig->result_attributes.location)))
            {
                strcpy(return_data->info[myEntry]->site, content);
            }
            else if ((content = ldapsearch_content_from_line(line, ldapConfig->result_attributes.mail)))
            {
                strcpy(return_data->info[myEntry]->friendly_email, content);
            }
            else if ((content = ldapsearch_content_from_line(line, ldapConfig->result_attributes.fullName)))
            {
                strcpy(return_data->info[myEntry]->name, content);
            }
            else if ((content = ldapsearch_content_from_line(line, ldapConfig->result_attributes.lastName)))
            {
                if (return_data->info[myEntry]->name[0])
                {
                    strcat(return_data->info[myEntry]->name, " ");
                    strcat(return_data->info[myEntry]->name, content);
                }
                else
                {
                    strcpy(return_data->info[myEntry]->name, content);
                }
            }
            else if ((content = ldapsearch_content_from_line(line, ldapConfig->result_attributes.firstName)))
            {
                if (return_data->info[myEntry]->name[0])
                {
                    strcpy (my_name, return_data->info[myEntry]->name);
                    strcpy(return_data->info[myEntry]->name, content);
                    strcat(return_data->info[myEntry]->name, " ");
                    strcat(return_data->info[myEntry]->name, my_name);
                }
                else
                {
                    strcpy(return_data->info[myEntry]->name, content);
                }
            }
        }
        fclose(result);
    }
}

/*!
 *  Private function ldapsearch()
 *
 *  Perform a search using the command "ldapsearch"
 **/
static LDAP_RETURN_DATA * ldapsearch(const char *searchData, int type)
{
     LDAP_RETURN_DATA * return_data = create_return_data();
     char command[512];
     int (*close_cmd)(FILE *)    = pclose;

     /*
      * ldapsearch -x -LL uid=nxa13339 -b  ou=people,ou=NXDI,o=NXP fullname mail city uid
        version: 1

        dn: cn=nxa13339,ou=Personal,ou=People,ou=NXDI,o=NXP
        uid: nxa13339
        city: Campinas
        mail: carlos.mazieri@nxp.com
        fullname: Carlos Mazieri
      */

     char searchString[256];
     char *name_parameter = ldapConfig->result_attributes.fullName;

     if (type == DO_SEARCH_COREID)
     {
         sprintf(searchString, "%s=%s", ldapConfig->result_attributes.core_id, searchData);
     }
     else if (type == DO_SEARCH_NAME)
     {
         if (*name_parameter == '\0') {name_parameter = ldapConfig->result_attributes.firstName; }
         if (*name_parameter == '\0') {name_parameter = ldapConfig->result_attributes.lastName; }
         sprintf(searchString, "%s=\"*%s*\"", name_parameter, searchData);
     }

     sprintf(command, "ldapsearch -x -LL %s -b %s %s %s %s %s",
             searchString,
             ldapConfig->searchString,
             ldapConfig->result_attributes.core_id,
             ldapConfig->result_attributes.mail,
             ldapConfig->result_attributes.location,
             name_parameter);
     if (name_parameter == ldapConfig->result_attributes.firstName && ldapConfig->result_attributes.lastName[0])
     {
         strcat(command, " ");
         strcat(command, ldapConfig->result_attributes.lastName);
     }
     else
     if (name_parameter == ldapConfig->result_attributes.lastName && ldapConfig->result_attributes.firstName[0])
     {
         strcat(command, " ");
         strcat(command, ldapConfig->result_attributes.firstName);
     }
#if REGRESSION_TEST_LDAP
    fprintf(stderr, "[%s:%d] ldapsearch(): commnd=%s\n", __FILE__, __LINE__, command );
#endif

    return_data->result = -1;
    FILE *cmd = NULL;

#if defined(REGRESSION_TEST_LDAP)
    if (regression_test_ldapsearch_file[0])
    {
         cmd = fopen(regression_test_ldapsearch_file, "r");
         close_cmd = fclose;
    }
    else
    {
         cmd = popen(command, "r");
         fprintf(stderr, "[%s:%d] ldapsearch(): cmd=%p\n", __FILE__, __LINE__, cmd);
    }
#else
    cmd = popen(command, "r");
#endif

    if (cmd != NULL)
    {
        char *line = command; // uses the same buffer
        int entries = 0;
        char tempFilName[256];
        char *user = getenv("USER");
        sprintf(tempFilName, "/tmp/ldapsearch_%s_%ld%ld.txt",  user != NULL ? user : "unknown" , (long)getpid(), (long)getppid());
        FILE * tempFile = fopen(tempFilName,"w");
        if (tempFile == NULL)
        {
            printf("ERROR: %s:%d Could not create a temporary file\n", __FILE__, __LINE__);
        }
        else
        {
            while (fgets(line, sizeof(command) -1, cmd) != NULL)
            {
                if (strncmp(line, "dn:", 3) == 0)
                {
                    entries++;
                }
                fputs(line, tempFile);
            }
            fclose(tempFile);
            close_cmd(cmd);
            populate_ldapsearch_from_tempfile(tempFilName, entries, return_data);
            unlink(tempFilName);
        }
    }
    else
    {
        printf("ERROR: %s:%d Could not execute the command \"%s\" file\n", __FILE__, __LINE__, command);
    }


    return return_data;
}


//=================================== public functions ===============================================
//====================================================================================================

//-----------------------------------------------------------
/*!
 *  Public function ldapfsl_setCaCertFileName()
 *
 * \param a full path and name of a certificate file
 */
void ldapfsl_setCaCertFileName(const char *pathname)
{
   strcpy(cert7db, pathname);

 #if USING_OPEN_LDAP
    {
        //OpenLDAP uses the Certificate Directory
        struct stat st;
        if (stat(cert7db, &st) != -1 &&  !S_ISDIR(st.st_mode))
        {
            char *dirDelimiter = strrchr(cert7db, '/');
            if (dirDelimiter)
            {
                *dirDelimiter = 0;
            }
        }
   }
#endif
}


//-----------------------------------------------------------
/*!
 *  Public function ldapfsl_setLdapConfig()
 *
 *  Sets all LDAP information to access the LDAP server
 *
 * \param pointer to LDAP_CONFIG struct
 */
void ldapfsl_setLdapConfig(LDAP_CONFIG *config)
{
    if (config != 0)
    {
        static LDAP_CONFIG  private_config;
        // copy data into a private and safe variable
        private_config = *config;
        ldapConfig = & private_config;
    }
}



//-----------------------------------------------------------
/*!
 *  Public function ldapfsl_setNXPcoreidLdapConfig()
 *
 *  Sets all FSL LDAP information to access the LDAP server
 *
 */
void ldapfsl_setNXPcoreidLdapConfig()
{
    ldapConfig = & ldapNXPcoreidConfig;
}


LDAP_CONFIG * ldapfsl_getNXPcoreidLdapConfig()
{
    return &ldapNXPcoreidConfig;
}


void ldapfsl_setNXPwbiidLdapConfig()
{
    ldapConfig = & ldapNXPwbiidConfig;
}


LDAP_CONFIG * ldapfsl_getNXPwbiidLdapConfig()
{
    return &ldapNXPwbiidConfig;
}


void ldapfsl_setFSLextranetLdapConfig()
{
     ldapConfig = & ldapFSLextranetLdapConfig;
}


LDAP_CONFIG * ldapfsl_getFSLExtranetLdapConfig()
{
    return &ldapFSLextranetLdapConfig;
}


void ldapfsl_setFSLintranetLdapConfig()
{
    ldapConfig = & ldapFSLintranetLdapConfig;
}


LDAP_CONFIG * ldapfsl_getFSLintranetLdapConfig()
{
    return  & ldapFSLintranetLdapConfig;
}


void ldapfsl_setServerID(enum Server_Config_ID  id)
{
     static LDAP_CONFIG * servers_table[] =
     {
          & ldapNXPcoreidConfig
        , & ldapNXPwbiidConfig
        , & ldapFSLintranetLdapConfig
        , & ldapFSLextranetLdapConfig
        , & ldapNXPextranetLdapConfig
     };
     // set only if id is a valid index
     if ((int)id >= 0 && id < sizeof(servers_table)/sizeof(servers_table[0]))
     {
        ldapConfig = servers_table[id];
     }
}

LDAP_CONFIG * ldapfsl_getCurrentConfig()
{
    return ldapConfig;
}

//--------------------------------------------------------
/*!
 *   Public ldapfsl_free_return_data()
 *
 *   Releases all data got in LDAP_RETURN_DATA
 */
void ldapfsl_free_return_data(LDAP_RETURN_DATA *data)
{
    if (data)
    {
        if (data->info)
        {
            int entries = data->entries;
            while(entries--)
            {
                free((void*) data->info[entries]);
            }
            free((void*)data->info);
        }
        free((void*) data);
    }
}


#if 0 // just disabled
/*!
 *   get_NXP_email_from_FSL_coreID()  get the correspoding NXP friendly email for a query mande in the Freescale Ldap
 *
 *   April 2016,
 *    As the Freescale email is going to be disabled soon and there still be  applications running the Freescale network
 *    that  needs a valid email, this function can be called to map the FSL coreID with the NXP coreID and get the right email
 */
static void get_NXP_email_from_FSL_coreID(LDAP_RETURN_DATA *data)
{
    int isNXP = strcmp(ldapConfig->emailSuffix, ldapNXPcoreidConfig.emailSuffix);
    //!isNXP means the configuration is for Freescale not for NXP
    if (!isNXP && data != 0 && data->result == LDAP_SUCCESS && data->entries > 0)
    {
        const char *csv = "/sync/admin/etc/wbi_map.csv";  //this a table made for  existent FSL coreIDs to map NXP coreIDs
        FILE *in  = fopen(csv, "r");
        if (in != NULL)
        {
            char fsl_coreID[96];
            char nxp_coreID[16];

            int counter = data->entries;
            char *pt = 0;
            char *fm = 0;
            LDAP_USER_INFORMATION *info = 0;
            while(counter--)
            {
                info  = data->info[counter];
                rewind(in);
                fsl_coreID[ sizeof(fsl_coreID) -1 ] = 0;
                while (!feof(in) && fgets(fsl_coreID, sizeof(fsl_coreID) -1, in) != NULL)
                {
                    if ((pt = strchr(fsl_coreID, ',')))
                    {
                        *pt++ = 0;
                        if (strcasecmp(info->coreId, fsl_coreID) == 0)
                        {
                            int lastChar = strlen(pt) -1;
                            if (isspace(pt[lastChar]))
                            {
                                pt[lastChar] = 0;
                            }
                            if ((fm=strchr(pt, ',')) != 0) // email is present in the file
                            {
                                *fm++ = 0;
                                strcpy(info->friendly_email, fm);
                            }
                            else
                            {
                                LDAP_RETURN_DATA *ret = 0;
                                strcpy(nxp_coreID,pt);
                                ldapfsl_setNXPwbiidLdapConfig();
                                ret = ldapfsl_lookupByCoreId(nxp_coreID);
                                if (ret != 0 && ret->result == LDAP_SUCCESS && ret->entries == 1 )
                                {
                                    strcpy(info->friendly_email, ret->info[0]->friendly_email);
                                }
                                ldapfsl_free_return_data(ret);
                                ldapfsl_setNXPcoreidLdapConfig();
                            }
                            break;
                        }// end the core matches
                    } // end has a comma
                }// end read the whole file
            }
            fclose(in);
        }//end file exists
    }
}
#endif


LDAP_RETURN_DATA * ldapfsl_lookupByCoreId(const char *coreId)
{
    LDAP_RETURN_DATA * ret = 0;
    if (ldapConfig->system != LDAP_CONFIG_SYSTEM_INVALID)
    {
        ret =   ldapConfig->system == LDAP_CONFIG_SYSTEM_API ?
                   ldapfsl_lookup(coreId, DO_SEARCH_COREID, NULL) :
                   ldapsearch(coreId, DO_SEARCH_COREID);
    }
  //  get_NXP_email_from_FSL_coreID(ret);
    return ret;
}



LDAP_RETURN_DATA * ldapfsl_lookupByName(const char *name)
{
    LDAP_RETURN_DATA * ret = 0;
    if (ldapConfig->system != LDAP_CONFIG_SYSTEM_INVALID)
    {
       ret =  ldapConfig->system == LDAP_CONFIG_SYSTEM_API ?
                 ldapfsl_lookup(name, DO_SEARCH_NAME, NULL) :
                 ldapsearch(name, DO_SEARCH_NAME);
    }
 //   get_NXP_email_from_FSL_coreID(ret);
    return ret;
}



LDAP_RETURN_DATA * ldapfsl_authenticateCoreId(const char *coreId, const char *password)
{
    LDAP_RETURN_DATA * ret = 0;
    if (ldapConfig->system != LDAP_CONFIG_SYSTEM_INVALID)
    {
        ret = ldapfsl_lookup(coreId, DO_AUTHENTICATE, password);
    }
    return ret;
}


LDAP_RETURN_DATA * ldapfsl_lookupByFilter(const char *filter)
{
    LDAP_RETURN_DATA * ret = 0;
    if (ldapConfig->system != LDAP_CONFIG_SYSTEM_INVALID)
    {
        ret = ldapfsl_lookup(filter, DO_SEARCH_FILTER, NULL);
    }
    return ret;
}



LDAP_RETURN_DATA * ldapfsl_lookupByMail(const char *mail)
{
#define name_alternative_email_field(config)  config->result_attributes.extra_info_3
    LDAP_RETURN_DATA * ret = 0;
    if (ldapConfig->system != LDAP_CONFIG_SYSTEM_INVALID)
    {
         char filter[512] = {0};
         if (name_alternative_email_field(ldapConfig)[0])
         {
            strcpy(filter, "(|");
         }
         sprintf(&filter[strlen(filter)], "(%s=%s)", ldapConfig->result_attributes.mail, mail);
         if (name_alternative_email_field(ldapConfig)[0])
         {
            sprintf(&filter[strlen(filter)], "(%s=%s))", name_alternative_email_field(ldapConfig), mail);
         }
         ret = ldapfsl_lookupByFilter(filter);
    }
    return ret;
}



LDAP_RETURN_DATA * ldapfsl_getManagerOf(const LDAP_USER_INFORMATION * user_info)
{
#define name_uid_field(config)           config->result_attributes.core_id
#define name_manager_field(config)       config->result_attributes.extra_info_8
#define value_manager_field(user)        user->extra_info_6
#define value_employeeType_field(user)   user->extra_info_7

  LDAP_RETURN_DATA * manager_info = 0;

  // two possibilities:
  //  1. the value of the manager field contains the 'uid' of the manager
  //         Example: CN=nxa09194, where CN is the 'uid'
  //     1.1 parse and get CN value
  //     1.2 call ldapfsl_lookupByCoreId()
  //  2. the value of the manager field is a direct value of a field that serch for it
  //     2.1 create a filter name_manager_field(config)=value_manager_field(user_info)
  //     2.2 search using this filter

  if (value_manager_field(user_info)[0])  // if not empty
  {
     char *equal = strchr(value_manager_field(user_info), '=');
     if (equal != 0 )  // perhaps case 1
     {
          int len  =  equal - value_manager_field(user_info);
          if (len > 2)
          {
               char *pt = equal;
               while (*pt == ' ' && len > 2) len--; // avoid any space before =
          }
          if (strncasecmp(value_manager_field(user_info), name_uid_field(ldapConfig), len) == 0)
          {
               char manager_id[LDAP_RESULT_ATTRIBUTE_SIZE] = {0};
               char *pt = equal + 1;
               while (*pt == ' ') ++pt;  // avoid spaces after =
               len  = 0;
               // ony letters and digits are expected
               while (isalnum((int)*pt))
               {
                    manager_id[len++] = *pt++;
               }
               manager_id[len] = 0;
               manager_info = ldapfsl_lookupByCoreId(manager_id);
          }
     }
     else
     {
               char filter[512];
               sprintf(filter, "(&(%s=%s)(employeeType=R))", name_manager_field(ldapConfig), value_manager_field(user_info));
               manager_info = ldapfsl_lookupByFilter(filter);
     }
  }
  return manager_info;
}



LDAP_RETURN_DATA * ldapfsl_getManagerOfCoreId(const char *login_id)
{
    LDAP_RETURN_DATA * manager_info = 0;
    LDAP_RETURN_DATA * user_info    = ldapfsl_lookupByCoreId(login_id);
    if (user_info != 0 && user_info->result == LDAP_SUCCESS)
    {
          manager_info = ldapfsl_getManagerOf(user_info->info[0]);
    }
    ldapfsl_free_return_data(user_info);
    return manager_info;
}


/*!
 * \brief printdse() used for debug purposes
 * \param ld
 * \return
 */
int printdse( LDAP *ld )
{
  int rc, i;
  LDAPMessage  *result, *e;
  BerElement  *ber;
  char    *a;
  char    **vals;
  char    *attrs[3];
  /* Verify that the connection handle is valid. */
  if ( ld == NULL ) {
    fprintf( stderr, "Invalid connection handle.\n" );
    return( 1 );
  }
  /* Set automatic referral processing off. */
  if ( (rc = ldap_set_option( ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF )) != 0 ) {
    fprintf( stderr, "ldap_set_option: %s\n", ldap_err2string( rc ) );
    return( 1 );
  }
  /* Search for the root DSE. */
  attrs[0] = "supportedControl";
  attrs[1] = "supportedExtension";
  attrs[2] = NULL;
  rc = ldap_search_ext_s( ld, "", LDAP_SCOPE_BASE, "(objectclass=*)", attrs,
    0, NULL, NULL, NULL, 0, &result );
  /* Check the search results. */
  switch( rc ) {
  /* If successful, the root DSE was found. */
  case LDAP_SUCCESS:
    break;
  /* If the root DSE was not found, the server does not comply
     with the LDAPv3 protocol. */
  case LDAP_PARTIAL_RESULTS:
  case LDAP_NO_SUCH_OBJECT:
  case LDAP_OPERATIONS_ERROR:
  case LDAP_PROTOCOL_ERROR:
    printf( "LDAP server returned result code %d (%s).\n"
      "This server does not support the LDAPv3 protocol.\n",
      rc, ldap_err2string( rc ) );
    return( 1 );
  /* If any other value is returned, an error must have occurred. */
  default:
    fprintf( stderr, "ldap_search_ext_s: %s\n", ldap_err2string( rc ) );
    return( 1 );
  }
  /* Since only one entry should have matched, get that entry. */
  e = ldap_first_entry( ld, result );
  if ( e == NULL ) {
    fprintf( stderr, "ldap_search_ext_s: Unable to get root DSE.\n");
    ldap_memfree( result );
    return( 1 );
  }

  /* Iterate through each attribute in the entry. */
  for ( a = ldap_first_attribute( ld, e, &ber );
    a != NULL; a = ldap_next_attribute( ld, e, ber ) ) {

    /* Print each value of the attribute. */
    if ((vals = ldap_get_values( ld, e, a)) != NULL ) {
      for ( i = 0; vals[i] != NULL; i++ ) {
        printf( "%s: %s\n", a, vals[i] );
      }

      /* Free memory allocated by ldap_get_values(). */
      ldap_value_free( vals );
    }

    /* Free memory allocated by ldap_first_attribute(). */
    ldap_memfree( a );
  }

  /* Free memory allocated by ldap_first_attribute(). */
  if ( ber != NULL ) {
    ber_free( ber, 0 );
  }

  printf( "\n" );
  /* Free memory allocated by ldap_search_ext_s(). */
  ldap_msgfree( result );
  ldap_unbind( ld );
  return( 0 );
}


void printLdapHardResults(LDAP_RETURN_DATA * ret, FILE * output)
{
#define PRINT_SAME_FIELD_NAME(name, counter)          fprintf(output, "%-20s[%02d] = %s\n", #name, counter, ret->info[counter]->name)
#define PRINT_DIFF_FIELD_NAME(name, field, counter)   fprintf(output, "%-20s[%02d] = %s\n", #name, counter, ret->info[counter]->field)
    int counter = 0;
    for  (; counter < ret->entries; counter++)
    {
        PRINT_SAME_FIELD_NAME(coreId, counter);
        PRINT_SAME_FIELD_NAME(name, counter);

        PRINT_DIFF_FIELD_NAME(email,friendly_email,counter);
        PRINT_SAME_FIELD_NAME(site, counter);

        PRINT_SAME_FIELD_NAME(alternative_coreId, counter);

        PRINT_SAME_FIELD_NAME(extra_info_1, counter);
        PRINT_SAME_FIELD_NAME(extra_info_2, counter);
        PRINT_SAME_FIELD_NAME(extra_info_3, counter);
        PRINT_SAME_FIELD_NAME(extra_info_4, counter);
        PRINT_SAME_FIELD_NAME(extra_info_5, counter);
        PRINT_SAME_FIELD_NAME(extra_info_6, counter);
        PRINT_SAME_FIELD_NAME(extra_info_7, counter);
        PRINT_SAME_FIELD_NAME(extra_info_8, counter);
        PRINT_SAME_FIELD_NAME(extra_info_9, counter);
        fprintf(stdout,"\n");
    }
}


#if 0  //GLOBAL
  int main ()
  {
      const char *csv = "/sync/admin/etc/wbi_map.csv";
      const char *out = "carlos_wbi_map.csv";
      FILE *in  = fopen(csv, "r");
      FILE *f = fopen(out, "w");
      char fsl_coreID[16], nxp_coreID[16];
      LDAP_RETURN_DATA * ret = 0;
      char *pt = 0;
      int counter = 0;
      ldapfsl_setCaCertFileName("cacerts/cert7.db");
      ldapfsl_setNXPwbiidLdapConfig();
      if (in != NULL)
      {
          while ( fscanf(in, "%s", fsl_coreID) == 1)
          {
              pt = strchr(fsl_coreID, ',');
              strcpy(nxp_coreID, pt+1);
              *pt = 0;
              ret = ldapfsl_lookupByCoreId(nxp_coreID);
              if (ret && ret->result == LDAP_SUCCESS)
              {
                  fprintf(f, "%s,%s,%s\n", fsl_coreID, nxp_coreID, ret->info[0]->friendly_email);
                  fflush(f);
              }
              ldapfsl_free_return_data(ret);
              if ((++counter % 20) == 0)
              {
                  printf("done: %d\n", counter);
              }
          }
      }
      fclose(in);
      fclose(f);
      return 0;
  }

#endif

#if  STANDALONE
void help()
{
    printf("syntax:\n");
    printf("        [ [-e] | [-i] | [-f] | [-N] | [-E] ] -> (default:-f)  where:\n");
    printf("                 -e -> xFSL Extranet\n");
    printf("                 -i -> xFSL Intranet (old one)\n");
    printf("                 -f -> NXP with 'xFSL coreid' or 'NXP WBI id'\n");
    printf("                 -N -> NXP with WBI id\n");
    printf("                 -E -> NXP global extranet\n");
    printf("        [ [-d] -c coreID]      -> get info\n");
    printf("        [ [-d] -n name]        -> get info\n");
    printf("        [ [-d] -m mail]        -> get info\n");
    printf("        [ [-d] -a coreid]      -> authenticate\n");
    printf(" -d debug mode\n");
}


void printBeautyResults(LDAP_RETURN_DATA * ret)
{
    /* strlen retuns size_t, so the cast to int is necessary */
#define PRINT_BEAUTY(name,  counter, field)  \
    fprintf(stdout, "%s: %*c %s\n", name, (int)(12 - strlen(name)), ' ', ret->info[counter]->field)


#define PRINT_BEAUTY_OR_CONTENT(name,  counter, field1, field2)  \
    if (ret->info[counter]->field1[0]) { PRINT_BEAUTY(name, counter, field1); } \
    else { PRINT_BEAUTY(name, counter, field2); }

    int counter = 0;
    for  (; counter < ret->entries; counter++)
    {
        PRINT_BEAUTY("User id",     counter, coreId);
        PRINT_BEAUTY("fsl Coreid",  counter, alternative_coreId);
        PRINT_BEAUTY("User name",   counter, name);
        PRINT_BEAUTY("Email",       counter, friendly_email);
        PRINT_BEAUTY("Location",    counter, site);
        PRINT_BEAUTY("Phone",       counter, extra_info_4);

        PRINT_BEAUTY("Department", counter, extra_info_5);
        fprintf(stdout,"\n");
    }
}


void printCurrentConfig()
{
    printf (" --> using host=%s core_id_alternative=%s\n", ldapConfig->host, ldapConfig->result_attributes.core_id_alternative);
}


int main (int argc, char *argv[])
{
    int arg = 0;
    int return_code = 1;
#if defined(USING_MOZILLA_LDAP)
    ldapfsl_setCaCertFileName("cacerts/cert7.db");
#endif
    if (argc  != 3 && argc != 4 && argc != 5)
    {
        help();
        return 1;
    }
    LDAP_RETURN_DATA * ret = 0;
    for (arg = 1; arg < argc; ++arg)
    {
        if (!strcmp(argv[arg], "-f"))
        {
           // ldapfsl_setNXPcoreidLdapConfig();
            ldapfsl_setServerID(SERVER_NXP_Coreid_ID);
        }
        else
        if (!strcmp(argv[arg], "-N"))
        {
            //ldapfsl_setNXPwbiidLdapConfig();
            ldapfsl_setServerID(SERVER_NXP_Wbiid_ID);
        }
        else
        if (!strcmp(argv[arg], "-e"))
        {
           //ldapfsl_setFSLextranetLdapConfig();
           ldapfsl_setServerID(SERVER_FSL_Extranet_ID);
        }
        else
        if (!strcmp(argv[arg], "-i"))
        {
           //ldapfsl_setFSLintranetLdapConfig();
           ldapfsl_setServerID(SERVER_FSL_Intranet_ID);
        }
        else
        if (!strcmp(argv[arg], "-E"))
        {
          //ldapfsl_setFSLintranetLdapConfig();
          ldapfsl_setServerID(SERVER_NXP_Exranet_ID);
        }
        else
        if (!strcmp(argv[arg], "-d"))
        {
            using_debug_mode = 1;
        }
        else
        if (!strcmp(argv[arg], "-c"))
        {
            printCurrentConfig();
            ret =  ldapfsl_lookupByCoreId(argv[arg+1]);
            break;
        }
        else
        if (!strcmp(argv[arg], "-m"))
        {
            printCurrentConfig();
            ret =  ldapfsl_lookupByMail(argv[arg+1]);
            break;
        }
        else
        if (!strcmp(argv[arg], "-n"))
        {
            printCurrentConfig();
            ret =  ldapfsl_lookupByName(argv[arg+1]);
            break;
        }
        else
        if (!strcmp(argv[arg], "-a"))
        {
            char password [32];
            printf("\nenter your password: ");
            scanf("%s", password);
            getchar();
            printCurrentConfig();
            ret =  ldapfsl_authenticateCoreId(argv[arg+1], password);
            break;
        }
        else
        {
            printf("error option invalid\n:") ;
            help();
            return 1;
        }
    }
    if (ret && ret->result == LDAP_SUCCESS)
    {
        return_code = 0;  // OK
#if !defined(BEAUTY_OUTPUT_ONLY)
        printLdapHardResults(ret, stdout);
#endif
        printBeautyResults(ret);
        if (ret->entries == 1)
        {
            LDAP_RETURN_DATA * ret_manager = ldapfsl_getManagerOf(ret->info[0]);
            if (ret_manager && ret_manager->result == LDAP_SUCCESS)
            {
                printf("**** MANAGER ***\n");
                printBeautyResults(ret_manager);
                ldapfsl_free_return_data(ret_manager);
            }
        }
    }
    else
    {
        printf("Failed with code = %d %s\n", ret->result, ret->errorMessage);
        if (IS_LDAP_CONNECTION_ERROR(ret))
        {
             printf("Could not connect to the %s:%d \n", ldapConfig->host, ldapConfig->ssl_port);
        }
    }
    ldapfsl_free_return_data(ret);
    return return_code;
}

#endif
/*es.files.fileuse*/
/*is.files.fileuse*/
/*ts.files.fileuse*/
