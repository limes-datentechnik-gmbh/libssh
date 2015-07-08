/*
 * misc.c - useful client functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
 * Copyright (c) 2008-2009 by Andreas Schneider <asn@cryptomilk.org>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#ifndef _WIN32
/* This is needed for a standard getpwuid_r on opensolaris */
#define _POSIX_PTHREAD_SEMANTICS
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */

#endif /* _WIN32 */

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <time.h>

#ifdef _WIN32

#ifndef _WIN32_IE
# define _WIN32_IE 0x0501 // SHGetSpecialFolderPath
#endif

#include <winsock2.h> // Must be the first to include
#include <ws2tcpip.h>
#include <shlobj.h>
#include <direct.h>

#if _MSC_VER >= 1400
# include <io.h>
#endif /* _MSC_VER */

#endif /* _WIN32 */

#include "libssh/priv.h"
#include "libssh/misc.h"
#include "libssh/session.h"

#ifdef HAVE_LIBGCRYPT
#define GCRYPT_STRING "/gnutls"
#else
#define GCRYPT_STRING ""
#endif

#ifdef HAVE_LIBCRYPTO
#define CRYPTO_STRING "/openssl"
#else
#define CRYPTO_STRING ""
#endif

#ifdef WITH_ZLIB
#define ZLIB_STRING "/zlib"
#else
#define ZLIB_STRING ""
#endif

/**
 * @defgroup libssh_misc The SSH helper functions.
 * @ingroup libssh
 *
 * Different helper functions used in the SSH Library.
 *
 * @{
 */

#ifdef _WIN32
char *ssh_get_user_home_dir(void) {
  char tmp[MAX_PATH] = {0};
  char *szPath = NULL;

  if (SHGetSpecialFolderPathA(NULL, tmp, CSIDL_PROFILE, TRUE)) {
    szPath = malloc(strlen(tmp) + 1);
    if (szPath == NULL) {
      return NULL;
    }

    strcpy(szPath, tmp);
    return szPath;
  }

  return NULL;
}

/* we have read access on file */
int ssh_file_readaccess_ok(const char *file) {
  if (_access(file, 4) < 0) {
    return 0;
  }

  return 1;
}

#define SSH_USEC_IN_SEC         1000000LL
#define SSH_SECONDS_SINCE_1601  11644473600LL

int gettimeofday(struct timeval *__p, void *__t) {
  union {
    unsigned long long ns100; /* time since 1 Jan 1601 in 100ns units */
    FILETIME ft;
  } now;

  GetSystemTimeAsFileTime (&now.ft);
  __p->tv_usec = (long) ((now.ns100 / 10LL) % SSH_USEC_IN_SEC);
  __p->tv_sec  = (long)(((now.ns100 / 10LL ) / SSH_USEC_IN_SEC) - SSH_SECONDS_SINCE_1601);

  return (0);
}

char *ssh_get_local_username(void) {
    DWORD size = 0;
    char *user;

    /* get the size */
    GetUserName(NULL, &size);

    user = (char *) malloc(size);
    if (user == NULL) {
        return NULL;
    }

    if (GetUserName(user, &size)) {
        return user;
    }

    return NULL;
}

int ssh_is_ipaddr_v4(const char *str) {
    struct sockaddr_storage ss;
    int sslen = sizeof(ss);
    int rc = SOCKET_ERROR;

    /* WSAStringToAddressA thinks that 0.0.0 is a valid IP */
    if (strlen(str) < 7) {
        return 0;
    }

    rc = WSAStringToAddressA((LPSTR) str,
                             AF_INET,
                             NULL,
                             (struct sockaddr*)&ss,
                             &sslen);
    if (rc == 0) {
        return 1;
    }

    return 0;
}

int ssh_is_ipaddr(const char *str) {
    int rc = SOCKET_ERROR;

    if (strchr(str, ':')) {
        struct sockaddr_storage ss;
        int sslen = sizeof(ss);

        /* TODO link-local (IP:v6:addr%ifname). */
        rc = WSAStringToAddressA((LPSTR) str,
                                 AF_INET6,
                                 NULL,
                                 (struct sockaddr*)&ss,
                                 &sslen);
        if (rc == 0) {
            return 1;
        }
    }

    return ssh_is_ipaddr_v4(str);
}
#else /* _WIN32 */

#ifndef NSS_BUFLEN_PASSWD
#define NSS_BUFLEN_PASSWD 4096
#endif /* NSS_BUFLEN_PASSWD */

char *ssh_get_user_home_dir(void) {
  char *szPath = NULL;
  struct passwd pwd;
  struct passwd *pwdbuf;
  char buf[NSS_BUFLEN_PASSWD];
  int rc;

  rc = getpwuid_r(getuid(), &pwd, buf, NSS_BUFLEN_PASSWD, &pwdbuf);
  if (rc != 0) {
      szPath = getenv("HOME");
      if (szPath == NULL) {
          return NULL;
      }
      memset(buf, 0, sizeof(buf));
      snprintf(buf, sizeof(buf), "%s", szPath);

      return strdup(buf);
  }

  szPath = strdup(pwd.pw_dir);

  return szPath;
}

/* we have read access on file */
int ssh_file_readaccess_ok(const char *file) {
  if (access(file, R_OK) < 0) {
    return 0;
  }

  return 1;
}

char *ssh_get_local_username(void) {
    struct passwd pwd;
    struct passwd *pwdbuf;
    char buf[NSS_BUFLEN_PASSWD];
    char *name;
    int rc;

    rc = getpwuid_r(getuid(), &pwd, buf, NSS_BUFLEN_PASSWD, &pwdbuf);
    if (rc != 0) {
        return NULL;
    }

    name = strdup(pwd.pw_name);

    if (name == NULL) {
        return NULL;
    }

    return name;
}

int ssh_is_ipaddr_v4(const char *str) {
    int rc = -1;
    struct in_addr dest;

    rc = inet_pton(AF_INET, str, &dest);
    if (rc > 0) {
        return 1;
    }

    return 0;
}

int ssh_is_ipaddr(const char *str) {
    int rc = -1;

    if (strchr(str, ':')) {
        struct in6_addr dest6;

        /* TODO link-local (IP:v6:addr%ifname). */
        rc = inet_pton(AF_INET6, str, &dest6);
        if (rc > 0) {
            return 1;
        }
    }

    return ssh_is_ipaddr_v4(str);
}

#endif /* _WIN32 */

#ifdef __EBCDIC__
/*-
 * License for strtol()
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


static inline int isupper_ascii(char c) {
    return (c >= 0x41 && c <= 0x5A); /* 'A' - 'Z' */
}

static inline int isalpha_ascii(char c) {
    return ((c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A)); /* 'A' - 'Z' || 'a' - 'z' */
}

static inline int isspace_ascii(char c) {
    return (c == 0x20 || c == 0x09 || c == 0x0A); /* ' ', '\t', '\n' */
}

static inline int isdigit_ascii(char c) {
    return (c >= 0x30 && c <= 0x39); /* '0' - '9' */
}

/*
 * Convert an ASCII string to a long integer.
 *
 * Treats the string as ASCII, even on EBCDIC systems.
 */
long strtol_ascii(const char *nptr, char **endptr, int base) {
    register const char *s = nptr;
    register unsigned long acc;
    register int c;
    register unsigned long cutoff;
    register int neg = 0, any, cutlim;

    /*
     * Skip white space and pick up leading +/- sign if any.
     * If base is 0, allow 0x for hex and 0 for octal, else
     * assume decimal; if base is already 16, allow 0x.
     */
    do {
        c = *s++;
    } while (isspace_ascii(c));
    if (c == 0x2D) { /* '-' */
        neg = 1;
        c = *s++;
    } else if (c == 0x2B) /* '+' */
        c = *s++;
    if ((base == 0 || base == 16) &&
        c == 0x30 && (*s == 0x78 || *s == 0x58)) { /* '0', 'x', 'X' */
        c = s[1];
        s += 2;
        base = 16;
    } else if ((base == 0 || base == 2) &&
        c == 0x30 && (*s == 0x62 || *s == 0x42)) { /* '0', 'b', 'B' */
        c = s[1];
        s += 2;
        base = 2;
    }
    if (base == 0)
        base = c == 0x30 ? 8 : 10; /* '0' */

    /*
     * Compute the cutoff value between legal numbers and illegal
     * numbers.  That is the largest legal value, divided by the
     * base.  An input number that is greater than this value, if
     * followed by a legal input character, is too big.  One that
     * is equal to this value may be valid or not; the limit
     * between valid and invalid numbers is then based on the last
     * digit.  For instance, if the range for longs is
     * [-2147483648..2147483647] and the input base is 10,
     * cutoff will be set to 214748364 and cutlim to either
     * 7 (neg==0) or 8 (neg==1), meaning that if we have accumulated
     * a value > 214748364, or equal but the next digit is > 7 (or 8),
     * the number is too big, and we will return a range error.
     *
     * Set any if any `digits' consumed; make it negative to indicate
     * overflow.
     */
    cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
    cutlim = cutoff % (unsigned long)base;
    cutoff /= (unsigned long)base;
    for (acc = 0, any = 0;; c = *s++) {
        if (isdigit_ascii(c))
            c -= 0x30; /* '0' */
        else if (isalpha_ascii(c))
            c -= isupper_ascii(c) ? 0x41 - 10 : 0x61 - 10; /* 'A', 'a' */
        else
            break;
        if (c >= base)
            break;
        if (any < 0 || acc > cutoff || acc == cutoff && c > cutlim)
            any = -1;
        else {
            any = 1;
            acc *= base;
            acc += c;
        }
    }
    if (any < 0) {
        acc = neg ? LONG_MIN : LONG_MAX;
    // errno = ERANGE;
    } else if (neg)
        acc = -acc;
    if (endptr != 0)
        *endptr = (char *)(any ? s - 1 : nptr);
    return (acc);
}

/*
 * Convert a string to an unsigned long integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
unsigned long strtoul(const char *nptr, char **endptr, int base) {
    register const char *s = nptr;
    register unsigned long acc;
    register int c;
    register unsigned long cutoff;
    register int neg = 0, any, cutlim;

    /*
     * See strtol for comments as to the logic used.
     */
    do {
        c = *s++;
    } while (isspace_ascii(c));
    if (c == 0x2D) { /* '-' */
        neg = 1;
        c = *s++;
    } else if (c == 0x2B) /* '+' */
        c = *s++;
    if ((base == 0 || base == 16) &&
        c == 0x30 && (*s == 0x78 || *s == 0x58)) { /* '0', 'x', 'X' */
        c = s[1];
        s += 2;
        base = 16;
    } else if ((base == 0 || base == 2) &&
        c == 0x30 && (*s == 0x62 || *s == 0x42)) { /* '0', 'b', 'B' */
        c = s[1];
        s += 2;
        base = 2;
    }
    if (base == 0)
        base = c == 0x30 ? 8 : 10; /* '0' */
    cutoff = (unsigned long)ULONG_MAX / (unsigned long)base;
    cutlim = (unsigned long)ULONG_MAX % (unsigned long)base;
    for (acc = 0, any = 0;; c = *s++) {
        if (isdigit_ascii(c))
            c -= 0x30; /* '0' */
        else if (isalpha_ascii(c))
            c -= isupper_ascii(c) ? 0x41 - 10 : 0x61 - 10; /* 'A', 'a' */
        else
            break;
        if (c >= base)
            break;
        if (any < 0 || acc > cutoff || acc == cutoff && c > cutlim)
            any = -1;
        else {
            any = 1;
            acc *= base;
            acc += c;
        }
    }
    if (any < 0) {
        acc = ULONG_MAX;
    // errno = ERANGE;
    } else if (neg)
        acc = -acc;
    if (endptr != 0)
        *endptr = (char *)(any ? s - 1 : nptr);
    return (acc);
}
#endif /* __EBCDIC__ */

#ifndef HAVE_NTOHLL
uint64_t ntohll(uint64_t a) {
#ifdef WORDS_BIGENDIAN
  return a;
#else /* WORDS_BIGENDIAN */
  return (((uint64_t)(a) << 56) | \
         (((uint64_t)(a) << 40) & 0xff000000000000ULL) | \
         (((uint64_t)(a) << 24) & 0xff0000000000ULL) | \
         (((uint64_t)(a) << 8)  & 0xff00000000ULL) | \
         (((uint64_t)(a) >> 8)  & 0xff000000ULL) | \
         (((uint64_t)(a) >> 24) & 0xff0000ULL) | \
         (((uint64_t)(a) >> 40) & 0xff00ULL) | \
         ((uint64_t)(a)  >> 56));
#endif /* WORDS_BIGENDIAN */
}
#endif /* HAVE_NTOHLL */

char *ssh_lowercase(const char* str) {
  char *new, *p;

  if (str == NULL) {
    return NULL;
  }

  new = strdup(str);
  if (new == NULL) {
    return NULL;
  }

  for (p = new; *p; p++) {
    *p = tolower(*p);
  }

  return new;
}

char *ssh_hostport(const char *host, int port){
    char *dest;
    size_t len;
    if(host==NULL)
        return NULL;
    /* 3 for []:, 5 for 65536 and 1 for nul */
    len=strlen(host) + 3 + 5 + 1;
    dest=malloc(len);
    if(dest==NULL)
        return NULL;
    snprintf(dest,len,"[%s]:%d",host,port);
    return dest;
}

/**
 * @brief Check if libssh is the required version or get the version
 * string.
 *
 * @param[in]  req_version The version required.
 *
 * @return              If the version of libssh is newer than the version
 *                      required it will return a version string.
 *                      NULL if the version is older.
 *
 * Example:
 *
 * @code
 *  if (ssh_version(SSH_VERSION_INT(0,2,1)) == NULL) {
 *    fprintf(stderr, "libssh version is too old!\n");
 *    exit(1);
 *  }
 *
 *  if (debug) {
 *    printf("libssh %s\n", ssh_version(0));
 *  }
 * @endcode
 */
const char *ssh_version(int req_version) {
  if (req_version <= LIBSSH_VERSION_INT) {
    return SSH_STRINGIFY(LIBSSH_VERSION) GCRYPT_STRING CRYPTO_STRING
      ZLIB_STRING;
  }

  return NULL;
}

struct ssh_list *ssh_list_new(void) {
  struct ssh_list *ret=malloc(sizeof(struct ssh_list));
  if(!ret)
    return NULL;
  ret->root=ret->end=NULL;
  return ret;
}

void ssh_list_free(struct ssh_list *list){
  struct ssh_iterator *ptr,*next;
  if(!list)
    return;
  ptr=list->root;
  while(ptr){
    next=ptr->next;
    SAFE_FREE(ptr);
    ptr=next;
  }
  SAFE_FREE(list);
}

struct ssh_iterator *ssh_list_get_iterator(const struct ssh_list *list){
  if(!list)
    return NULL;
  return list->root;
}

struct ssh_iterator *ssh_list_find(const struct ssh_list *list, void *value){
  struct ssh_iterator *it;
  for(it = ssh_list_get_iterator(list); it != NULL ;it=it->next)
    if(it->data==value)
      return it;
  return NULL;
}

static struct ssh_iterator *ssh_iterator_new(const void *data){
  struct ssh_iterator *iterator=malloc(sizeof(struct ssh_iterator));
  if(!iterator)
    return NULL;
  iterator->next=NULL;
  iterator->data=data;
  return iterator;
}

int ssh_list_append(struct ssh_list *list,const void *data){
  struct ssh_iterator *iterator=ssh_iterator_new(data);
  if(!iterator)
    return SSH_ERROR;
  if(!list->end){
    /* list is empty */
    list->root=list->end=iterator;
  } else {
    /* put it on end of list */
    list->end->next=iterator;
    list->end=iterator;
  }
  return SSH_OK;
}

int ssh_list_prepend(struct ssh_list *list, const void *data){
  struct ssh_iterator *it = ssh_iterator_new(data);

  if (it == NULL) {
    return SSH_ERROR;
  }

  if (list->end == NULL) {
    /* list is empty */
    list->root = list->end = it;
  } else {
    /* set as new root */
    it->next = list->root;
    list->root = it;
  }

  return SSH_OK;
}

void ssh_list_remove(struct ssh_list *list, struct ssh_iterator *iterator){
  struct ssh_iterator *ptr,*prev;
  prev=NULL;
  ptr=list->root;
  while(ptr && ptr != iterator){
    prev=ptr;
    ptr=ptr->next;
  }
  if(!ptr){
    /* we did not find the element */
    return;
  }
  /* unlink it */
  if(prev)
    prev->next=ptr->next;
  /* if iterator was the head */
  if(list->root == iterator)
    list->root=iterator->next;
  /* if iterator was the tail */
  if(list->end == iterator)
    list->end = prev;
  SAFE_FREE(iterator);
}

/**
 * @internal
 *
 * @brief Removes the top element of the list and returns the data value
 * attached to it.
 *
 * @param[in[  list     The ssh_list to remove the element.
 *
 * @returns             A pointer to the element being stored in head, or NULL
 *                      if the list is empty.
 */
const void *_ssh_list_pop_head(struct ssh_list *list){
  struct ssh_iterator *iterator=list->root;
  const void *data;
  if(!list->root)
    return NULL;
  data=iterator->data;
  list->root=iterator->next;
  if(list->end==iterator)
    list->end=NULL;
  SAFE_FREE(iterator);
  return data;
}

/**
 * @brief Parse directory component.
 *
 * dirname breaks a null-terminated pathname string into a directory component.
 * In the usual case, ssh_dirname() returns the string up to, but not including,
 * the final '/'. Trailing '/' characters are  not  counted as part of the
 * pathname. The caller must free the memory.
 *
 * @param[in]  path     The path to parse.
 *
 * @return              The dirname of path or NULL if we can't allocate memory.
 *                      If path does not contain a slash, c_dirname() returns
 *                      the string ".".  If path is the string "/", it returns
 *                      the string "/". If path is NULL or an empty string,
 *                      "." is returned.
 */
char *ssh_dirname (const char *path) {
  char *new = NULL;
  size_t len;

  if (path == NULL || *path == '\0') {
    return strdup(".");
  }

  len = strlen(path);

  /* Remove trailing slashes */
  while(len > 0 && path[len - 1] == '/') --len;

  /* We have only slashes */
  if (len == 0) {
    return strdup("/");
  }

  /* goto next slash */
  while(len > 0 && path[len - 1] != '/') --len;

  if (len == 0) {
    return strdup(".");
  } else if (len == 1) {
    return strdup("/");
  }

  /* Remove slashes again */
  while(len > 0 && path[len - 1] == '/') --len;

  new = malloc(len + 1);
  if (new == NULL) {
    return NULL;
  }

  strncpy(new, path, len);
  new[len] = '\0';

  return new;
}

/**
 * @brief basename - parse filename component.
 *
 * basename breaks a null-terminated pathname string into a filename component.
 * ssh_basename() returns the component following the final '/'.  Trailing '/'
 * characters are not counted as part of the pathname.
 *
 * @param[in]  path     The path to parse.
 *
 * @return              The filename of path or NULL if we can't allocate
 *                      memory. If path is a the string "/", basename returns
 *                      the string "/". If path is NULL or an empty string,
 *                      "." is returned.
 */
char *ssh_basename (const char *path) {
  char *new = NULL;
  const char *s;
  size_t len;

  if (path == NULL || *path == '\0') {
    return strdup(".");
  }

  len = strlen(path);
  /* Remove trailing slashes */
  while(len > 0 && path[len - 1] == '/') --len;

  /* We have only slashes */
  if (len == 0) {
    return strdup("/");
  }

  while(len > 0 && path[len - 1] != '/') --len;

  if (len > 0) {
    s = path + len;
    len = strlen(s);

    while(len > 0 && s[len - 1] == '/') --len;
  } else {
    return strdup(path);
  }

  new = malloc(len + 1);
  if (new == NULL) {
    return NULL;
  }

  strncpy(new, s, len);
  new[len] = '\0';

  return new;
}

/**
 * @brief Attempts to create a directory with the given pathname.
 *
 * This is the portable version of mkdir, mode is ignored on Windows systems.
 *
 * @param[in]  pathname The path name to create the directory.
 *
 * @param[in]  mode     The permissions to use.
 *
 * @return              0 on success, < 0 on error with errno set.
 */
int ssh_mkdir(const char *pathname, mode_t mode) {
  int r;

#ifdef _WIN32
  r = _mkdir(pathname);
#else
  r = mkdir(pathname, mode);
#endif

  return r;
}

/**
 * @brief Expand a directory starting with a tilde '~'
 *
 * @param[in]  d        The directory to expand.
 *
 * @return              The expanded directory, NULL on error.
 */
char *ssh_path_expand_tilde(const char *d) {
    char *h = NULL, *r;
    const char *p;
    size_t ld;
    size_t lh = 0;

    if (d[0] != '~') {
        return strdup(d);
    }
    d++;

    /* handle ~user/path */
    p = strchr(d, '/');
    if (p != NULL && p > d) {
#ifdef _WIN32
        return strdup(d);
#else
        struct passwd *pw;
        size_t s = p - d;
        char u[128];

        if (s >= sizeof(u)) {
            return NULL;
        }
        memcpy(u, d, s);
        u[s] = '\0';
        pw = getpwnam(u);
        if (pw == NULL) {
            return NULL;
        }
        ld = strlen(p);
        h = strdup(pw->pw_dir);
#endif
    } else {
        ld = strlen(d);
        p = (char *) d;
        h = ssh_get_user_home_dir();
    }
    if (h == NULL) {
        return NULL;
    }
    lh = strlen(h);

    r = malloc(ld + lh + 1);
    if (r == NULL) {
        SAFE_FREE(h);
        return NULL;
    }

    if (lh > 0) {
        memcpy(r, h, lh);
    }
    SAFE_FREE(h);
    memcpy(r + lh, p, ld + 1);

    return r;
}

char *ssh_path_expand_escape(ssh_session session, const char *s) {
    char host[NI_MAXHOST];
    char buf[MAX_BUF_SIZE];
    char *r, *x = NULL;
    const char *p;
    size_t i, l;

    r = ssh_path_expand_tilde(s);
    if (r == NULL) {
        ssh_set_error_oom(session);
        return NULL;
    }

    if (strlen(r) > MAX_BUF_SIZE) {
        ssh_set_error(session, SSH_FATAL, "string to expand too long");
        free(r);
        return NULL;
    }

    p = r;
    buf[0] = '\0';

    for (i = 0; *p != '\0'; p++) {
        if (*p != '%') {
            buf[i] = *p;
            i++;
            if (i >= MAX_BUF_SIZE) {
                free(r);
                return NULL;
            }
            buf[i] = '\0';
            continue;
        }

        p++;
        if (*p == '\0') {
            break;
        }

        switch (*p) {
            case 'd':
                x = strdup(session->opts.sshdir);
                break;
            case 'u':
                x = ssh_get_local_username();
                break;
            case 'l':
                if (gethostname(host, sizeof(host) == 0)) {
                    x = strdup(host);
                }
                break;
            case 'h':
                x = strdup(session->opts.host);
                break;
            case 'r':
                x = strdup(session->opts.username);
                break;
            case 'p':
                if (session->opts.port < 65536) {
                    char tmp[6];

                    snprintf(tmp, sizeof(tmp), "%u", session->opts.port);
                    x = strdup(tmp);
                }
                break;
            default:
                ssh_set_error(session, SSH_FATAL,
                        "Wrong escape sequence detected");
                free(r);
                return NULL;
        }

        if (x == NULL) {
            ssh_set_error_oom(session);
            free(r);
            return NULL;
        }

        i += strlen(x);
        if (i >= MAX_BUF_SIZE) {
            ssh_set_error(session, SSH_FATAL,
                    "String too long");
            free(x);
            free(r);
            return NULL;
        }
        l = strlen(buf);
        strncpy(buf + l, x, sizeof(buf) - l - 1);
        buf[i] = '\0';
        SAFE_FREE(x);
    }

    free(r);
    return strdup(buf);
#undef MAX_BUF_SIZE
}

/**
 * @internal
 *
 * @brief Analyze the SSH banner to find out if we have a SSHv1 or SSHv2
 * server.
 *
 * @param  session      The session to analyze the banner from.
 * @param  server       0 means we are a client, 1 a server.
 * @param  ssh1         The variable which is set if it is a SSHv1 server.
 * @param  ssh2         The variable which is set if it is a SSHv2 server.
 *
 * @return 0 on success, < 0 on error.
 *
 * @see ssh_get_banner()
 */
int ssh_analyze_banner(ssh_session session, int server, int *ssh1, int *ssh2) {
  const char *banner;
  const char *openssh;

  if (server) {
      banner = session->clientbanner;
  } else {
      banner = session->serverbanner;
  }

  if (banner == NULL) {
      ssh_set_error(session, SSH_FATAL, "Invalid banner");
      return -1;
  }

  /*
   * Typical banners e.g. are:
   *
   * SSH-1.5-openSSH_5.4
   * SSH-1.99-openSSH_3.0
   *
   * SSH-2.0-something
   * 012345678901234567890
   */
  if (strlen(banner) < 6 ||
#ifdef __EBCDIC__
#pragma convert("ISO8859-1")
#endif
      strncmp(banner, "SSH-", 4) != 0) {
#ifdef __EBCDIC__
#pragma convert(pop)
#endif
    ssh_set_error(session, SSH_FATAL, "Protocol mismatch: %s", ssh_string_for_log(banner));
    return -1;
  }

  SSH_LOG(SSH_LOG_RARE, "Analyzing banner: %s", ssh_string_for_log(banner));

  switch(banner[4]) {
#ifdef __EBCDIC__
#pragma convert("ISO8859-1")
#endif
    case '1':
      *ssh1 = 1;
      if (strlen(banner) > 6) {
          if (banner[6] == '9') {
            *ssh2 = 1;
          } else {
            *ssh2 = 0;
          }
      }
      break;
    case '2':
      *ssh1 = 0;
      *ssh2 = 1;
      break;
#ifdef __EBCDIC__
#pragma convert(pop)
#endif
    default:
      ssh_set_error(session, SSH_FATAL, "Protocol mismatch: %s", banner);
      return -1;
  }

#ifdef __EBCDIC__
#pragma convert("ISO8859-1")
#endif
  openssh = strstr(banner, "OpenSSH");
#ifdef __EBCDIC__
#pragma convert(pop)
#endif
  if (openssh != NULL) {
      int major, minor;

      /*
       * The banner is typical:
       * OpenSSH_5.4
       * 012345678901234567890
       */
      if (strlen(openssh) > 9) {
#ifdef __EBCDIC__
          major = strtol_ascii(openssh + 8, (char **) NULL, 10);
          minor = strtol_ascii(openssh + 10, (char **) NULL, 10);
#else
          major = strtol(openssh + 8, (char **) NULL, 10);
          minor = strtol(openssh + 10, (char **) NULL, 10);
#endif
          session->openssh = SSH_VERSION_INT(major, minor, 0);
          SSH_LOG(SSH_LOG_RARE,
                  "We are talking to an OpenSSH client version: %d.%d (%x)",
                  major, minor, session->openssh);
      }
  }


  return 0;
}

/* try the Monotonic clock if possible for perfs reasons */
#ifdef _POSIX_MONOTONIC_CLOCK
#define CLOCK CLOCK_MONOTONIC
#else
#define CLOCK CLOCK_REALTIME
#endif

/**
 * @internal
 * @brief initializes a timestamp to the current time
 * @param[out] ts pointer to an allocated ssh_timestamp structure
 */
void ssh_timestamp_init(struct ssh_timestamp *ts){
#ifdef HAVE_CLOCK_GETTIME
  struct timespec tp;
  clock_gettime(CLOCK, &tp);
  ts->useconds = tp.tv_nsec / 1000;
#else
  struct timeval tp;
  gettimeofday(&tp, NULL);
  ts->useconds = tp.tv_usec;
#endif
  ts->seconds = tp.tv_sec;
}

#undef CLOCK

/**
 * @internal
 * @brief gets the time difference between two timestamps in ms
 * @param[in] old older value
 * @param[in] new newer value
 * @returns difference in milliseconds
 */

static int ssh_timestamp_difference(struct ssh_timestamp *old,
    struct ssh_timestamp *new){
  long seconds, usecs, msecs;
  seconds = new->seconds - old->seconds;
  usecs = new->useconds - old->useconds;
  if (usecs < 0){
    seconds--;
    usecs += 1000000;
  }
  msecs = seconds * 1000 + usecs/1000;
  return msecs;
}

/**
 * @internal
 * @brief turn seconds and microseconds pair (as provided by user-set options)
 * into millisecond value
 * @param[in] sec number of seconds
 * @param[in] usec number of microseconds
 * @returns milliseconds, or 10000 if user supplied values are equal to zero
 */
int ssh_make_milliseconds(long sec, long usec) {
	int res = usec ? (usec / 1000) : 0;
	res += (sec * 1000);
	if (res == 0) {
		res = 10 * 1000; /* use a reasonable default value in case
				* SSH_OPTIONS_TIMEOUT is not set in options. */
	}
	return res;
}

/**
 * @internal
 * @brief Checks if a timeout is elapsed, in function of a previous
 * timestamp and an assigned timeout
 * @param[in] ts pointer to an existing timestamp
 * @param[in] timeout timeout in milliseconds. Negative values mean infinite
 *                   timeout
 * @returns 1 if timeout is elapsed
 *          0 otherwise
 */
int ssh_timeout_elapsed(struct ssh_timestamp *ts, int timeout) {
    struct ssh_timestamp now;

    switch(timeout) {
        case -2: /*
                  * -2 means user-defined timeout as available in
                  * session->timeout, session->timeout_usec.
                  */
            fprintf(stderr, "ssh_timeout_elapsed called with -2. this needs to "
                            "be fixed. please set a breakpoint on %s:%d and "
                            "fix the caller\n", __FILE__, __LINE__);
        case -1: /* -1 means infinite timeout */
            return 0;
        case 0: /* 0 means no timeout */
            return 1;
        default:
            break;
    }

    ssh_timestamp_init(&now);

    return (ssh_timestamp_difference(ts,&now) >= timeout);
}

/**
 * @brief updates a timeout value so it reflects the remaining time
 * @param[in] ts pointer to an existing timestamp
 * @param[in] timeout timeout in milliseconds. Negative values mean infinite
 *             timeout
 * @returns   remaining time in milliseconds, 0 if elapsed, -1 if never.
 */
int ssh_timeout_update(struct ssh_timestamp *ts, int timeout){
  struct ssh_timestamp now;
  int ms, ret;
  if (timeout <= 0) {
      return timeout;
  }
  ssh_timestamp_init(&now);
  ms = ssh_timestamp_difference(ts,&now);
  if(ms < 0)
    ms = 0;
  ret = timeout - ms;
  return ret >= 0 ? ret: 0;
}


int ssh_match_group(const char *group, const char *object)
{
    const char *a;
    const char *z;

    z = group;
    do {
        a = strchr(z, ',');
        if (a == NULL) {
            if (strcmp(z, object) == 0) {
                return 1;
            }
            return 0;
        } else {
            if (strncmp(z, object, a - z) == 0) {
                return 1;
            }
        }
        z = a + 1;
    } while(1);

    /* not reached */
    return 0;
}

/** @} */

/* vim: set ts=4 sw=4 et cindent: */
