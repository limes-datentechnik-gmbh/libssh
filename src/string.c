/*
 * string.c - ssh string functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
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

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "libssh/priv.h"
#include "libssh/string.h"
#include "libssh/session.h"

/**
 * @defgroup libssh_string The SSH string functions
 * @ingroup libssh
 *
 * @brief String manipulations used in libssh.
 *
 * @{
 */

/**
 * @brief Create a new SSH String object.
 *
 * @param[in] size       The size of the string.
 *
 * @return               The newly allocated string, NULL on error.
 */
struct ssh_string_struct *ssh_string_new(size_t size) {
  struct ssh_string_struct *str = NULL;

  if (size > UINT_MAX - sizeof(struct ssh_string_struct)) {
      return NULL;
  }

  str = malloc(sizeof(struct ssh_string_struct) + size);
  if (str == NULL) {
    return NULL;
  }

  str->size = htonl(size);
  str->data[0] = 0;

  return str;
}

/**
 * @brief Fill a string with given data. The string should be big enough.
 *
 * @param s        An allocated string to fill with data.
 *
 * @param data     The data to fill the string with.
 *
 * @param len      Size of data.
 *
 * @return         0 on success, < 0 on error.
 */
int ssh_string_fill(struct ssh_string_struct *s, const void *data, size_t len) {
  if ((s == NULL) || (data == NULL) ||
      (len == 0) || (len > ssh_string_len(s))) {
    return -1;
  }

  memcpy(s->data, data, len);

  return 0;
}

/**
 * @brief Create a ssh string using a C string
 *
 * @param[in] what      The source 0-terminated C string.
 *
 * @return              The newly allocated string, NULL on error with errno
 *                      set.
 *
 * @note The nul byte is not copied nor counted in the ouput string.
 */
struct ssh_string_struct *ssh_string_from_char(const char *what) {
  struct ssh_string_struct *ptr;
  size_t len;

  if(what == NULL) {
      errno = EINVAL;
      return NULL;
  }

  len = strlen(what);

  ptr = ssh_string_new(len);
  if (ptr == NULL) {
    return NULL;
  }

  memcpy(ptr->data, what, len);

  return ptr;
}

/**
 * @brief Return the size of a SSH string.
 *
 * @param[in] s         The the input SSH string.
 *
 * @return The size of the content of the string, 0 on error.
 */
size_t ssh_string_len(struct ssh_string_struct *s) {
    size_t size;

    if (s == NULL) {
        return 0;
    }

    size = ntohl(s->size);
    if (size > 0 && size < UINT_MAX) {
        return size;
    }

    return 0;
}

/**
 * @brief Get the the string as a C nul-terminated string.
 *
 * This is only available as long as the SSH string exists.
 *
 * @param[in] s         The SSH string to get the C string from.
 *
 * @return              The char pointer, NULL on error.
 */
const char *ssh_string_get_char(struct ssh_string_struct *s)
{
    if (s == NULL) {
        return NULL;
    }
    s->data[ssh_string_len(s)] = '\0';

    return (const char *) s->data;
}

/**
 * @brief Convert a SSH string to a C nul-terminated string.
 *
 * @param[in] s         The SSH input string.
 *
 * @return              An allocated string pointer, NULL on error with errno
 *                      set.
 *
 * @note If the input SSH string contains zeroes, some parts of the output
 * string may not be readable with regular libc functions.
 */
char *ssh_string_to_char(struct ssh_string_struct *s) {
  size_t len;
  char *new;

  if (s == NULL) {
      return NULL;
  }

  len = ssh_string_len(s);
  if (len + 1 < len) {
    return NULL;
  }

  new = malloc(len + 1);
  if (new == NULL) {
    return NULL;
  }
  memcpy(new, s->data, len);
  new[len] = '\0';

  return new;
}

/**
 * @brief Deallocate a char string object.
 *
 * @param[in] s         The string to delete.
 */
void ssh_string_free_char(char *s) {
    SAFE_FREE(s);
}

/**
 * @brief Copy a string, return a newly allocated string. The caller has to
 *        free the string.
 *
 * @param[in] s         String to copy.
 *
 * @return              Newly allocated copy of the string, NULL on error.
 */
struct ssh_string_struct *ssh_string_copy(struct ssh_string_struct *s) {
  struct ssh_string_struct *new;
  size_t len;

  if (s == NULL) {
      return NULL;
  }

  len = ssh_string_len(s);
  if (len == 0) {
      return NULL;
  }

  new = ssh_string_new(len);
  if (new == NULL) {
    return NULL;
  }

  memcpy(new->data, s->data, len);

  return new;
}

/**
 * @brief Destroy the data in a string so it couldn't appear in a core dump.
 *
 * @param[in] s         The string to burn.
 */
void ssh_string_burn(struct ssh_string_struct *s) {
    if (s == NULL || s->size == 0) {
        return;
    }

    BURN_BUFFER(s->data, ssh_string_len(s));
}

/**
 * @brief Get the payload of the string.
 *
 * @param s             The string to get the data from.
 *
 * @return              Return the data of the string or NULL on error.
 */
void *ssh_string_data(struct ssh_string_struct *s) {
  if (s == NULL) {
    return NULL;
  }

  return s->data;
}

/**
 * @brief Deallocate a SSH string object.
 *
 * \param[in] s         The SSH string to delete.
 */
void ssh_string_free(struct ssh_string_struct *s) {
  SAFE_FREE(s);
}

#ifdef __EBCDIC__
/**
 * @brief Convert an EBCDIC string to ASCII (supports only non-diacritic characters).
 *
 * \param[in]  ebcdic   The EBCDIC string to convert.
 * \param[out] ascii    Buffer that has enough room for len ASCII characters
 * \param[in]  len      Length of the input string
 */
void ssh_string_from_ebcdic(const char* ebcdic, char* ascii, unsigned int len) {
   unsigned int i;
   for (i=0;i<len;i++) {
      switch (ebcdic[i]) {
         case 0x00 : ascii[i]=0x00; break;
         case '\n' : ascii[i]=0x0A; break;
         case '\r' : ascii[i]=0x0D; break;

         case ' '  : ascii[i]=0x20; break;
         case '\"' : ascii[i]=0x22; break;
         case '%'  : ascii[i]=0x25; break;
         case '&'  : ascii[i]=0x26; break;
         case '\'' : ascii[i]=0x27; break;
         case '('  : ascii[i]=0x28; break;
         case ')'  : ascii[i]=0x29; break;
         case '*'  : ascii[i]=0x2A; break;
         case '+'  : ascii[i]=0x2B; break;
         case ','  : ascii[i]=0x2C; break;
         case '-'  : ascii[i]=0x2D; break;
         case '.'  : ascii[i]=0x2E; break;
         case '/'  : ascii[i]=0x2F; break;

         case '0'  : ascii[i]=0x30; break;
         case '1'  : ascii[i]=0x31; break;
         case '2'  : ascii[i]=0x32; break;
         case '3'  : ascii[i]=0x33; break;
         case '4'  : ascii[i]=0x34; break;
         case '5'  : ascii[i]=0x35; break;
         case '6'  : ascii[i]=0x36; break;
         case '7'  : ascii[i]=0x37; break;
         case '8'  : ascii[i]=0x38; break;
         case '9'  : ascii[i]=0x39; break;
         case ':'  : ascii[i]=0x3A; break;
         case ';'  : ascii[i]=0x3B; break;
         case '<'  : ascii[i]=0x3C; break;
         case '='  : ascii[i]=0x3D; break;
         case '>'  : ascii[i]=0x3E; break;
         case '?'  : ascii[i]=0x3F; break;

         case 'A'  : ascii[i]=0x41; break;
         case 'B'  : ascii[i]=0x42; break;
         case 'C'  : ascii[i]=0x43; break;
         case 'D'  : ascii[i]=0x44; break;
         case 'E'  : ascii[i]=0x45; break;
         case 'F'  : ascii[i]=0x46; break;
         case 'G'  : ascii[i]=0x47; break;
         case 'H'  : ascii[i]=0x48; break;
         case 'I'  : ascii[i]=0x49; break;
         case 'J'  : ascii[i]=0x4A; break;
         case 'K'  : ascii[i]=0x4B; break;
         case 'L'  : ascii[i]=0x4C; break;
         case 'M'  : ascii[i]=0x4D; break;
         case 'N'  : ascii[i]=0x4E; break;
         case 'O'  : ascii[i]=0x4F; break;

         case 'P'  : ascii[i]=0x50; break;
         case 'Q'  : ascii[i]=0x51; break;
         case 'R'  : ascii[i]=0x52; break;
         case 'S'  : ascii[i]=0x53; break;
         case 'T'  : ascii[i]=0x54; break;
         case 'U'  : ascii[i]=0x55; break;
         case 'V'  : ascii[i]=0x56; break;
         case 'W'  : ascii[i]=0x57; break;
         case 'X'  : ascii[i]=0x58; break;
         case 'Y'  : ascii[i]=0x59; break;
         case 'Z'  : ascii[i]=0x5A; break;
         case '_'  : ascii[i]=0x5F; break;

         case 'a'  : ascii[i]=0x61; break;
         case 'b'  : ascii[i]=0x62; break;
         case 'c'  : ascii[i]=0x63; break;
         case 'd'  : ascii[i]=0x64; break;
         case 'e'  : ascii[i]=0x65; break;
         case 'f'  : ascii[i]=0x66; break;
         case 'g'  : ascii[i]=0x67; break;
         case 'h'  : ascii[i]=0x68; break;
         case 'i'  : ascii[i]=0x69; break;
         case 'j'  : ascii[i]=0x6A; break;
         case 'k'  : ascii[i]=0x6B; break;
         case 'l'  : ascii[i]=0x6C; break;
         case 'm'  : ascii[i]=0x6D; break;
         case 'n'  : ascii[i]=0x6E; break;
         case 'o'  : ascii[i]=0x6F; break;

         case 'p'  : ascii[i]=0x70; break;
         case 'q'  : ascii[i]=0x71; break;
         case 'r'  : ascii[i]=0x72; break;
         case 's'  : ascii[i]=0x73; break;
         case 't'  : ascii[i]=0x74; break;
         case 'u'  : ascii[i]=0x75; break;
         case 'v'  : ascii[i]=0x76; break;
         case 'w'  : ascii[i]=0x77; break;
         case 'x'  : ascii[i]=0x78; break;
         case 'y'  : ascii[i]=0x79; break;
         case 'z'  : ascii[i]=0x7A; break;

         case 0x7C : // one of both is the @ character
         case 0xB5 : ascii[i]=0x40; break;
         default   : ascii[i]=0x5F; break;
      }
   }
}

static const char ascii_map[256]={
   '_','_','_','_','_','_','_','_','_','_','\n','_','_','\r','_','_',
   '_','_','_','_','_','_','_','_','_','_','_','_','_','_','_','_',
   ' ','_','\"','_','$','%','&','\'','(',')','*','+',',','-','.','/',
   '0','1','2','3','4','5','6','7','8','9',':',';','<','=','>','?',
   '@','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O',
   'P','Q','R','S','T','U','V','W','X','Y','Z','_','/','_','_','_',
   '_','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o',
   'p','q','r','s','t','u','v','w','x','y','z','_','_','_','_','_',
   '_','_','_','_','_','_','_','_','_','_','_','_','_','_','_','_',
   '_','_','_','_','_','_','_','_','_','_','_','_','_','_','_','_',
   '_','_','_','_','_','_','_','_','_','_','_','_','_','_','_','_',
   '_','_','_','_','_','_','_','_','_','_','_','_','_','_','_','_',
   '_','_','_','_','_','_','_','_','_','_','_','_','_','_','_','_',
   '_','_','_','_','_','_','_','_','_','_','_','_','_','_','_','_',
   '_','_','_','_','_','_','_','_','_','_','_','_','_','_','_','_',
   '_','_','_','_','_','_','_','_','_','_','_','_','_','_','_','_'
};

/**
 * @brief Convert an ASCII string to EBCDIC (supports only non-diacritic characters).
 *
 * \param[in] ascii     The ASCII string to convert.
 * \param[out] ebcdic   Buffer that has enough room for len EBCDIC characters
 * \param[in] len       Length of the input string
 */
void ssh_string_to_ebcdic(const char* ascii, char* ebcdic, unsigned int len) {
   unsigned int i;

   for (i=0;i<len;i++) {
      ebcdic[i]=ascii_map[*((unsigned char*)(ascii+i))];
   }
}

/**
 * @brief Convert a null-terminated ASCII string to EBCDIC
 * (supports only non-diacritic characters), writing to a static buffer.
 *
 * \param[in] ascii     The ASCII string to convert.
 */
char* ssh_string_for_log(const char* ascii) {
   unsigned int i;
   static char ebcdic[4096];

   for (i=0; ascii[i]!='\0' && i < sizeof(ebcdic)-1; i++) {
      ebcdic[i]=ascii_map[*((unsigned char*)(ascii+i))];
   }
   ebcdic[i]='\0';

   return ebcdic;
}

#endif /* __EBCDIC__ */

char* ssh_string_utf8_to_local(ssh_session session, char* utf8) {
    if (session == NULL || utf8 == NULL) {
        if (session == NULL)
            fprintf(stderr, "session==NULL\n");
        else
            fprintf(stderr, "utf==NULL\n");

        return NULL;
    }
    if (session->opts.utf_to_local_func == NULL) {
        fprintf(stderr, "No UTF8->local function set\n");
#ifdef __EBCDIC__
        // if EBCDIC, let's do at least basic ASCII->EBCDIC conversion
        ssh_string_to_ebcdic(utf8, utf8, strlen(utf8));
#endif
        return utf8; // no conversion function set = no conversion
    }

    fprintf(stderr, "Doing UTF8->local... UTF-8: %s", utf8);
    char* r  = session->opts.utf_to_local_func(utf8);
    fprintf(stderr, " local: %s\n", r);
    return r;
}

char* ssh_string_local_to_utf8(ssh_session session, char* local) {
    if (session == NULL || local == NULL)
        return NULL;
    if (session->opts.local_to_utf_func == NULL) {
#ifdef __EBCDIC__
        // if EBCDIC, let's do at least basic EBCDIC->ASCII conversion
        ssh_string_from_ebcdic(local, local, strlen(local));
#endif
        return local; // no conversion function set = no conversion
    }
    return session->opts.local_to_utf_func(local);
}

/** @} */

/* vim: set ts=4 sw=4 et cindent: */
