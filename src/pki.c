/*
 * pki.c
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
 * Copyright (c) 2011-2013 Andreas Schneider <asn@cryptomilk.org>
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

/**
 * @defgroup libssh_pki The SSH Public Key Infrastructure
 * @ingroup libssh
 *
 * Functions for the creation, importation and manipulation of public and
 * private keys in the context of the SSH protocol
 *
 * @{
 */

#include "config.h"

#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
# ifdef HAVE_IO_H
#  include <io.h>
#  undef open
#  define open _open
#  undef close
#  define close _close
#  undef read
#  define read _read
#  undef unlink
#  define unlink _unlink
# endif /* HAVE_IO_H */
#endif

#include "libssh/libssh.h"
#include "libssh/session.h"
#include "libssh/priv.h"
#include "libssh/pki.h"
#include "libssh/pki_priv.h"
#include "libssh/keys.h"
#include "libssh/buffer.h"
#include "libssh/misc.h"
#include "libssh/agent.h"

enum ssh_keytypes_e pki_privatekey_type_from_string(const char *privkey) {
    if (strncmp(privkey, DSA_HEADER_BEGIN, strlen(DSA_HEADER_BEGIN)) == 0) {
        return SSH_KEYTYPE_DSS;
    }

    if (strncmp(privkey, RSA_HEADER_BEGIN, strlen(RSA_HEADER_BEGIN)) == 0) {
        return SSH_KEYTYPE_RSA;
    }

    if (strncmp(privkey, ECDSA_HEADER_BEGIN, strlen(ECDSA_HEADER_BEGIN)) == 0) {
        return SSH_KEYTYPE_ECDSA;
    }

    return SSH_KEYTYPE_UNKNOWN;
}

/**
 * @brief returns the ECDSA key name ("ecdsa-sha2-nistp256" for example)
 *
 * @param[in] key the ssh_key whose ECDSA name to get
 *
 * @returns the ECDSA key name ("ecdsa-sha2-nistp256" for example)
 *
 * @returns "unknown" if the ECDSA key name is not known
 */
const char *ssh_pki_key_ecdsa_name(const ssh_key key)
{
    if (key == NULL) {
        return NULL;
    }

#ifdef HAVE_ECC /* FIXME Better ECC check needed */
    return pki_key_ecdsa_nid_to_name(key->ecdsa_nid);
#else
    return NULL;
#endif
}

/**
 * @brief creates a new empty SSH key
 * @returns an empty ssh_key handle, or NULL on error.
 */
ssh_key ssh_key_new (void) {
  ssh_key ptr = malloc (sizeof (struct ssh_key_struct));
  if (ptr == NULL) {
      return NULL;
  }
  ZERO_STRUCTP(ptr);
  return ptr;
}

ssh_key ssh_key_dup(const ssh_key key)
{
    if (key == NULL) {
        return NULL;
    }

    return pki_key_dup(key, 0);
}

/**
 * @brief clean up the key and deallocate all existing keys
 * @param[in] key ssh_key to clean
 */
void ssh_key_clean (ssh_key key){
    if(key == NULL)
        return;
#ifdef HAVE_LIBGCRYPT
    if(key->dsa) gcry_sexp_release(key->dsa);
    if(key->rsa) gcry_sexp_release(key->rsa);
    if(key->ecdsa) gcry_sexp_release(key->ecdsa);
#elif defined HAVE_LIBCRYPTO
    if(key->dsa) DSA_free(key->dsa);
    if(key->rsa) RSA_free(key->rsa);
#ifdef HAVE_OPENSSL_ECC
    if(key->ecdsa) EC_KEY_free(key->ecdsa);
#endif /* HAVE_OPENSSL_ECC */
#elif defined HAVE_LIBMBEDCRYPTO
    if (key->rsa != NULL) {
        mbedtls_pk_free(key->rsa);
        SAFE_FREE(key->rsa);
    }

    if (key->ecdsa != NULL) {
        mbedtls_ecdsa_free(key->ecdsa);
        SAFE_FREE(key->ecdsa);
    }
#endif
    if (key->ed25519_privkey != NULL){
        explicit_bzero(key->ed25519_privkey, sizeof(ed25519_privkey));
        SAFE_FREE(key->ed25519_privkey);
    }
    SAFE_FREE(key->ed25519_pubkey);
    if (key->cert != NULL) {
        ssh_buffer_free(key->cert);
    }
    key->cert_type = SSH_KEYTYPE_UNKNOWN;
    key->flags=SSH_KEY_FLAG_EMPTY;
    key->type=SSH_KEYTYPE_UNKNOWN;
    key->ecdsa_nid = 0;
    key->type_c=NULL;
    key->dsa = NULL;
    key->rsa = NULL;
    key->ecdsa = NULL;
}

/**
 * @brief deallocate a SSH key
 * @param[in] key ssh_key handle to free
 */
void ssh_key_free (ssh_key key){
    if(key){
        ssh_key_clean(key);
        SAFE_FREE(key);
    }
}

/**
 * @brief returns the type of a ssh key
 * @param[in] key the ssh_key handle
 * @returns one of SSH_KEYTYPE_RSA, SSH_KEYTYPE_DSS,
 *          SSH_KEYTYPE_ECDSA, SSH_KEYTYPE_ED25519,
 *          SSH_KEYTYPE_DSS_CERT01, SSH_KEYTYPE_RSA_CERT01
 * @returns SSH_KEYTYPE_UNKNOWN if the type is unknown
 */
enum ssh_keytypes_e ssh_key_type(const ssh_key key){
    if (key == NULL) {
        return SSH_KEYTYPE_UNKNOWN;
    }
    return key->type;
}

/**
 * @brief Convert a signature type to a string.
 *
 * @param[in]  type     The algorithm type to convert.
 *
 * @return              A string for the keytype or NULL if unknown.
 */
const char *
ssh_key_signature_to_char(enum ssh_keytypes_e type,
                          enum ssh_digest_e hash_type)
{
    if (type != SSH_KEYTYPE_RSA) {
        return ssh_key_type_to_char(type);
    }

#ifdef __EBCDIC__
#pragma convert("ISO8859-1")
#endif
    switch (hash_type) {
    case SSH_DIGEST_SHA256:
        return "rsa-sha2-256";
    case SSH_DIGEST_SHA512:
        return "rsa-sha2-512";
    case SSH_DIGEST_SHA1:
    case SSH_DIGEST_AUTO:
        return "ssh-rsa";
    default:
        return NULL;
    }
#ifdef __EBCDIC__
#pragma convert(pop)
#endif

    /* We should never reach this */
    return NULL;
}

/**
 * @brief Convert a key type to a string.
 *
 * @param[in]  type     The type to convert.
 *
 * @return              A string for the keytype or NULL if unknown.
 */
const char *ssh_key_type_to_char(enum ssh_keytypes_e type) {
#ifdef __EBCDIC__
#pragma convert("ISO8859-1")
#endif
  switch (type) {
    case SSH_KEYTYPE_DSS:
      return "ssh-dss";
    case SSH_KEYTYPE_RSA:
      return "ssh-rsa";
    case SSH_KEYTYPE_ECDSA:
      return "ssh-ecdsa";
    case SSH_KEYTYPE_ED25519:
      return "ssh-ed25519";
    case SSH_KEYTYPE_DSS_CERT01:
      return "ssh-dss-cert-v01@openssh.com";
    case SSH_KEYTYPE_RSA_CERT01:
      return "ssh-rsa-cert-v01@openssh.com";
    case SSH_KEYTYPE_RSA1:
    case SSH_KEYTYPE_UNKNOWN:
      return NULL;
  }
#ifdef __EBCDIC__
#pragma convert(pop)
#endif

  /* We should never reach this */
  return NULL;
}

static enum ssh_digest_e ssh_key_hash_from_name(const char *name)
{
    if (name == NULL) {
        /* TODO we should rather fail */
        return SSH_DIGEST_AUTO;
    }

#ifdef __EBCDIC__
#pragma convert("ISO8859-1")
    // On EBCDIC, compare in Latin-1 first
    if (strcmp(name, "ssh-rsa") == 0) {
        return SSH_DIGEST_SHA1;
    } else if (strcmp(name, "rsa-sha2-256") == 0) {
        return SSH_DIGEST_SHA256;
    } else if (strcmp(name, "rsa-sha2-512") == 0) {
        return SSH_DIGEST_SHA512;
    }
#pragma convert(pop)
#endif
    if (strcmp(name, "ssh-rsa") == 0) {
        return SSH_DIGEST_SHA1;
    } else if (strcmp(name, "rsa-sha2-256") == 0) {
        return SSH_DIGEST_SHA256;
    } else if (strcmp(name, "rsa-sha2-512") == 0) {
        return SSH_DIGEST_SHA512;
    }

    /* we do not care for others now */
    return SSH_DIGEST_AUTO;
}

/**
 * @brief Checks the given key against the configured allowed
 * public key algorithm types
 *
 * @param[in] session The SSH session
 * @param[in] type    The key algorithm to check
 * @returns           1 if the key algorithm is allowed, 0 otherwise
 */
int ssh_key_algorithm_allowed(ssh_session session, const char *type)
{
    const char *allowed_list;

    allowed_list = session->opts.pubkey_accepted_types;
    if (allowed_list == NULL) {
        allowed_list = ssh_kex_get_default_methods(SSH_HOSTKEYS);
    }

    SSH_LOG(SSH_LOG_DEBUG, "Checking %s with list <%s>", type, allowed_list);
    return ssh_match_group(allowed_list, type);
}

/**
 * @brief Checks the given host key against the configured allowed
 * host key algorithm types
 *
 * @param[in] session The SSH session
 * @param[in] type    The host key algorithm to check
 * @returns           1 if the host key algorithm is allowed, 0 otherwise
 */
int ssh_hostkey_algorithm_allowed(ssh_session session, const char *type)
{
    const char *allowed_types;

    allowed_types = session->opts.wanted_methods[SSH_HOSTKEYS];
    if (allowed_types == NULL) {
       return 0; /* should never get here */
    }

    if (ssh_match_group(allowed_types, type)) {
        return 1;
    }
    if (strcmp(type, "ssh-rsa") == 0) {
        /*
         * If rsa-sha2 hostkey algo is used, the server returns ssh-rsa as
         * host key type. Hence, we need to check if one of the rsa-sha2
         * variants is in the allowed hostkey types list.
         */
        if (ssh_match_group(allowed_types, "rsa-sha2-256")) {
            return 1;
        }
        if (ssh_match_group(allowed_types, "rsa-sha2-512")) {
            return 1;
        }
    }

    return 0;
}

/**
 * @brief Convert a key type to a hash type. This is usually unambiguous
 * for all the key types, unless the SHA2 extension (RFC 8332) is
 * negotiated during key exchange.
 *
 * @param[in]  session  SSH Session.
 *
 * @param[in]  type     The type to convert.
 *
 * @return              A hash type to be used.
 */
enum ssh_digest_e ssh_key_type_to_hash(ssh_session session,
                                       enum ssh_keytypes_e type)
{
    switch (type) {
    case SSH_KEYTYPE_RSA:
        if (ssh_key_algorithm_allowed(session, "rsa-sha2-512") &&
            (session->extensions & SSH_EXT_SIG_RSA_SHA512)) {
            return SSH_DIGEST_SHA512;
        }

        if (ssh_key_algorithm_allowed(session, "rsa-sha2-256") &&
            (session->extensions & SSH_EXT_SIG_RSA_SHA256)) {
            return SSH_DIGEST_SHA256;
        }

        /* Default algorithm for RSA is SHA1 */
        return SSH_DIGEST_SHA1;

    default:
        /* Other key types use the default value (not used) */
        return SSH_DIGEST_AUTO;
    }

    /* We should never reach this */
    return SSH_DIGEST_AUTO;
}

/**
 * @brief Gets signature algorithm name to be used with the given
 *        key type.
 *
 * @param[in]  session  SSH session.
 * @param[in]  type     The algorithm type to convert.
 *
 * @return              A string for the keytype or NULL if unknown.
 */
const char *
ssh_key_get_signature_algorithm(ssh_session session,
                                enum ssh_keytypes_e type)
{
    enum ssh_digest_e hash_type;

    hash_type = ssh_key_type_to_hash(session, type);

    return ssh_key_signature_to_char(type, hash_type);
}

/**
 * @brief Convert a ssh key algorithm name to a ssh key algorithm type.
 *
 * @param[in] name      The name to convert.
 *
 * @return              The enum ssh key algorithm type.
 */
enum ssh_keytypes_e ssh_key_type_from_signature_name(const char *name) {
    if (name == NULL) {
        return SSH_KEYTYPE_UNKNOWN;
    }

#ifdef __EBCDIC__
#pragma convert("ISO8859-1")
    // On EBCDIC, compare in Latin-1 first
    if ((strcmp(name, "rsa-sha2-256") == 0) ||
        (strcmp(name, "rsa-sha2-512") == 0)) {
        return SSH_KEYTYPE_RSA;
    }
#pragma convert(pop)
#endif
    if ((strcmp(name, "rsa-sha2-256") == 0) ||
        (strcmp(name, "rsa-sha2-512") == 0)) {
        return SSH_KEYTYPE_RSA;
    }

    /* Otherwise the key type matches the signature type */
    return ssh_key_type_from_name(name);
}

/**
 * @brief Convert a ssh key name to a ssh key type.
 *
 * @param[in] name      The name to convert.
 *
 * @return              The enum ssh key type.
 */
enum ssh_keytypes_e ssh_key_type_from_name(const char *name) {
    if (name == NULL) {
        return SSH_KEYTYPE_UNKNOWN;
    }

#ifdef __EBCDIC__
#pragma convert("ISO8859-1")
    // On EBCDIC, compare in Latin-1 first
    if (strcmp(name, "rsa") == 0) {
        return SSH_KEYTYPE_RSA;
    } else if (strcmp(name, "dsa") == 0) {
        return SSH_KEYTYPE_DSS;
    } else if (strcmp(name, "ssh-rsa") == 0) {
        return SSH_KEYTYPE_RSA;
    } else if (strcmp(name, "ssh-dss") == 0) {
        return SSH_KEYTYPE_DSS;
    } else if (strcmp(name, "ssh-ecdsa") == 0
            || strcmp(name, "ecdsa") == 0
            || strcmp(name, "ecdsa-sha2-nistp256") == 0
            || strcmp(name, "ecdsa-sha2-nistp384") == 0
            || strcmp(name, "ecdsa-sha2-nistp521") == 0) {
        return SSH_KEYTYPE_ECDSA;
    } else if (strcmp(name, "ssh-ed25519") == 0){
        return SSH_KEYTYPE_ED25519;
    } else if (strcmp(name, "ssh-dss-cert-v01@openssh.com") == 0) {
        return SSH_KEYTYPE_DSS_CERT01;
    } else if (strcmp(name, "ssh-rsa-cert-v01@openssh.com") == 0) {
        return SSH_KEYTYPE_RSA_CERT01;
    }
#pragma convert(pop)
#endif

    if (strcmp(name, "rsa") == 0) {
        return SSH_KEYTYPE_RSA;
    } else if (strcmp(name, "dsa") == 0) {
        return SSH_KEYTYPE_DSS;
    } else if (strcmp(name, "ssh-rsa") == 0) {
        return SSH_KEYTYPE_RSA;
    } else if (strcmp(name, "ssh-dss") == 0) {
        return SSH_KEYTYPE_DSS;
    } else if (strcmp(name, "ssh-ecdsa") == 0
            || strcmp(name, "ecdsa") == 0
            || strcmp(name, "ecdsa-sha2-nistp256") == 0
            || strcmp(name, "ecdsa-sha2-nistp384") == 0
            || strcmp(name, "ecdsa-sha2-nistp521") == 0) {
        return SSH_KEYTYPE_ECDSA;
    } else if (strcmp(name, "ssh-ed25519") == 0){
        return SSH_KEYTYPE_ED25519;
    } else if (strcmp(name, "ssh-dss-cert-v01@openssh.com") == 0) {
        return SSH_KEYTYPE_DSS_CERT01;
    } else if (strcmp(name, "ssh-rsa-cert-v01@openssh.com") == 0) {
        return SSH_KEYTYPE_RSA_CERT01;
    }

    return SSH_KEYTYPE_UNKNOWN;
}

/**
 * @brief Check if the key has/is a public key.
 *
 * @param[in] k         The key to check.
 *
 * @return              1 if it is a public key, 0 if not.
 */
int ssh_key_is_public(const ssh_key k) {
    if (k == NULL) {
        return 0;
    }

    return (k->flags & SSH_KEY_FLAG_PUBLIC) == SSH_KEY_FLAG_PUBLIC;
}

/**
 * @brief Check if the key is a private key.
 *
 * @param[in] k         The key to check.
 *
 * @return              1 if it is a private key, 0 if not.
 */
int ssh_key_is_private(const ssh_key k) {
    if (k == NULL) {
        return 0;
    }

    return (k->flags & SSH_KEY_FLAG_PRIVATE) == SSH_KEY_FLAG_PRIVATE;
}

/**
 * @brief Compare keys if they are equal.
 *
 * @param[in] k1        The first key to compare.
 *
 * @param[in] k2        The second key to compare.
 *
 * @param[in] what      What part or type of the key do you want to compare.
 *
 * @return              0 if equal, 1 if not.
 */
int ssh_key_cmp(const ssh_key k1,
                const ssh_key k2,
                enum ssh_keycmp_e what)
{
    if (k1 == NULL || k2 == NULL) {
        return 1;
    }

    if (k1->type != k2->type) {
        SSH_LOG(SSH_LOG_WARN, "key types don't match!");
        return 1;
    }

    if (what == SSH_KEY_CMP_PRIVATE) {
        if (!ssh_key_is_private(k1) ||
            !ssh_key_is_private(k2)) {
            return 1;
        }
    }

    if (k1->type == SSH_KEYTYPE_ED25519) {
        return pki_ed25519_key_cmp(k1, k2, what);
    }

    return pki_key_compare(k1, k2, what);
}

ssh_signature ssh_signature_new(void)
{
    struct ssh_signature_struct *sig;

    sig = malloc(sizeof(struct ssh_signature_struct));
    if (sig == NULL) {
        return NULL;
    }
    ZERO_STRUCTP(sig);

    return sig;
}

void ssh_signature_free(ssh_signature sig)
{
    if (sig == NULL) {
        return;
    }

    switch(sig->type) {
        case SSH_KEYTYPE_DSS:
#ifdef HAVE_LIBGCRYPT
            gcry_sexp_release(sig->dsa_sig);
#elif defined HAVE_LIBCRYPTO
            DSA_SIG_free(sig->dsa_sig);
#endif
            break;
        case SSH_KEYTYPE_RSA:
#ifdef HAVE_LIBGCRYPT
            gcry_sexp_release(sig->rsa_sig);
#elif defined HAVE_LIBCRYPTO
            SAFE_FREE(sig->rsa_sig);
#elif defined HAVE_LIBMBEDCRYPTO
            SAFE_FREE(sig->rsa_sig);
#endif
            break;
        case SSH_KEYTYPE_ECDSA:
#ifdef HAVE_GCRYPT_ECC
            gcry_sexp_release(sig->ecdsa_sig);
#elif defined(HAVE_LIBCRYPTO) && defined(HAVE_OPENSSL_ECC)
            ECDSA_SIG_free(sig->ecdsa_sig);
#elif defined HAVE_LIBMBEDCRYPTO
            bignum_safe_free(sig->ecdsa_sig.r);
            bignum_safe_free(sig->ecdsa_sig.s);
#endif
            break;
        case SSH_KEYTYPE_ED25519:
            SAFE_FREE(sig->ed25519_sig);
            break;
        case SSH_KEYTYPE_DSS_CERT01:
        case SSH_KEYTYPE_RSA_CERT01:
        case SSH_KEYTYPE_RSA1:
        case SSH_KEYTYPE_UNKNOWN:
            break;
    }

    SAFE_FREE(sig);
}

/**
 * @brief import a base64 formated key from a memory c-string
 *
 * @param[in]  b64_key  The c-string holding the base64 encoded key
 *
 * @param[in]  passphrase The passphrase to decrypt the key, or NULL
 *
 * @param[in]  auth_fn  An auth function you may want to use or NULL.
 *
 * @param[in]  auth_data Private data passed to the auth function.
 *
 * @param[out] pkey     A pointer where the allocated key can be stored. You
 *                      need to free the memory.
 *
 * @return  SSH_ERROR in case of error, SSH_OK otherwise.
 *
 * @see ssh_key_free()
 */
int ssh_pki_import_privkey_base64(const char *b64_key,
                                  const char *passphrase,
                                  ssh_auth_callback auth_fn,
                                  void *auth_data,
                                  ssh_key *pkey)
{
    ssh_key key;
    int cmp;

    if (b64_key == NULL || pkey == NULL) {
        return SSH_ERROR;
    }

    if (b64_key == NULL || !*b64_key) {
        return SSH_ERROR;
    }

    SSH_LOG(SSH_LOG_INFO,
            "Trying to decode privkey passphrase=%s",
            passphrase ? "true" : "false");

    /* Test for OpenSSH key format first */
    cmp = strncmp(b64_key, OPENSSH_HEADER_BEGIN, strlen(OPENSSH_HEADER_BEGIN));
    if (cmp == 0) {
        key = ssh_pki_openssh_privkey_import(b64_key,
                                             passphrase,
                                             auth_fn,
                                             auth_data);
    } else {
        /* fallback on PEM decoder */
        key = pki_private_key_from_base64(b64_key,
                                          passphrase,
                                          auth_fn,
                                          auth_data);
    }
    if (key == NULL) {
        return SSH_ERROR;
    }

    *pkey = key;

    return SSH_OK;
}
 /**
 * @brief Convert a private key to a pem base64 encoded key, or OpenSSH format for
 *        keytype ssh-ed25519
 *
 * @param[in]  privkey  The private key to export.
 *
 * @param[in]  passphrase The passphrase to use to encrypt the key with or
 *             NULL. An empty string means no passphrase.
 *
 * @param[in]  auth_fn  An auth function you may want to use or NULL.
 *
 * @param[in]  auth_data Private data passed to the auth function.
 *
 * @param[out] b64_key  A pointer to store the allocated base64 encoded key. You
 *                      need to free the buffer.
 *
 * @return     SSH_OK on success, SSH_ERROR on error.
 */
int ssh_pki_export_privkey_base64(const ssh_key privkey,
                                  const char *passphrase,
                                  ssh_auth_callback auth_fn,
                                  void *auth_data,
                                  char **b64_key)
{
    ssh_string blob = NULL;
    char *b64 = NULL;

    if (privkey == NULL || !ssh_key_is_private(privkey)) {
        return SSH_ERROR;
    }

    if (privkey->type == SSH_KEYTYPE_ED25519){
        blob = ssh_pki_openssh_privkey_export(privkey,
                                              passphrase,
                                              auth_fn,
                                              auth_data);
    } else {
        blob = pki_private_key_to_pem(privkey,
                                      passphrase,
                                      auth_fn,
                                      auth_data);
    }
    if (blob == NULL) {
        return SSH_ERROR;
    }

    b64 = strndup(ssh_string_data(blob), ssh_string_len(blob));
    ssh_string_free(blob);
    if (b64 == NULL) {
        return SSH_ERROR;
    }

    *b64_key = b64;

    return SSH_OK;
}

/**
 * @brief Import a key from a file.
 *
 * @param[in]  filename The filename of the the private key.
 *
 * @param[in]  passphrase The passphrase to decrypt the private key. Set to NULL
 *                        if none is needed or it is unknown.
 *
 * @param[in]  auth_fn  An auth function you may want to use or NULL.
 *
 * @param[in]  auth_data Private data passed to the auth function.
 *
 * @param[out] pkey     A pointer to store the allocated ssh_key. You need to
 *                      free the key.
 *
 * @returns SSH_OK on success, SSH_EOF if the file doesn't exist or permission
 *          denied, SSH_ERROR otherwise.
 *
 * @see ssh_key_free()
 **/
int ssh_pki_import_privkey_file(const char *filename,
                                const char *passphrase,
                                ssh_auth_callback auth_fn,
                                void *auth_data,
                                ssh_key *pkey) {
    struct stat sb;
    char *key_buf;
    FILE *file;
    off_t size;
    int rc;

    if (pkey == NULL || filename == NULL || *filename == '\0') {
        return SSH_ERROR;
    }

    file = fopen(filename, "rb");
    if (file == NULL) {
        SSH_LOG(SSH_LOG_WARN,
                "Error opening %s: %s",
                filename,
                strerror(errno));
        return SSH_EOF;
    }

    rc = fstat(fileno(file), &sb);
    if (rc < 0) {
        fclose(file);
        SSH_LOG(SSH_LOG_WARN,
                "Error getting stat of %s: %s",
                filename,
                strerror(errno));
        switch (errno) {
            case ENOENT:
            case EACCES:
                return SSH_EOF;
        }

        return SSH_ERROR;
    }

    if (sb.st_size > MAX_PRIVKEY_SIZE) {
        SSH_LOG(SSH_LOG_WARN,
                "Private key is bigger than 4M.");
        fclose(file);
        return SSH_ERROR;
    }

    key_buf = malloc(sb.st_size + 1);
    if (key_buf == NULL) {
        fclose(file);
        SSH_LOG(SSH_LOG_WARN, "Out of memory!");
        return SSH_ERROR;
    }

    size = fread(key_buf, 1, sb.st_size, file);
    fclose(file);

    if (size != sb.st_size) {
        SAFE_FREE(key_buf);
        SSH_LOG(SSH_LOG_WARN,
                "Error reading %s: %s",
                filename,
                strerror(errno));
        return SSH_ERROR;
    }
    key_buf[size] = 0;

    rc = ssh_pki_import_privkey_base64(key_buf,
                                       passphrase,
                                       auth_fn,
                                       auth_data,
                                       pkey);

    SAFE_FREE(key_buf);
    return rc;
}

/**
 * @brief Export a private key to a pem file on disk, or OpenSSH format for
 *        keytype ssh-ed25519
 *
 * @param[in]  privkey  The private key to export.
 *
 * @param[in]  passphrase The passphrase to use to encrypt the key with or
 *             NULL. An empty string means no passphrase.
 *
 * @param[in]  auth_fn  An auth function you may want to use or NULL.
 *
 * @param[in]  auth_data Private data passed to the auth function.
 *
 * @param[in]  filename  The path where to store the pem file.
 *
 * @return     SSH_OK on success, SSH_ERROR on error.
 */
int ssh_pki_export_privkey_file(const ssh_key privkey,
                                const char *passphrase,
                                ssh_auth_callback auth_fn,
                                void *auth_data,
                                const char *filename)
{
    ssh_string blob;
    FILE *fp;
    int rc;

    if (privkey == NULL || !ssh_key_is_private(privkey)) {
        return SSH_ERROR;
    }

    fp = fopen(filename, "wb");
    if (fp == NULL) {
        SSH_LOG(SSH_LOG_FUNCTIONS, "Error opening %s: %s",
                filename, strerror(errno));
        return SSH_EOF;
    }

    if (privkey->type == SSH_KEYTYPE_ED25519){
        blob = ssh_pki_openssh_privkey_export(privkey,
                                              passphrase,
                                              auth_fn,
                                              auth_data);
    } else {
        blob = pki_private_key_to_pem(privkey,
                                      passphrase,
                                      auth_fn,
                                      auth_data);
    }
    if (blob == NULL) {
        fclose(fp);
        return -1;
    }

    rc = fwrite(ssh_string_data(blob), ssh_string_len(blob), 1, fp);
    ssh_string_free(blob);
    if (rc != 1 || ferror(fp)) {
        fclose(fp);
        unlink(filename);
        return SSH_ERROR;
    }
    fclose(fp);

    return SSH_OK;
}

/* temporary function to migrate seemlessly to ssh_key */
ssh_public_key ssh_pki_convert_key_to_publickey(const ssh_key key) {
    ssh_public_key pub;
    ssh_key tmp;

    if(key == NULL) {
        return NULL;
    }

    tmp = ssh_key_dup(key);
    if (tmp == NULL) {
        return NULL;
    }

    pub = malloc(sizeof(struct ssh_public_key_struct));
    if (pub == NULL) {
        ssh_key_free(tmp);
        return NULL;
    }
    ZERO_STRUCTP(pub);

    pub->type = tmp->type;
    pub->type_c = tmp->type_c;

    pub->dsa_pub = tmp->dsa;
    tmp->dsa = NULL;
    pub->rsa_pub = tmp->rsa;
    tmp->rsa = NULL;

    ssh_key_free(tmp);

    return pub;
}

ssh_private_key ssh_pki_convert_key_to_privatekey(const ssh_key key) {
    ssh_private_key privkey;

    privkey = malloc(sizeof(struct ssh_private_key_struct));
    if (privkey == NULL) {
        ssh_key_free(key);
        return NULL;
    }

    privkey->type = key->type;
    privkey->dsa_priv = key->dsa;
    privkey->rsa_priv = key->rsa;

    return privkey;
}

int pki_import_privkey_buffer(enum ssh_keytypes_e type,
                              ssh_buffer buffer,
                              ssh_key *pkey)
{
    ssh_key key = NULL;
    int rc;

    key = ssh_key_new();
    if (key == NULL) {
        return SSH_ERROR;
    }

    key->type = type;
    key->type_c = ssh_key_type_to_char(type);
    key->flags = SSH_KEY_FLAG_PRIVATE | SSH_KEY_FLAG_PUBLIC;

    switch (type) {
        case SSH_KEYTYPE_DSS:
            {
                ssh_string p = NULL;
                ssh_string q = NULL;
                ssh_string g = NULL;
                ssh_string pubkey = NULL;
                ssh_string privkey = NULL;

                rc = ssh_buffer_unpack(buffer, "SSSSS", &p, &q, &g,
                                       &pubkey, &privkey);
                if (rc != SSH_OK) {
                    SSH_LOG(SSH_LOG_WARN, "Unpack error");
                    goto fail;
                }

                rc = pki_privkey_build_dss(key, p, q, g, pubkey, privkey);
#ifdef DEBUG_CRYPTO
                ssh_print_hexa("p", ssh_string_data(p), ssh_string_len(p));
                ssh_print_hexa("q", ssh_string_data(q), ssh_string_len(q));
                ssh_print_hexa("g", ssh_string_data(g), ssh_string_len(g));
//                ssh_print_hexa("pubkey", ssh_string_data(pubkey),
//                               ssh_string_len(pubkey));
//                ssh_print_hexa("privkey", ssh_string_data(privkey),
//                               ssh_string_len(privkey));
#endif
                ssh_string_burn(p);
                ssh_string_free(p);
                ssh_string_burn(q);
                ssh_string_free(q);
                ssh_string_burn(g);
                ssh_string_free(g);
                ssh_string_burn(pubkey);
                ssh_string_free(pubkey);
                ssh_string_burn(privkey);
                ssh_string_free(privkey);
                if (rc == SSH_ERROR) {
                    goto fail;
                }
            }
            break;
        case SSH_KEYTYPE_RSA:
            {
                ssh_string n = NULL;
                ssh_string e = NULL;
                ssh_string d = NULL;
                ssh_string iqmp = NULL;
                ssh_string p = NULL;
                ssh_string q = NULL;

                rc = ssh_buffer_unpack(buffer, "SSSSSS", &n, &e, &d,
                                       &iqmp, &p, &q);
                if (rc != SSH_OK) {
                    SSH_LOG(SSH_LOG_WARN, "Unpack error");
                    goto fail;
                }

                rc = pki_privkey_build_rsa(key, n, e, d, iqmp, p, q);
#ifdef DEBUG_CRYPTO
                ssh_print_hexa("n", ssh_string_data(n), ssh_string_len(n));
                ssh_print_hexa("e", ssh_string_data(e), ssh_string_len(e));
                ssh_print_hexa("d", ssh_string_data(d), ssh_string_len(d));
                ssh_print_hexa("iqmp", ssh_string_data(iqmp),
                               ssh_string_len(iqmp));
                ssh_print_hexa("p", ssh_string_data(p), ssh_string_len(p));
                ssh_print_hexa("q", ssh_string_data(q), ssh_string_len(q));
#endif
                ssh_string_burn(n);
                ssh_string_free(n);
                ssh_string_burn(e);
                ssh_string_free(e);
                ssh_string_burn(d);
                ssh_string_free(d);
                ssh_string_burn(iqmp);
                ssh_string_free(iqmp);
                ssh_string_burn(p);
                ssh_string_free(p);
                ssh_string_burn(q);
                ssh_string_free(q);
                if (rc == SSH_ERROR) {
                    SSH_LOG(SSH_LOG_WARN, "Failed to build RSA private key");
                    goto fail;
                }
            }
            break;
#ifdef HAVE_ECC
        case SSH_KEYTYPE_ECDSA:
            {
                ssh_string e = NULL;
                ssh_string exp = NULL;
                ssh_string i = NULL;
                int nid;

                rc = ssh_buffer_unpack(buffer, "SSS", &i, &e, &exp);
                if (rc != SSH_OK) {
                    SSH_LOG(SSH_LOG_WARN, "Unpack error");
                    goto fail;
                }

                nid = pki_key_ecdsa_nid_from_name(ssh_string_get_char(i));
                ssh_string_free(i);
                if (nid == -1) {
                    goto fail;
                }

                rc = pki_privkey_build_ecdsa(key, nid, e, exp);
                ssh_string_burn(e);
                ssh_string_free(e);
                ssh_string_burn(exp);
                ssh_string_free(exp);
                if (rc < 0) {
                    SSH_LOG(SSH_LOG_WARN, "Failed to build ECDSA private key");
                    goto fail;
                }

                /* Update key type */
                key->type_c = ssh_pki_key_ecdsa_name(key);
            }
            break;
#endif
        case SSH_KEYTYPE_ED25519:
            {
                ssh_string pubkey = NULL, privkey = NULL;

                rc = ssh_buffer_unpack(buffer, "SS", &pubkey, &privkey);
                if (rc != SSH_OK){
                    SSH_LOG(SSH_LOG_WARN, "Unpack error");
                    goto fail;
                }

                rc = pki_privkey_build_ed25519(key, pubkey, privkey);
                ssh_string_burn(privkey);
                ssh_string_free(privkey);
                ssh_string_free(pubkey);
                if (rc != SSH_OK) {
                    SSH_LOG(SSH_LOG_WARN, "Failed to build ed25519 key");
                    goto fail;
                }
            }
            break;
        case SSH_KEYTYPE_DSS_CERT01:
        case SSH_KEYTYPE_RSA_CERT01:
        case SSH_KEYTYPE_RSA1:
        case SSH_KEYTYPE_UNKNOWN:
        default:
            SSH_LOG(SSH_LOG_WARN, "Unknown private key type (%d)", type);
            goto fail;
    }

    *pkey = key;
    return SSH_OK;
fail:
    ssh_key_free(key);

    return SSH_ERROR;
}

static int pki_import_pubkey_buffer(ssh_buffer buffer,
                                    enum ssh_keytypes_e type,
                                    ssh_key *pkey) {
    ssh_key key = NULL;
    int rc;

    key = ssh_key_new();
    if (key == NULL) {
        return SSH_ERROR;
    }

    key->type = type;
    key->type_c = ssh_key_type_to_char(type);
    key->flags = SSH_KEY_FLAG_PUBLIC;

    switch (type) {
        case SSH_KEYTYPE_DSS:
            {
                ssh_string p = NULL;
                ssh_string q = NULL;
                ssh_string g = NULL;
                ssh_string pubkey = NULL;

                rc = ssh_buffer_unpack(buffer, "SSSS", &p, &q, &g, &pubkey);
                if (rc != SSH_OK) {
                    SSH_LOG(SSH_LOG_WARN, "Unpack error");
                    goto fail;
                }

                rc = pki_pubkey_build_dss(key, p, q, g, pubkey);
#ifdef DEBUG_CRYPTO
                ssh_print_hexa("p", ssh_string_data(p), ssh_string_len(p));
                ssh_print_hexa("q", ssh_string_data(q), ssh_string_len(q));
                ssh_print_hexa("g", ssh_string_data(g), ssh_string_len(g));
#endif
                ssh_string_burn(p);
                ssh_string_free(p);
                ssh_string_burn(q);
                ssh_string_free(q);
                ssh_string_burn(g);
                ssh_string_free(g);
                ssh_string_burn(pubkey);
                ssh_string_free(pubkey);
                if (rc == SSH_ERROR) {
                    SSH_LOG(SSH_LOG_WARN, "Failed to build DSA public key");
                    goto fail;
                }
            }
            break;
        case SSH_KEYTYPE_RSA:
            {
                ssh_string e = NULL;
                ssh_string n = NULL;

                rc = ssh_buffer_unpack(buffer, "SS", &e, &n);
                if (rc != SSH_OK) {
                    SSH_LOG(SSH_LOG_WARN, "Unpack error");
                    goto fail;
                }

                rc = pki_pubkey_build_rsa(key, e, n);
#ifdef DEBUG_CRYPTO
                ssh_print_hexa("e", ssh_string_data(e), ssh_string_len(e));
                ssh_print_hexa("n", ssh_string_data(n), ssh_string_len(n));
#endif
                ssh_string_burn(e);
                ssh_string_free(e);
                ssh_string_burn(n);
                ssh_string_free(n);
                if (rc == SSH_ERROR) {
                    SSH_LOG(SSH_LOG_WARN, "Failed to build RSA public key");
                    goto fail;
                }
            }
            break;
#ifdef HAVE_ECC
        case SSH_KEYTYPE_ECDSA:
            {
                ssh_string e = NULL;
                ssh_string i = NULL;
                int nid;

                rc = ssh_buffer_unpack(buffer, "SS", &i, &e);
                if (rc != SSH_OK) {
                    SSH_LOG(SSH_LOG_WARN, "Unpack error");
                    goto fail;
                }

                nid = pki_key_ecdsa_nid_from_name(ssh_string_get_char(i));
                ssh_string_free(i);
                if (nid == -1) {
                    goto fail;
                }

                rc = pki_pubkey_build_ecdsa(key, nid, e);
                ssh_string_burn(e);
                ssh_string_free(e);
                if (rc < 0) {
                    SSH_LOG(SSH_LOG_WARN, "Failed to build ECDSA public key");
                    goto fail;
                }

                /* Update key type */
                key->type_c = ssh_pki_key_ecdsa_name(key);
            }
            break;
#endif
        case SSH_KEYTYPE_ED25519:
        {
            ssh_string pubkey = ssh_buffer_get_ssh_string(buffer);
            if (ssh_string_len(pubkey) != ED25519_PK_LEN) {
                SSH_LOG(SSH_LOG_WARN, "Invalid public key length");
                ssh_string_burn(pubkey);
                ssh_string_free(pubkey);
                goto fail;
            }

            key->ed25519_pubkey = malloc(ED25519_PK_LEN);
            if (key->ed25519_pubkey == NULL) {
                ssh_string_burn(pubkey);
                ssh_string_free(pubkey);
                goto fail;
            }

            memcpy(key->ed25519_pubkey, ssh_string_data(pubkey), ED25519_PK_LEN);
            ssh_string_burn(pubkey);
            ssh_string_free(pubkey);
        }
        break;
        case SSH_KEYTYPE_DSS_CERT01:
        case SSH_KEYTYPE_RSA_CERT01:
        case SSH_KEYTYPE_RSA1:
        case SSH_KEYTYPE_UNKNOWN:
        default:
            SSH_LOG(SSH_LOG_WARN, "Unknown public key protocol %d", type);
            goto fail;
    }

    *pkey = key;
    return SSH_OK;
fail:
    ssh_key_free(key);

    return SSH_ERROR;
}

static int pki_import_cert_buffer(ssh_buffer buffer,
                                  enum ssh_keytypes_e type,
                                  ssh_key *pkey) {
    ssh_buffer cert;
    ssh_string type_s;
    ssh_key key;
    int rc;

    key = ssh_key_new();
    if (key == NULL) {
        return SSH_ERROR;
    }
    cert = ssh_buffer_new();
    if (cert == NULL) {
        ssh_key_free(key);
        return SSH_ERROR;
    }

    key->type = type;
    key->type_c = ssh_key_type_to_char(type);
    key->flags = SSH_KEY_FLAG_PUBLIC;

    /*
     * The cert blob starts with the key type as an ssh_string, but this
     * string has been read out of the buffer to identify the key type.
     * Simply add it again as first element before copying the rest.
     */
    type_s = ssh_string_from_char(key->type_c);
    if (type_s == NULL) {
        goto fail;
    }
    rc = ssh_buffer_add_ssh_string(cert, type_s);
    ssh_string_free(type_s);
    if (rc != 0) {
        goto fail;
    }

    rc = ssh_buffer_add_buffer(cert, buffer);
    if (rc != 0) {
        goto fail;
    }
    key->cert = (void*) cert;

    *pkey = key;
    return SSH_OK;

fail:
    ssh_key_free(key);
    ssh_buffer_free(cert);
    return SSH_ERROR;
}

/**
 * @brief Import a base64 formated public key from a memory c-string.
 *
 * @param[in]  b64_key  The base64 key to format.
 *
 * @param[in]  type     The type of the key to format.
 *
 * @param[out] pkey     A pointer where the allocated key can be stored. You
 *                      need to free the memory.
 *
 * @return              SSH_OK on success, SSH_ERROR on error.
 *
 * @see ssh_key_free()
 */
int ssh_pki_import_pubkey_base64(const char *b64_key,
                                 enum ssh_keytypes_e type,
                                 ssh_key *pkey) {
    ssh_buffer buffer = NULL;
    ssh_string type_s = NULL;
    int rc;

    if (b64_key == NULL || pkey == NULL) {
        return SSH_ERROR;
    }

    buffer = base64_to_bin(b64_key);
    if (buffer == NULL) {
        return SSH_ERROR;
    }

    type_s = ssh_buffer_get_ssh_string(buffer);
    if (type_s == NULL) {
        ssh_buffer_free(buffer);
        return SSH_ERROR;
    }
    ssh_string_free(type_s);

    if (type == SSH_KEYTYPE_RSA_CERT01 ||
        type == SSH_KEYTYPE_DSS_CERT01) {
        rc = pki_import_cert_buffer(buffer, type, pkey);
    } else {
        rc = pki_import_pubkey_buffer(buffer, type, pkey);
    }
    ssh_buffer_free(buffer);

    return rc;
}

/**
 * @internal
 *
 * @brief Import a public key from a ssh string.
 *
 * @param[in]  key_blob The key blob to import as specified in RFC 4253 section
 *                      6.6 "Public Key Algorithms".
 *
 * @param[out] pkey     A pointer where the allocated key can be stored. You
 *                      need to free the memory.
 *
 * @return              SSH_OK on success, SSH_ERROR on error.
 *
 * @see ssh_key_free()
 */
int ssh_pki_import_pubkey_blob(const ssh_string key_blob,
                               ssh_key *pkey) {
    ssh_buffer buffer = NULL;
    ssh_string type_s = NULL;
    enum ssh_keytypes_e type;
    int rc;

    if (key_blob == NULL || pkey == NULL) {
        return SSH_ERROR;
    }

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        SSH_LOG(SSH_LOG_WARN, "Out of memory!");
        return SSH_ERROR;
    }

    rc = ssh_buffer_add_data(buffer, ssh_string_data(key_blob),
            ssh_string_len(key_blob));
    if (rc < 0) {
        SSH_LOG(SSH_LOG_WARN, "Out of memory!");
        goto fail;
    }

    type_s = ssh_buffer_get_ssh_string(buffer);
    if (type_s == NULL) {
        SSH_LOG(SSH_LOG_WARN, "Out of memory!");
        goto fail;
    }

    type = ssh_key_type_from_name(ssh_string_get_char(type_s));
    if (type == SSH_KEYTYPE_UNKNOWN) {
        SSH_LOG(SSH_LOG_WARN, "Unknown key type found!");
        goto fail;
    }
    ssh_string_free(type_s);

    if (type == SSH_KEYTYPE_RSA_CERT01 ||
        type == SSH_KEYTYPE_DSS_CERT01) {
        rc = pki_import_cert_buffer(buffer, type, pkey);
    } else {
        rc = pki_import_pubkey_buffer(buffer, type, pkey);
    }

    ssh_buffer_free(buffer);

    return rc;
fail:
    ssh_buffer_free(buffer);
    ssh_string_free(type_s);

    return SSH_ERROR;
}

/**
 * @brief Import a public key from the given filename.
 *
 * @param[in]  filename The path to the public key.
 *
 * @param[out] pkey     A pointer to store the allocated public key. You need to
 *                      free the memory.
 *
 * @returns SSH_OK on success, SSH_EOF if the file doesn't exist or permission
 *          denied, SSH_ERROR otherwise.
 *
 * @see ssh_key_free()
 */
int ssh_pki_import_pubkey_file(const char *filename, ssh_key *pkey)
{
    enum ssh_keytypes_e type;
    struct stat sb;
    char *key_buf, *p;
    size_t buflen, i;
    const char *q;
    FILE *file;
    off_t size;
    int rc, cmp;

    if (pkey == NULL || filename == NULL || *filename == '\0') {
        return SSH_ERROR;
    }

    file = fopen(filename, "rb");
    if (file == NULL) {
        SSH_LOG(SSH_LOG_WARN, "Error opening %s: %s",
                    filename, strerror(errno));
        return SSH_EOF;
    }

    rc = fstat(fileno(file), &sb);
    if (rc < 0) {
        fclose(file);
        SSH_LOG(SSH_LOG_WARN, "Error gettint stat of %s: %s",
                    filename, strerror(errno));
        switch (errno) {
            case ENOENT:
            case EACCES:
                return SSH_EOF;
        }
        return SSH_ERROR;
    }

    if (sb.st_size > MAX_PUBKEY_SIZE) {
        fclose(file);
        return SSH_ERROR;
    }

    key_buf = malloc(sb.st_size + 1);
    if (key_buf == NULL) {
        fclose(file);
        SSH_LOG(SSH_LOG_WARN, "Out of memory!");
        return SSH_ERROR;
    }

    size = fread(key_buf, 1, sb.st_size, file);
    fclose(file);

    if (size != sb.st_size) {
        SAFE_FREE(key_buf);
        SSH_LOG(SSH_LOG_WARN, "Error reading %s: %s",
                    filename, strerror(errno));
        return SSH_ERROR;
    }
    key_buf[size] = '\0';
    buflen = strlen(key_buf);

    /* Test for new OpenSSH key format first */
    cmp = strncmp(key_buf, OPENSSH_HEADER_BEGIN, strlen(OPENSSH_HEADER_BEGIN));
    if (cmp == 0) {
        *pkey = ssh_pki_openssh_pubkey_import(key_buf);
        SAFE_FREE(key_buf);
        if (*pkey == NULL) {
            SSH_LOG(SSH_LOG_WARN, "Failed to import public key from OpenSSH"
                                  " private key file");
            return SSH_ERROR;
        }
        return SSH_OK;
    }

    /* This the old one-line public key format */
    q = p = key_buf;
    for (i = 0; i < buflen; i++) {
        if (isspace((int)p[i])) {
            p[i] = '\0';
            break;
        }
    }

    type = ssh_key_type_from_name(q);
    if (type == SSH_KEYTYPE_UNKNOWN) {
        SAFE_FREE(key_buf);
        return SSH_ERROR;
    }

    q = &p[i + 1];
    for (; i < buflen; i++) {
        if (isspace((int)p[i])) {
            p[i] = '\0';
            break;
        }
    }

    rc = ssh_pki_import_pubkey_base64(q, type, pkey);
    SAFE_FREE(key_buf);

    return rc;
}

/**
 * @brief Import a base64 formated certificate from a memory c-string.
 *
 * @param[in]  b64_cert  The base64 cert to format.
 *
 * @param[in]  type     The type of the cert to format.
 *
 * @param[out] pkey     A pointer where the allocated key can be stored. You
 *                      need to free the memory.
 *
 * @return              SSH_OK on success, SSH_ERROR on error.
 *
 * @see ssh_key_free()
 */
int ssh_pki_import_cert_base64(const char *b64_cert,
                               enum ssh_keytypes_e type,
                               ssh_key *pkey) {
    return ssh_pki_import_pubkey_base64(b64_cert, type, pkey);
}

/**
 * @internal
 *
 * @brief Import a certificate from a ssh string.
 *
 * @param[in]  cert_blob The cert blob to import as specified in RFC 4253 section
 *                      6.6 "Public Key Algorithms".
 *
 * @param[out] pkey     A pointer where the allocated key can be stored. You
 *                      need to free the memory.
 *
 * @return              SSH_OK on success, SSH_ERROR on error.
 *
 * @see ssh_key_free()
 */
int ssh_pki_import_cert_blob(const ssh_string cert_blob,
                             ssh_key *pkey) {
    return ssh_pki_import_pubkey_blob(cert_blob, pkey);
}

/**
 * @brief Import a certificate from the given filename.
 *
 * @param[in]  filename The path to the certificate.
 *
 * @param[out] pkey     A pointer to store the allocated certificate. You need to
 *                      free the memory.
 *
 * @returns SSH_OK on success, SSH_EOF if the file doesn't exist or permission
 *          denied, SSH_ERROR otherwise.
 *
 * @see ssh_key_free()
 */
int ssh_pki_import_cert_file(const char *filename, ssh_key *pkey)
{
    return ssh_pki_import_pubkey_file(filename, pkey);
}

/**
 * @brief Generates a keypair.
 *
 * @param[in] type      Type of key to create
 *
 * @param[in] parameter Parameter to the creation of key:
 *                      rsa : length of the key in bits (e.g. 1024, 2048, 4096)
 *                      dsa : length of the key in bits (e.g. 1024, 2048, 3072)
 *                      ecdsa : bits of the key (e.g. 256, 384, 521)
 * @param[out] pkey     A pointer to store the allocated private key. You need
 *                      to free the memory.
 *
 * @return              SSH_OK on success, SSH_ERROR on error.
 *
 * @warning             Generating a key pair may take some time.
 */
int ssh_pki_generate(enum ssh_keytypes_e type, int parameter,
        ssh_key *pkey){
    int rc;
    ssh_key key = ssh_key_new();

    if (key == NULL) {
        return SSH_ERROR;
    }

    key->type = type;
    key->type_c = ssh_key_type_to_char(type);
    key->flags = SSH_KEY_FLAG_PRIVATE | SSH_KEY_FLAG_PUBLIC;

    switch(type){
        case SSH_KEYTYPE_RSA:
            rc = pki_key_generate_rsa(key, parameter);
            if(rc == SSH_ERROR)
                goto error;
            break;
        case SSH_KEYTYPE_DSS:
            rc = pki_key_generate_dss(key, parameter);
            if(rc == SSH_ERROR)
                goto error;
            break;
#ifdef HAVE_ECC
        case SSH_KEYTYPE_ECDSA:
            rc = pki_key_generate_ecdsa(key, parameter);
            if (rc == SSH_ERROR) {
                goto error;
            }

            /* Update key type */
            key->type_c = ssh_pki_key_ecdsa_name(key);
            break;
#endif
        case SSH_KEYTYPE_ED25519:
            rc = pki_key_generate_ed25519(key);
            if (rc == SSH_ERROR) {
                goto error;
            }
            break;
        case SSH_KEYTYPE_DSS_CERT01:
        case SSH_KEYTYPE_RSA_CERT01:
        case SSH_KEYTYPE_RSA1:
        case SSH_KEYTYPE_UNKNOWN:
        default:
            goto error;
    }

    *pkey = key;
    return SSH_OK;
error:
    ssh_key_free(key);
    return SSH_ERROR;
}

/**
 * @brief Create a public key from a private key.
 *
 * @param[in]  privkey  The private key to get the public key from.
 *
 * @param[out] pkey     A pointer to store the newly allocated public key. You
 *                      NEED to free the key.
 *
 * @return              SSH_OK on success, SSH_ERROR on error.
 *
 * @see ssh_key_free()
 */
int ssh_pki_export_privkey_to_pubkey(const ssh_key privkey,
                                     ssh_key *pkey)
{
    ssh_key pubkey;

    if (privkey == NULL || !ssh_key_is_private(privkey)) {
        return SSH_ERROR;
    }

    pubkey = pki_key_dup(privkey, 1);
    if (pubkey == NULL) {
        return SSH_ERROR;
    }

    *pkey = pubkey;
    return SSH_OK;
}

/**
 * @internal
 *
 * @brief Create a key_blob from a public key.
 *
 * The "key_blob" is encoded as per RFC 4253 section 6.6 "Public Key
 * Algorithms" for any of the supported protocol 2 key types.
 * Encoding of EC keys is described in RFC 5656 section 3.1 "Key
 * Format".
 *
 * @param[in]  key      A public or private key to create the public ssh_string
 *                      from.
 *
 * @param[out] pblob    A pointer to store the newly allocated key blob. You
 *                      NEED to free it.
 *
 * @return              SSH_OK on success, SSH_ERROR otherwise.
 *
 * @see ssh_string_free()
 */
int ssh_pki_export_pubkey_blob(const ssh_key key,
                               ssh_string *pblob)
{
    ssh_string blob;

    if (key == NULL) {
        return SSH_OK;
    }

    blob = pki_publickey_to_blob(key);
    if (blob == NULL) {
        return SSH_ERROR;
    }

    *pblob = blob;
    return SSH_OK;
}

/**
 * @brief Convert a public key to a base64 encoded key.
 *
 * @param[in] key       The key to hash
 *
 * @param[out] b64_key  A pointer to store the allocated base64 encoded key. You
 *                      need to free the buffer.
 *
 * @return              SSH_OK on success, SSH_ERROR on error.
 *
 * @see ssh_string_free_char()
 */
int ssh_pki_export_pubkey_base64(const ssh_key key,
                                 char **b64_key)
{
    ssh_string key_blob;
    unsigned char *b64;

    if (key == NULL || b64_key == NULL) {
        return SSH_ERROR;
    }

    key_blob = pki_publickey_to_blob(key);
    if (key_blob == NULL) {
        return SSH_ERROR;
    }

    b64 = bin_to_base64(ssh_string_data(key_blob), ssh_string_len(key_blob));
    ssh_string_free(key_blob);
    if (b64 == NULL) {
        return SSH_ERROR;
    }

    *b64_key = (char *)b64;

    return SSH_OK;
}

int ssh_pki_export_pubkey_file(const ssh_key key,
                               const char *filename)
{
    char key_buf[4096];
    char host[256];
    char *b64_key;
    char *user;
    FILE *fp;
    int rc;

    if (key == NULL || filename == NULL || *filename == '\0') {
        return SSH_ERROR;
    }

    user = ssh_get_local_username();
    if (user == NULL) {
        return SSH_ERROR;
    }

    rc = gethostname(host, sizeof(host));
    if (rc < 0) {
        free(user);
        return SSH_ERROR;
    }

    rc = ssh_pki_export_pubkey_base64(key, &b64_key);
    if (rc < 0) {
        free(user);
        return SSH_ERROR;
    }

    rc = snprintf(key_buf, sizeof(key_buf),
                  "%s %s %s@%s\n",
                  key->type_c,
                  b64_key,
                  user,
                  host);
    free(user);
    free(b64_key);
    if (rc < 0) {
        return SSH_ERROR;
    }

    fp = fopen(filename, "wb+");
    if (fp == NULL) {
        return SSH_ERROR;
    }
    rc = fwrite(key_buf, strlen(key_buf), 1, fp);
    if (rc != 1 || ferror(fp)) {
        fclose(fp);
        unlink(filename);
        return SSH_ERROR;
    }
    fclose(fp);

    return SSH_OK;
}

/**
 * @brief Copy the certificate part of a public key into a private key.
 *
 * @param[in]  certkey  The certificate key.
 *
 * @param[in]  privkey  The target private key to copy the certificate to.
 *
 * @returns SSH_OK on success, SSH_ERROR otherwise.
 **/
int ssh_pki_copy_cert_to_privkey(const ssh_key certkey, ssh_key privkey) {
  ssh_buffer cert_buffer;
  int rc;

  if (certkey == NULL || privkey == NULL) {
      return SSH_ERROR;
  }

  if (privkey->cert != NULL) {
      return SSH_ERROR;
  }

  if (certkey->cert == NULL) {
      return SSH_ERROR;
  }

  cert_buffer = ssh_buffer_new();
  if (cert_buffer == NULL) {
      return SSH_ERROR;
  }

  rc = ssh_buffer_add_buffer(cert_buffer, certkey->cert);
  if (rc != 0) {
      ssh_buffer_free(cert_buffer);
      return SSH_ERROR;
  }

  privkey->cert = cert_buffer;
  privkey->cert_type = certkey->type;
  return SSH_OK;
}

int ssh_pki_export_signature_blob(const ssh_signature sig,
                                  ssh_string *sig_blob)
{
    ssh_buffer buf = NULL;
    ssh_string str;
    int rc;

    if (sig == NULL || sig_blob == NULL) {
        return SSH_ERROR;
    }

    buf = ssh_buffer_new();
    if (buf == NULL) {
        return SSH_ERROR;
    }

    str = ssh_string_from_char(sig->type_c);
    if (str == NULL) {
        ssh_buffer_free(buf);
        return SSH_ERROR;
    }

    rc = ssh_buffer_add_ssh_string(buf, str);
    ssh_string_free(str);
    if (rc < 0) {
        ssh_buffer_free(buf);
        return SSH_ERROR;
    }

    str = pki_signature_to_blob(sig);
    if (str == NULL) {
        ssh_buffer_free(buf);
        return SSH_ERROR;
    }

    rc = ssh_buffer_add_ssh_string(buf, str);
    ssh_string_free(str);
    if (rc < 0) {
        ssh_buffer_free(buf);
        return SSH_ERROR;
    }

    str = ssh_string_new(ssh_buffer_get_len(buf));
    if (str == NULL) {
        ssh_buffer_free(buf);
        return SSH_ERROR;
    }

    ssh_string_fill(str, ssh_buffer_get(buf), ssh_buffer_get_len(buf));
    ssh_buffer_free(buf);

    *sig_blob = str;

    return SSH_OK;
}

int ssh_pki_import_signature_blob(const ssh_string sig_blob,
                                  const ssh_key pubkey,
                                  ssh_signature *psig)
{
    ssh_signature sig = NULL;
    enum ssh_keytypes_e type;
    enum ssh_digest_e hash_type;
    ssh_string algorithm = NULL, blob = NULL;
    ssh_buffer buf;
    const char *alg = NULL;
    int rc;

    if (sig_blob == NULL || psig == NULL) {
        return SSH_ERROR;
    }

    buf = ssh_buffer_new();
    if (buf == NULL) {
        return SSH_ERROR;
    }

    rc = ssh_buffer_add_data(buf,
                             ssh_string_data(sig_blob),
                             ssh_string_len(sig_blob));
    if (rc < 0) {
        ssh_buffer_free(buf);
        return SSH_ERROR;
    }

    algorithm = ssh_buffer_get_ssh_string(buf);
    if (algorithm == NULL) {
        ssh_buffer_free(buf);
        return SSH_ERROR;
    }

    alg = ssh_string_get_char(algorithm);
    type = ssh_key_type_from_signature_name(alg);
    hash_type = ssh_key_hash_from_name(alg);
    ssh_string_free(algorithm);

    blob = ssh_buffer_get_ssh_string(buf);
    ssh_buffer_free(buf);
    if (blob == NULL) {
        return SSH_ERROR;
    }

    sig = pki_signature_from_blob(pubkey, blob, type, hash_type);
    ssh_string_free(blob);
    if (sig == NULL) {
        return SSH_ERROR;
    }

    *psig = sig;
    return SSH_OK;
}

int ssh_pki_signature_verify(ssh_session session,
                             ssh_signature sig,
                             const ssh_key key,
                             unsigned char *digest,
                             size_t dlen)
{
    int rc;
#ifdef __EBCDIC__
  char* sigTypeStr;
  char* keyTypeStr;
#endif

#ifdef __EBCDIC__
    sigTypeStr = strdup(sig->type_c);
    if (sigTypeStr == NULL) {
        ssh_set_error(session, SSH_FATAL, "Memory allocation failed for key type");
        return SSH_ERROR;
    }
    keyTypeStr = strdup(key->type_c);
    if (keyTypeStr == NULL) {
        ssh_set_error(session, SSH_FATAL, "Memory allocation failed for key type");
        free(sigTypeStr);
        return SSH_ERROR;
    }
    ssh_string_to_ebcdic(sigTypeStr, sigTypeStr, strlen(sigTypeStr));
    ssh_string_to_ebcdic(keyTypeStr, keyTypeStr, strlen(keyTypeStr));
    SSH_LOG(SSH_LOG_FUNCTIONS,
            "Going to verify a %s type signature",
            sigTypeStr);

    if (key->type != sig->type) {
        SSH_LOG(SSH_LOG_WARN,
                "Can not verify %s signature with %s key",
                sigTypeStr, key->type_c);
        free(sigTypeStr);
        free(keyTypeStr);
        return SSH_ERROR;
    }
    free(sigTypeStr);
    free(keyTypeStr);
#else
    SSH_LOG(SSH_LOG_FUNCTIONS,
            "Going to verify a %s type signature",
            sig->type_c);

    if (key->type != sig->type) {
        SSH_LOG(SSH_LOG_WARN,
                "Can not verify %s signature with %s key",
                sig->type_c, key->type_c);
        return SSH_ERROR;
    }
#endif

    if (key->type == SSH_KEYTYPE_ECDSA) {
#if HAVE_ECC
        unsigned char ehash[EVP_DIGEST_LEN] = {0};
        uint32_t elen;

        evp(key->ecdsa_nid, digest, dlen, ehash, &elen);

#ifdef DEBUG_CRYPTO
        ssh_print_hexa("Hash to be verified with ecdsa",
                       ehash, elen);
#endif

        rc = pki_signature_verify(session,
                                  sig,
                                  key,
                                  ehash,
                                  elen);
#endif
    } else if (key->type == SSH_KEYTYPE_ED25519) {
        rc = pki_signature_verify(session, sig, key, digest, dlen);
    } else {
        unsigned char hash[SHA512_DIGEST_LEN] = {0};
        uint32_t hlen = 0;

        if (sig->type != SSH_KEYTYPE_RSA && sig->hash_type != SSH_DIGEST_AUTO) {
            SSH_LOG(SSH_LOG_TRACE, "Only RSA keys support non-SHA1 hashes.");
            return SSH_ERROR;
        }

        switch (sig->hash_type) {
        case SSH_DIGEST_SHA256:
            sha256(digest, dlen, hash);
            hlen = SHA256_DIGEST_LEN;
            break;
        case SSH_DIGEST_SHA512:
            sha512(digest, dlen, hash);
            hlen = SHA512_DIGEST_LEN;
            break;
        case SSH_DIGEST_SHA1:
        case SSH_DIGEST_AUTO:
            sha1(digest, dlen, hash);
            hlen = SHA_DIGEST_LEN;
            break;
        default:
            SSH_LOG(SSH_LOG_TRACE, "Unknown sig->hash_type: %d", sig->hash_type);
            return SSH_ERROR;
        }
#ifdef DEBUG_CRYPTO
        ssh_print_hexa(key->type == SSH_KEYTYPE_DSS
                       ? "Hash to be verified with DSA"
                       : "Hash to be verified with RSA",
                       hash,
                       hlen);
#endif

        rc = pki_signature_verify(session,
                                  sig,
                                  key,
                                  hash,
                                  hlen);
    }

    return rc;
}

/*
 * This function signs the session id as a string then
 * the content of sigbuf */
ssh_string ssh_pki_do_sign(ssh_session session,
                           ssh_buffer sigbuf,
                           const ssh_key privkey)
{
    struct ssh_crypto_struct *crypto = NULL;
    ssh_signature sig = NULL;
    ssh_string sig_blob;
    ssh_string session_id;
    int rc;

    if (privkey == NULL || !ssh_key_is_private(privkey)) {
        return NULL;
    }

    crypto = ssh_packet_get_current_crypto(session, SSH_DIRECTION_BOTH);
    session_id = ssh_string_new(crypto->digest_len);
    if (session_id == NULL) {
        return NULL;
    }
    ssh_string_fill(session_id, crypto->session_id, crypto->digest_len);

    if (privkey->type == SSH_KEYTYPE_ECDSA) {
#ifdef HAVE_ECC
        unsigned char ehash[EVP_DIGEST_LEN] = {0};
        uint32_t elen;
        EVPCTX ctx;

        ctx = evp_init(privkey->ecdsa_nid);
        if (ctx == NULL) {
            ssh_string_free(session_id);
            return NULL;
        }

        evp_update(ctx, session_id, ssh_string_len(session_id) + 4);
        evp_update(ctx, ssh_buffer_get(sigbuf), ssh_buffer_get_len(sigbuf));
        evp_final(ctx, ehash, &elen);

#ifdef DEBUG_CRYPTO
        ssh_print_hexa("Hash being signed", ehash, elen);
#endif

        sig = pki_do_sign(privkey, ehash, elen);
#endif
    } else if (privkey->type == SSH_KEYTYPE_ED25519){
        ssh_buffer buf;

        buf = ssh_buffer_new();
        if (buf == NULL) {
            ssh_string_free(session_id);
            return NULL;
        }

        ssh_buffer_set_secure(buf);
        rc = ssh_buffer_pack(buf,
                             "SP",
                             session_id,
                             ssh_buffer_get_len(sigbuf), ssh_buffer_get(sigbuf));
        if (rc != SSH_OK) {
            ssh_string_free(session_id);
            ssh_buffer_free(buf);
            return NULL;
        }

        sig = pki_do_sign(privkey,
                          ssh_buffer_get(buf),
                          ssh_buffer_get_len(buf));
        ssh_buffer_free(buf);
    } else {
        unsigned char hash[SHA512_DIGEST_LEN] = {0};
        uint32_t hlen = 0;
        enum ssh_digest_e hash_type;
        ssh_buffer buf;

        buf = ssh_buffer_new();
        if (buf == NULL) {
            ssh_string_free(session_id);
            return NULL;
        }

        ssh_buffer_set_secure(buf);
        rc = ssh_buffer_pack(buf,
                             "SP",
                             session_id,
                             ssh_buffer_get_len(sigbuf), ssh_buffer_get(sigbuf));
        if (rc != SSH_OK) {
            ssh_string_free(session_id);
            ssh_buffer_free(buf);
            return NULL;
        }

        hash_type = ssh_key_type_to_hash(session, privkey->type);
        switch (hash_type) {
        case SSH_DIGEST_SHA256:
            sha256(ssh_buffer_get(buf), ssh_buffer_get_len(buf), hash);
            hlen = SHA256_DIGEST_LEN;
            break;
        case SSH_DIGEST_SHA512:
            sha512(ssh_buffer_get(buf), ssh_buffer_get_len(buf), hash);
            hlen = SHA512_DIGEST_LEN;
            break;
        case SSH_DIGEST_SHA1:
        case SSH_DIGEST_AUTO:
            sha1(ssh_buffer_get(buf), ssh_buffer_get_len(buf), hash);
            hlen = SHA_DIGEST_LEN;
            break;
        default:
            SSH_LOG(SSH_LOG_TRACE, "Unknown hash algorithm for type: %d",
                    hash_type);
            ssh_string_free(session_id);
            ssh_buffer_free(buf);
            return NULL;
        }
        ssh_buffer_free(buf);

#ifdef DEBUG_CRYPTO
        ssh_print_hexa("Hash being signed", hash, hlen);
#endif

        sig = pki_do_sign_hash(privkey, hash, hlen, hash_type);
    }
    ssh_string_free(session_id);
    if (sig == NULL) {
        return NULL;
    }

    rc = ssh_pki_export_signature_blob(sig, &sig_blob);
    ssh_signature_free(sig);
    if (rc < 0) {
        return NULL;
    }

    return sig_blob;
}

#ifndef _WIN32
ssh_string ssh_pki_do_sign_agent(ssh_session session,
                                 struct ssh_buffer_struct *buf,
                                 const ssh_key pubkey)
{
    struct ssh_crypto_struct *crypto = NULL;
    ssh_string session_id;
    ssh_string sig_blob;
    ssh_buffer sig_buf;
    int rc;

    crypto = ssh_packet_get_current_crypto(session, SSH_DIRECTION_BOTH);

    /* prepend session identifier */
    session_id = ssh_string_new(crypto->digest_len);
    if (session_id == NULL) {
        return NULL;
    }
    ssh_string_fill(session_id, crypto->session_id, crypto->digest_len);

    sig_buf = ssh_buffer_new();
    if (sig_buf == NULL) {
        ssh_string_free(session_id);
        return NULL;
    }

    rc = ssh_buffer_add_ssh_string(sig_buf, session_id);
    if (rc < 0) {
        ssh_string_free(session_id);
        ssh_buffer_free(sig_buf);
        return NULL;
    }
    ssh_string_free(session_id);

    /* append out buffer */
    if (ssh_buffer_add_buffer(sig_buf, buf) < 0) {
        ssh_buffer_free(sig_buf);
        return NULL;
    }

    /* create signature */
    sig_blob = ssh_agent_sign_data(session, pubkey, sig_buf);

    ssh_buffer_free(sig_buf);

    return sig_blob;
}
#endif /* _WIN32 */

#ifdef WITH_SERVER
ssh_string ssh_srv_pki_do_sign_sessionid(ssh_session session,
                                         const ssh_key privkey)
{
    struct ssh_crypto_struct *crypto = NULL;
    ssh_signature sig = NULL;
    ssh_string sig_blob;
    int rc;

    if (session == NULL || privkey == NULL || !ssh_key_is_private(privkey)) {
        return NULL;
    }

    crypto = session->next_crypto ? session->next_crypto :
                                    session->current_crypto;

    if (crypto->secret_hash == NULL){
        ssh_set_error(session,SSH_FATAL,"Missing secret_hash");
        return NULL;
    }

    if (privkey->type == SSH_KEYTYPE_ECDSA) {
#ifdef HAVE_ECC
        unsigned char ehash[EVP_DIGEST_LEN] = {0};
        uint32_t elen;

        evp(privkey->ecdsa_nid, crypto->secret_hash, crypto->digest_len,
            ehash, &elen);

#ifdef DEBUG_CRYPTO
        ssh_print_hexa("Hash being signed", ehash, elen);
#endif

        sig = pki_do_sign_sessionid(privkey, ehash, elen);
        if (sig == NULL) {
            return NULL;
        }
#endif
    } else if (privkey->type == SSH_KEYTYPE_ED25519) {
        sig = ssh_signature_new();
        if (sig == NULL){
            return NULL;
        }

        sig->type = privkey->type;
        sig->type_c = privkey->type_c;

        rc = pki_ed25519_sign(privkey,
                              sig,
                              crypto->secret_hash,
                              crypto->digest_len);
        if (rc != SSH_OK){
            ssh_signature_free(sig);
            sig = NULL;
        }
    } else {
        unsigned char hash[SHA512_DIGEST_LEN] = {0};
        uint32_t hlen = 0;
        enum ssh_digest_e hash_type;

        hash_type = ssh_key_type_to_hash(session, privkey->type);
        switch (hash_type) {
        case SSH_DIGEST_SHA256:
            sha256(crypto->secret_hash, crypto->digest_len, hash);
            hlen = SHA256_DIGEST_LEN;
            break;
        case SSH_DIGEST_SHA512:
            sha512(crypto->secret_hash, crypto->digest_len, hash);
            hlen = SHA512_DIGEST_LEN;
            break;
        case SSH_DIGEST_SHA1:
        case SSH_DIGEST_AUTO:
            sha1(crypto->secret_hash, crypto->digest_len, hash);
            hlen = SHA_DIGEST_LEN;
            break;
        default:
            SSH_LOG(SSH_LOG_TRACE, "Unknown sig->type: %d", hash_type);
            return NULL;
        }


#ifdef DEBUG_CRYPTO
        ssh_print_hexa("Hash being signed", hash, hlen);
#endif

        sig = pki_do_sign_sessionid_hash(privkey, hash, hlen, hash_type);
        if (sig == NULL) {
            return NULL;
        }
    }

    rc = ssh_pki_export_signature_blob(sig, &sig_blob);
    ssh_signature_free(sig);
    if (rc < 0) {
        return NULL;
    }

    return sig_blob;
}
#endif /* WITH_SERVER */

/**
 * @}
 */
