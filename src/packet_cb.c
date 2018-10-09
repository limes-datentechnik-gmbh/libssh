/*
 * packet.c - packet building functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2011      Aris Adamantiadis
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

#include <stdlib.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "libssh/priv.h"
#include "libssh/buffer.h"
#include "libssh/crypto.h"
#include "libssh/dh.h"
#include "libssh/misc.h"
#include "libssh/packet.h"
#include "libssh/pki.h"
#include "libssh/session.h"
#include "libssh/socket.h"
#include "libssh/ssh2.h"
#include "libssh/curve25519.h"

/**
 * @internal
 *
 * @brief Handle a SSH_DISCONNECT packet.
 */
SSH_PACKET_CALLBACK(ssh_packet_disconnect_callback){
  int rc;
  uint32_t code = 0;
  char *error = NULL;
  ssh_string error_s;
  (void)user;
  (void)type;

  rc = ssh_buffer_get_u32(packet, &code);
  if (rc != 0) {
    code = ntohl(code);
  }

  error_s = ssh_buffer_get_ssh_string(packet);
  if (error_s != NULL) {
    error = ssh_string_utf8_to_local(session, ssh_string_to_char(error_s));
    ssh_string_free(error_s);
  }
#ifdef __EBCDIC__
  //if (error != NULL) {
  //  ssh_string_to_ebcdic(error, error, strlen(error));
  //}
#endif
  SSH_LOG(SSH_LOG_PACKET, "Received SSH_MSG_DISCONNECT %d:%s",
                          code, error != NULL ? error : "no error");
  ssh_set_error(session, SSH_FATAL,
      "Received SSH_MSG_DISCONNECT: %d:%s",
      code, error != NULL ? error : "no error");
  SAFE_FREE(error);

  ssh_socket_close(session->socket);
  session->alive = 0;
  session->session_state = SSH_SESSION_STATE_ERROR;
  /* TODO: handle a graceful disconnect */
  return SSH_PACKET_USED;
}

/**
 * @internal
 *
 * @brief Handle a SSH_IGNORE and SSH_DEBUG packet.
 */
SSH_PACKET_CALLBACK(ssh_packet_ignore_callback){
    (void)session; /* unused */
	(void)user;
	(void)type;
	(void)packet;
	SSH_LOG(SSH_LOG_PROTOCOL,"Received %s packet",type==SSH2_MSG_IGNORE ? "SSH_MSG_IGNORE" : "SSH_MSG_DEBUG");
	/* TODO: handle a graceful disconnect */
	return SSH_PACKET_USED;
}

SSH_PACKET_CALLBACK(ssh_packet_dh_reply){
  int rc;
  (void)type;
  (void)user;
  SSH_LOG(SSH_LOG_PROTOCOL,"Received SSH_KEXDH_REPLY");
  if (session->session_state != SSH_SESSION_STATE_DH ||
		session->dh_handshake_state != DH_STATE_INIT_SENT){
	ssh_set_error(session,SSH_FATAL,"ssh_packet_dh_reply called in wrong state : %d:%d",
			session->session_state,session->dh_handshake_state);
	goto error;
  }
  switch(session->next_crypto->kex_type){
    case SSH_KEX_DH_GROUP1_SHA1:
    case SSH_KEX_DH_GROUP14_SHA1:
      rc=ssh_client_dh_reply(session, packet);
      break;
#ifdef HAVE_ECDH
    case SSH_KEX_ECDH_SHA2_NISTP256:
    case SSH_KEX_ECDH_SHA2_NISTP384:
    case SSH_KEX_ECDH_SHA2_NISTP521:
      rc = ssh_client_ecdh_reply(session, packet);
      break;
#endif
#ifdef HAVE_CURVE25519
    case SSH_KEX_CURVE25519_SHA256:
    case SSH_KEX_CURVE25519_SHA256_LIBSSH_ORG:
      rc = ssh_client_curve25519_reply(session, packet);
      break;
#endif
    default:
      ssh_set_error(session,SSH_FATAL,"Wrong kex type in ssh_packet_dh_reply");
      goto error;
  }
  if(rc==SSH_OK) {
    session->dh_handshake_state = DH_STATE_NEWKEYS_SENT;
    return SSH_PACKET_USED;
  }
error:
  session->session_state=SSH_SESSION_STATE_ERROR;
  return SSH_PACKET_USED;
}

SSH_PACKET_CALLBACK(ssh_packet_newkeys){
  ssh_string sig_blob = NULL;
  int rc;
#ifdef __EBCDIC__
  char* str;
#endif
  (void)packet;
  (void)user;
  (void)type;
  SSH_LOG(SSH_LOG_PROTOCOL, "Received SSH_MSG_NEWKEYS");

  if (session->session_state != SSH_SESSION_STATE_DH ||
      session->dh_handshake_state != DH_STATE_NEWKEYS_SENT) {
      ssh_set_error(session,
                    SSH_FATAL,
                    "ssh_packet_newkeys called in wrong state : %d:%d",
                    session->session_state,session->dh_handshake_state);
      goto error;
  }

  if(session->server){
    /* server things are done in server.c */
    session->dh_handshake_state=DH_STATE_FINISHED;
  } else {
    ssh_key server_key;

    /* client */
    rc = ssh_make_sessionid(session);
    if (rc != SSH_OK) {
      goto error;
    }

    /*
     * Set the cryptographic functions for the next crypto
     * (it is needed for ssh_generate_session_keys for key lengths)
     */
    rc = crypt_set_algorithms_client(session);
    if (rc < 0) {
        goto error;
    }

    if (ssh_generate_session_keys(session) < 0) {
      goto error;
    }

    /* Verify the host's signature. FIXME do it sooner */
    sig_blob = session->next_crypto->dh_server_signature;
    session->next_crypto->dh_server_signature = NULL;

#ifdef DEBUG_CRYPTO
    ssh_print_hexa("Server signature: ", ssh_string_data(sig_blob), ssh_string_len(sig_blob));
    ssh_print_hexa("Server Public Key: ", ssh_string_data(session->next_crypto->server_pubkey), ssh_string_len(session->next_crypto->server_pubkey));
#endif

    /* get the server public key */
    server_key = ssh_dh_get_next_server_publickey(session);
    if (server_key == NULL) {
        return SSH_ERROR;
    }

    /* check if public key from server matches user preferences */
    if (session->opts.wanted_methods[SSH_HOSTKEYS]) {
#ifdef __EBCDIC__
        str = strdup(server_key->type_c);
        if (str == NULL) {
            ssh_set_error(session, SSH_FATAL, "Memory allocation failed for key type");
            ssh_key_free(key);
            return -1;
        }
        ssh_string_to_ebcdic(str, str, strlen(str));
        if(!ssh_match_group(session->opts.wanted_methods[SSH_HOSTKEYS],
                            str)) {
            ssh_set_error(session,
                          SSH_FATAL,
                          "Public key from server (%s) doesn't match user "
                          "preference (%s)",
                          str,
                          session->opts.wanted_methods[SSH_HOSTKEYS]);
            free(str);
            ssh_key_free(key);
            return -1;
        }
        free(str);
#else
        if(!ssh_match_group(session->opts.wanted_methods[SSH_HOSTKEYS],
                            server_key->type_c)) {
            ssh_set_error(session,
                          SSH_FATAL,
                          "Public key from server (%s) doesn't match user "
                          "preference (%s)",
                          server_key->type_c,
                          session->opts.wanted_methods[SSH_HOSTKEYS]);
            return -1;
        }
#endif /* __EBCDIC */
    }

    rc = ssh_pki_signature_verify_blob(session,
                                       sig_blob,
                                       server_key,
                                       session->next_crypto->secret_hash,
                                       session->next_crypto->digest_len);
    ssh_string_burn(sig_blob);
    ssh_string_free(sig_blob);
    sig_blob = NULL;
    if (rc == SSH_ERROR) {
      goto error;
    }
    SSH_LOG(SSH_LOG_PROTOCOL,"Signature verified and valid");

    /*
     * Once we got SSH2_MSG_NEWKEYS we can switch next_crypto and
     * current_crypto
     */
    if (session->current_crypto) {
      crypto_free(session->current_crypto);
      session->current_crypto=NULL;
    }

    /* FIXME later, include a function to change keys */
    session->current_crypto = session->next_crypto;

    session->next_crypto = crypto_new();
    if (session->next_crypto == NULL) {
      ssh_set_error_oom(session);
      goto error;
    }
    session->next_crypto->session_id = malloc(session->current_crypto->digest_len);
    if (session->next_crypto->session_id == NULL) {
      ssh_set_error_oom(session);
      goto error;
    }
    memcpy(session->next_crypto->session_id, session->current_crypto->session_id,
            session->current_crypto->digest_len);
    if (session->current_crypto->in_cipher->set_decrypt_key(session->current_crypto->in_cipher, session->current_crypto->decryptkey,
        session->current_crypto->decryptIV) < 0) {
      goto error;
    }
    if (session->current_crypto->out_cipher->set_encrypt_key(session->current_crypto->out_cipher, session->current_crypto->encryptkey,
        session->current_crypto->encryptIV) < 0) {
      goto error;
    }
  }
  session->dh_handshake_state = DH_STATE_FINISHED;
  session->ssh_connection_callback(session);
	return SSH_PACKET_USED;
error:
	session->session_state=SSH_SESSION_STATE_ERROR;
	return SSH_PACKET_USED;
}

/**
 * @internal
 * @brief handles a SSH_SERVICE_ACCEPT packet
 *
 */
SSH_PACKET_CALLBACK(ssh_packet_service_accept){
	(void)packet;
	(void)type;
	(void)user;

	session->auth_service_state=SSH_AUTH_SERVICE_ACCEPTED;
	SSH_LOG(SSH_LOG_PACKET,
	      "Received SSH_MSG_SERVICE_ACCEPT");

	return SSH_PACKET_USED;
}
