/**
 * @file  CRYPTHDL.h
 * @brief  Crypto handle declaration shared between all crypto modules
 * @author limes datentechnik gmbh
 * @date  17.08.2020
 * @copyright limes datentechnik gmbh
 **********************************************************************/

#ifndef INC_CRYPTHDL_H
#define INC_CRYPTHDL_H

/**********************************************************************/

// NOTE: Copy to libssh/include/libssh/limes/ after changing this header

#include "libssh/limes/TYPDEF.h"

/**********************************************************************/

typedef enum SymCryptoAlgo {
   NONE,
   AES128_ECB_NOPAD,  AES128_ECB_PKCS,
   AES128_CBC_NOPAD,  AES128_CBC_PKCS,
   AES128_OFB,
   AES128_CFB,
   AES128_CTR,
   AES192_ECB_NOPAD, AES192_ECB_PKCS,
   AES192_CBC_NOPAD, AES192_CBC_PKCS,
   AES192_OFB,
   AES192_CFB,
   AES192_CTR,
   AES256_ECB_NOPAD, AES256_ECB_PKCS,
   AES256_CBC_NOPAD, AES256_CBC_PKCS,
   AES256_OFB,
   AES256_CFB,
   AES256_CTR,
   TDES_ECB_NOPAD, TDES_ECB_PKCS,
   TDES_CBC_NOPAD, TDES_CBC_PKCS,
   TDES_OFB,
   TDES_CFB,
   CAST5_ECB_NOPAD, CAST5_ECB_PKCS,
   CAST5_CBC_NOPAD, CAST5_CBC_PKCS,
   CAST5_OFB,
   CAST5_CFB,
   IDEA_ECB_NOPAD, IDEA_ECB_PKCS,
   IDEA_CBC_NOPAD, IDEA_CBC_PKCS,
   IDEA_OFB,
   IDEA_CFB,
   BLOWFISH_ECB_NOPAD, BLOWFISH_ECB_PKCS,
   BLOWFISH_CBC_NOPAD, BLOWFISH_CBC_PKCS,
   BLOWFISH_OFB,
   BLOWFISH_CFB,
   CAMELLIA128_ECB_NOPAD, CAMELLIA128_ECB_PKCS,
   CAMELLIA128_CBC_NOPAD, CAMELLIA128_CBC_PKCS,
   CAMELLIA128_OFB,
   CAMELLIA128_CFB,
   CAMELLIA192_ECB_NOPAD, CAMELLIA192_ECB_PKCS,
   CAMELLIA192_CBC_NOPAD, CAMELLIA192_CBC_PKCS,
   CAMELLIA192_OFB,
   CAMELLIA192_CFB,
   CAMELLIA256_ECB_NOPAD, CAMELLIA256_ECB_PKCS,
   CAMELLIA256_CBC_NOPAD, CAMELLIA256_CBC_PKCS,
   CAMELLIA256_OFB,
   CAMELLIA256_CFB
} SymCryptoAlgo;

typedef enum CryptoImpl {
   CRYPTO_SOFTWARE,
   CRYPTO_HARDWARE,
   CRYPTO_OPENSSL
} CryptoImpl;

typedef enum CryptoPadding {
   PADDING_NONE,
   PADDING_PKCS,
} CryptoPadding;

typedef struct CryptoHdl {
   /**
    * (Re)Initializes the crypto handle with the key and IV
    * @return 0 on success
    */
   U32    (*init)      (struct CryptoHdl* self, U32 uiKeyLen, const U08* pcKey, U32 uiIvLen, const U08* pcIv);
   // NOTE: piOutLen can be up to: uiInLen + BLOCKSIZE - 1
   /**
    * De- or encrypt uiInLen bytes from pcIn and writes the output to pcOut.
    * The length of input data be arbitrary, but passing a multiples of the
    *  block size will performs better.
    *
    * FOR BLOCK CIPHERS:
    *
    * If the handle was initialized with a block cipher mode (e.g. ECB, CBC),
    * the output might be shorter or longer than the input. Therefore, the
    * output buffer pcOut must have a size of at least uiInLen + BLOCKSIZE - 1
    * bytes when encrypting or uiInLen + BLOCKSIZE when decrypting. Passing a
    * smaller buffer is undefined behavior.
    *
    * If no padding is used, the total length of input data that was passed to
    * the update() function since last initialization must be a multiple of the
    * block size. Otherwise, the final() function returns an error.
    *
    * The final() function must be called after the last byte of input has been
    * processed, if padding is used or if the total input length is not a multiple
    * of the block size. Not calling final() will result in data loss in these
    * cases.
    *
    * FOR STREAM CIPHERS:
    *
    * If the handle was initialized with a stream cipher mode (e.g. OFB, CFB),
    * the input can have arbitrary length. The number of bytes written to the
    * output buffer is equal to uiInLen if the function succeeds. Calling final()
    * is optional.
    *
    * @param self Handle
    * @param piOutLen Contains the number of bytes written to pcOut if function succeeds,
    *                 optional (can be NULL, but is not recommended unless all input is multiple of block length)
    * @param pcOut Output buffer
    * @param uiInLen Input length
    * @param pcIn Input Buffer
    * @return 0 on success
    */
   U32    (*update)    (struct CryptoHdl* self, U32* piOutLen, U08* pcOut, U32 uiInLen, const U08* pcIn);
   /**
    * Writes any remaining output to pcOut, adding or removing padding if necessary.
    *
    * IMPORTANT: The output buffer size must be at least BLOCKSIZE.
    *
    * Note that this function can fail on decryption if the padding is invalid.
    *
    * @param self Handle
    * @param piOutLen Contains the number of bytes written to pcOut if function succeeds,
    *                 optional (can be NULL, but is not recommended unless all input is multiple of block length)
    * @param pcOut Outout buffer
    * @return 0 = OK, 1 = bad input/crypto error, 2 = invalid padding
    */
   U32    (*final)     (struct CryptoHdl* self, U32* piOutLen, U08* pcOut);
   /**
    * Releases any ressources used by the specified handle
    */
   void   (*free)      (struct CryptoHdl** self);
   /**
    * Returns the number of bytes per block which depends on cipher algo and mode
    */
   U32    (*blockLen)  (struct CryptoHdl* self);
   /**
    * Returns the key length which depends on the cipher algo
    */
   U32    (*keyLen)    (struct CryptoHdl* self);
   /**
    * Returns the IV length which depends on the cipher algo
    */
   U32    (*ivLen)     (struct CryptoHdl* self);
   /**
    * Returns a human-readable for the cipher algo and mode
    */
   const char* (*name) (struct CryptoHdl* self);
   /**
    * Returns the type of implementation used (OpenSSL, Hardware, Software (custom implementation))
    */
   CryptoImpl  (*impl) (struct CryptoHdl* self);
} CryptoHdl;

typedef CryptoHdl* (CryptoConstructor)(SymCryptoAlgo enAlgo, U32 uiKeyLen, const U08* pcKey, U32 uiIvLen, const U08* pcIv);

struct SymCryptoFunctions {
   CryptoConstructor* encryptInit;
   CryptoConstructor* decryptInit;
   SymCryptoAlgo algorithm;
};

// NOTE: Copy to libssh/include/libssh/limes/ after changing this header

/**********************************************************************/

#endif /* INC_CRYPTHDL_H */
