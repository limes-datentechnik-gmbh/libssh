#ifndef _LIMES_H
#define _LIMES_H

#if defined _WIN32 || defined __CYGWIN__
  #ifdef LIBSSH_STATIC
    #define LIBSSH_API
  #else
    #ifdef LIBSSH_EXPORTS
      #ifdef __GNUC__
        #define LIBSSH_API __attribute__((dllexport))
      #else
        #define LIBSSH_API __declspec(dllexport)
      #endif
    #else
      #ifdef __GNUC__
        #define LIBSSH_API __attribute__((dllimport))
      #else
        #define LIBSSH_API __declspec(dllimport)
      #endif
    #endif
  #endif
#else
  #if __GNUC__ >= 4 && !defined(__OS2__)
    #define LIBSSH_API __attribute__((visibility("default")))
  #else
    #define LIBSSH_API
  #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SymCryptoFunctions SymCryptoFunctions;

LIBSSH_API void set_symmetric_crypto(const SymCryptoFunctions* funcs);

#ifdef __cplusplus
}
#endif
#endif /* _LIBSSH_H */
