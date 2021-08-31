/**
 * @file   TYPDEF.h
 * @brief  Defines for fixed length data types
 * @author limes datentechnik gmbh
 * @date   03.09.2019
 * @copyright limes datentechnik gmbh
 **********************************************************************/

#ifdef __cplusplus
   extern "C" {
#endif

#ifndef INC_TYPDEF_H
#define INC_TYPDEF_H

/**********************************************************************/

#include <inttypes.h>

/**********************************************************************/

typedef  int8_t      I08;     /**< @brief signed 8 bit integer*/
typedef  int16_t     I16;     /**< @brief signed 16 bit integer*/
typedef  int32_t     I32;     /**< @brief signed 32 bit integer*/
typedef  int64_t     I64;     /**< @brief signed 64 bit integer*/
typedef  uint8_t     U08;     /**< @brief unsigned 8 bit integer*/
typedef  uint16_t    U16;     /**< @brief unsigned 16 bit integer*/
typedef  uint32_t    U32;     /**< @brief unsigned 32 bit integer*/
typedef  uint64_t    U64;     /**< @brief unsigned 64 bit integer*/
typedef  char        C08;     /**< @brief 8 bit character value*/
typedef  U08         W08;     /**< @brief 8 bit word (unsigned)*/
typedef  U16         W16;     /**< @brief 16 bit word (unsigned)*/
typedef  U32         W32;     /**< @brief 32 bit word (unsigned)*/
typedef  U64         W64;     /**< @brief 64 bit word (unsigned)*/
typedef  float       F32;     /**< @brief 32 bit float*/
typedef  double      F64;     /**< @brief 64 bit float*/
typedef  uintptr_t   UIP;     /**< @brief unsigned integer pointer type*/
typedef  intptr_t    SIP;     /**< @brief signed integer pointer type*/

/**********************************************************************/

#endif /* INC_TYPDEF_H */

#ifdef __cplusplus
   }
#endif

