// Copyright (c) 2018 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBALTOKEN_HARDFORK_PARAMS_H
#define GLOBALTOKEN_HARDFORK_PARAMS_H

#include <arith_uint256.h>

arith_uint256 GetAlgoPowLimit(int algo);
bool IsHardForkActivated(uint32_t height);
int64_t GetPoWTargetTimeSpan(uint32_t height);
int64_t GetPoWTargetSpacing(uint32_t height);

#endif // GLOBALTOKEN_HARDFORK_PARAMS_H
