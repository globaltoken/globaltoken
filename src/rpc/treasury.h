// Copyright (c) 2020 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_TREASURY_H
#define BITCOIN_RPC_TREASURY_H
#include <stdint.h>

class UniValue;

/** Treasury Mempool information to JSON */
UniValue treasurymempoolInfoToJSON();

#endif // BITCOIN_RPC_TREASURY_H
