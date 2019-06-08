// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_MINING_H
#define BITCOIN_RPC_MINING_H

#include <script/script.h>

#include <string>

#include <univalue.h>

/** Generate blocks (mine) */
UniValue generateBlocks(std::shared_ptr<CReserveScript> coinbaseScript, int nGenerate, uint64_t nMaxTries, bool keepScript, uint8_t nAlgo);

/** Check bounds on a command line confirm target */
unsigned int ParseConfirmTarget(const UniValue& value);

/* Creation and submission of auxpow blocks.  */
UniValue AuxMiningCreateBlock(const CScript& scriptPubKey, const uint8_t nAlgo);
bool AuxMiningSubmitBlock(const std::string& hashHex,
                          const std::string& auxpowHex,
                          const int nAuxPoWVersion);

#endif
