// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2018 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>

#include <stdint.h>

enum {
    RETARGETING_LAST = 0,
    RETARGETING_NEXT = 1
};

class CBlockHeader;
class CBlockIndex;
class CChainParams;
class CEquihashBlockHeader;
class uint256;

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&, uint8_t algo);
unsigned int GetNextWorkRequiredV1(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&, uint8_t algo);
unsigned int GetNextWorkRequiredV2(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&, uint8_t algo);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);

/** Check whether the Equihash solution in a block header is valid */
bool CheckEquihashSolution(const CEquihashBlockHeader *pblock, const CChainParams&, bool fisZhash, const std::string stateString);
bool CheckEquihashSolution(const CBlockHeader *pblock, const CChainParams&);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&, uint8_t algo);
const CBlockIndex* GetLastBlockIndexForAlgo(const CBlockIndex* pindex, uint8_t algo);
const CBlockIndex* GetNextBlockIndexForAlgo(const CBlockIndex* pindex, uint8_t algo);

/**
 * Check proof-of-work of a block header, taking auxpow into account.
 * @param block The block header.
 * @param params Consensus parameters.
 * @param ehsolutionvalid boolean set to false if equihash solution fails
 * @return True iff the PoW is correct.
 */
bool CheckProofOfWork(const CBlockHeader& block, const Consensus::Params& params);
bool CheckProofOfWork(const CBlockHeader& block, const Consensus::Params& params, bool &ehsolutionvalid);

/** Calculations */
int CalculateDiffRetargetingBlock(const CBlockIndex* pindex, int retargettype, uint8_t algo, const Consensus::Params&);

#endif // BITCOIN_POW_H
