// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2009-2017 The DigiByte Core developers
// Copyright (c) 2018 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <globaltoken/hardfork.h>
#include <primitives/block.h>
#include <uint256.h>
#include <streams.h>
#include <crypto/algos/equihash/equihash.h>

#include <globaltoken/hardfork.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, int algo)
{
    if(IsHardForkActivated((pindexLast->nHeight)+1))
		return GetNextWorkRequiredV2(pindexLast, pblock, params, algo);
	else
		return GetNextWorkRequiredV1(pindexLast, pblock, params, algo);
}

unsigned int GetNextWorkRequiredV1(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, int algo)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = GetAlgoPowLimit(ALGO_SHA256D).GetCompact(); // Before the Hardfork starts, there is just SHA256D

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int GetNextWorkRequiredV2(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, int algo)
{

	unsigned int npowWorkLimit = GetAlgoPowLimit(algo).GetCompact();

	// Genesis block
	if (pindexLast == nullptr)
		return npowWorkLimit;

	if (Params().NetworkIDString() == CBaseChainParams::TESTNET)
	{
		// Special difficulty rule for testnet:
		// If the new block's timestamp is more than 2* 10 minutes
		// then allow mining of a min-difficulty block.
		if (pblock->nTime > pindexLast->nTime + params.nPowTargetSpacingV2*2)
			return npowWorkLimit;
		else
		{
			// Return the last non-special-min-difficulty-rules-block
			const CBlockIndex* pindex = pindexLast;
			while (pindex->pprev && pindex->nHeight % params.nInterval != 0 && pindex->nBits == npowWorkLimit)
				pindex = pindex->pprev;
			return pindex->nBits;
		}
	}

	// find first block in averaging interval
	// Go back by what we want to be nAveragingInterval blocks per algo
	const CBlockIndex* pindexFirst = pindexLast;
	for (int i = 0; pindexFirst && i < NUM_ALGOS*params.nAveragingInterval; i++)
	{
		pindexFirst = pindexFirst->pprev;
	}
	const CBlockIndex* pindexPrevAlgo = GetLastBlockIndexForAlgo(pindexLast, algo);
	if (pindexPrevAlgo == nullptr || pindexFirst == nullptr)
		return npowWorkLimit; // not enough blocks available

	// Limit adjustment step
	// Use medians to prevent time-warp attacks
	int64_t nActualTimespan = pindexLast->GetMedianTimePast() - pindexFirst->GetMedianTimePast();
	nActualTimespan = params.nAveragingTargetTimespan + (nActualTimespan - params.nAveragingTargetTimespan)/6;
	if (nActualTimespan < params.nMinActualTimespan)
		nActualTimespan = params.nMinActualTimespan;
	if (nActualTimespan > params.nMaxActualTimespan)
		nActualTimespan = params.nMaxActualTimespan;

	// Global retarget
	arith_uint256 bnNew;
	bnNew.SetCompact(pindexPrevAlgo->nBits);
	bnNew *= nActualTimespan;
	bnNew /= params.nAveragingTargetTimespan;

	// Per-algo retarget
	int nAdjustments = pindexPrevAlgo->nHeight - pindexLast->nHeight + NUM_ALGOS - 1;
	if (nAdjustments > 0)
	{
		for (int i = 0; i < nAdjustments; i++)
		{
			bnNew *= 100;
			bnNew /= 100 + params.nLocalDifficultyAdjustment;
		}
	}
	if (nAdjustments < 0)
	{
		for (int i = 0; i < -nAdjustments; i++)
		{
			bnNew *= 100 + params.nLocalDifficultyAdjustment;
			bnNew /= 100;
		}
	}

	if (bnNew > GetAlgoPowLimit(algo))
		bnNew = GetAlgoPowLimit(algo);

	return bnNew.GetCompact();
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = GetAlgoPowLimit(ALGO_SHA256D);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckEquihashSolution(const CBlockHeader *pblock, const CChainParams& params)
{
    unsigned int n = params.EquihashN();
    unsigned int k = params.EquihashK();

    // Hash state
    crypto_generichash_blake2b_state state;
    EhInitialiseState(n, k, state);

    // I = the block header minus nonce and solution.
    CEquihashInput I{*pblock};
    // I||V
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    ss << pblock->nNonce;

    // H(I||V||...
    crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());

    bool isValid;
    EhIsValidSolution(n, k, state, pblock->nSolution, isValid);
    if (!isValid)
        return false;

    return true;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params, int algo)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > GetAlgoPowLimit(algo))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

const CBlockIndex* GetLastBlockIndexForAlgo(const CBlockIndex* pindex, int algo)
{
	for (;;)
	{
		if (!pindex)
			return nullptr;
		if (pindex->GetAlgo() == algo)
			return pindex;
		pindex = pindex->pprev;
	}
	return nullptr;
}