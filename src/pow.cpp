// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2009-2017 The DigiByte Core developers
// Copyright (c) 2016-2017 The Zcash developers
// Copyright (c) 2018 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <auxpow.h>
#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <globaltoken/hardfork.h>
#include <primitives/block.h>
#include <primitives/mining_block.h>
#include <uint256.h>
#include <util.h>
#include <streams.h>
#include <crypto/algos/equihash/equihash.h>
#include <validation.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, uint8_t algo)
{
    if(IsHardForkActivated(pblock->nTime))
       return GetNextWorkRequiredV2(pindexLast, pblock, params, algo);
    else
       return GetNextWorkRequiredV1(pindexLast, pblock, params, algo);
}

unsigned int GetNextWorkRequiredV1(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, uint8_t algo)
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

unsigned int GetNextWorkRequiredV2(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, uint8_t algo)
{
	unsigned int npowWorkLimit = GetAlgoPowLimit(algo).GetCompact();

	// Genesis block
	if (pindexLast == nullptr)
		return npowWorkLimit;
		
	if (params.fPowNoRetargeting)
	{
		const CBlockIndex* pindexLastAlgo = GetLastBlockIndexForAlgo(pindexLast, algo);
		if(pindexLastAlgo == nullptr)
		{
		    return npowWorkLimit;
		}
		else
		{
		    return pindexLastAlgo->nBits;	
		}
	}

	if (params.fPowAllowMinDifficultyBlocks)
	{
        const CBlockIndex* pindexLastAlgo = GetLastBlockIndexForAlgo(pindexLast, algo);
		if(pindexLastAlgo == nullptr)
		{
		    return npowWorkLimit;
		}
        
		// Special difficulty rule for testnet:
		// If the new block's timestamp is more than NUM_ALGOS * 1 minutes
		// then allow mining of a min-difficulty block.
		if (pblock->nTime > pindexLastAlgo->nTime + params.nTargetSpacing * NUM_ALGOS)
			return npowWorkLimit;
		else
		{
			// Return the last non-special-min-difficulty-rules-block
			const CBlockIndex* pindex = pindexLastAlgo;
            
			while (pindex != nullptr && pindex->pprev && pindex->nHeight % params.nInterval != 0 && pindex->nBits == npowWorkLimit)
				pindex = GetLastBlockIndexForAlgo(pindex->pprev, algo);
            
            if (pindex == nullptr)
                return npowWorkLimit;
            else
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
	{
		return npowWorkLimit;
	}

	// Limit adjustment step
	// Use medians to prevent time-warp attacks
	int64_t nActualTimespan = pindexLast-> GetMedianTimePast() - pindexFirst->GetMedianTimePast();
	nActualTimespan = params.nAveragingTargetTimespan + (nActualTimespan - params.nAveragingTargetTimespan)/4;

	if (nActualTimespan < params.nMinActualTimespan)
		nActualTimespan = params.nMinActualTimespan;
	if (nActualTimespan > params.nMaxActualTimespan)
		nActualTimespan = params.nMaxActualTimespan;

	//Global retarget
	arith_uint256 bnNew;
	bnNew.SetCompact(pindexPrevAlgo->nBits);

	bnNew *= nActualTimespan;
	bnNew /= params.nAveragingTargetTimespan;

	//Per-algo retarget
	int nAdjustments = pindexPrevAlgo->nHeight + NUM_ALGOS - 1 - pindexLast->nHeight;
	if (nAdjustments > 0)
	{
		for (int i = 0; i < nAdjustments; i++)
		{
			bnNew *= 100;
			bnNew /= (100 + params.nLocalTargetAdjustment);
		}
	}
	else if (nAdjustments < 0)//make it easier
	{
		for (int i = 0; i < -nAdjustments; i++)
		{
			bnNew *= (100 + params.nLocalTargetAdjustment);
			bnNew /= 100;
		}
	}

	if (bnNew > GetAlgoPowLimit(algo))
	{
		bnNew = GetAlgoPowLimit(algo);
	}

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

bool CheckEquihashSolution(const CEquihashBlockHeader *pblock, const CChainParams& params, bool fisZhash, const std::string stateString)
{
    // if fisZhash is true, this is a Zhash Block, otherwhise Equihash.
    unsigned int n = fisZhash ? params.ZhashN() : params.EquihashN();
    unsigned int k = fisZhash ? params.ZhashK() : params.EquihashK();

    // Hash state
    crypto_generichash_blake2b_state state;
    EhInitialiseState(n, k, state, stateString);

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

bool CheckEquihashSolution(const CBlockHeader *pblock, const CChainParams& params)
{
    CEquihashBlockHeader pequihashblock;
    pequihashblock = pblock->GetEquihashBlockHeader();
    return CheckEquihashSolution(&pequihashblock, params, pblock->GetAlgo() == ALGO_ZHASH, pblock->GetAlgo() == ALGO_ZHASH ? DEFAULT_ZHASH_PERSONALIZE : DEFAULT_EQUIHASH_PERSONALIZE);
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params, uint8_t algo)
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

bool CheckProofOfWork(const CBlockHeader& block, const Consensus::Params& params)
{
    bool equihashvalidator;
    return CheckProofOfWork(block, params, equihashvalidator);
}

bool CheckProofOfWork(const CBlockHeader& block, const Consensus::Params& params, bool &ehsolutionvalid)
{
    bool hardfork = IsHardForkActivated(block.nTime);
    uint8_t nAlgo = block.GetAlgo();
    ehsolutionvalid = true;
    
    /* Except for legacy blocks with full version 1, ensure that
       the chain ID is correct.  Legacy blocks are not allowed since
       the merge-mining start, which is checked in AcceptBlockHeader
       where the height is known.  */
    if (hardfork && params.fStrictChainId
        && block.GetChainId() != params.nAuxpowChainId)
        return error("%s : block does not have our chain ID"
                     " (got %d, expected %d, full nVersion %d)",
                     __func__, block.GetChainId(),
                     params.nAuxpowChainId, block.nVersion);

    /* If there is no auxpow, just check the block hash.  */
    if (!block.auxpow)
    {
        if (block.IsAuxpow())
            return error("%s : no auxpow on block with auxpow version",
                         __func__);
        
        if(hardfork)
        {
            if(nAlgo == ALGO_EQUIHASH || nAlgo == ALGO_ZHASH)
            {
                const size_t sol_size = Params().EquihashSolutionWidth(nAlgo);
                
                // Check Equihash solution
                if (!CheckEquihashSolution(&block, Params())) {
                    ehsolutionvalid = false;
                    return error("%s: non-AUX proof of work : bad %s solution", __func__, GetAlgoName(nAlgo));
                }
                
                if(block.nSolution.size() != sol_size) {
                    ehsolutionvalid = false;
                    return error("%s: non-AUX proof of work : %s solution has invalid size have %d need %d", __func__, GetAlgoName(nAlgo), block.nSolution.size(), sol_size);
                }
                
                // Check the header
                // Also check the Block Header after Equihash solution check.
                if (!CheckProofOfWork(block.GetPoWHash(), block.nBits, params, nAlgo))
                    return error("%s : non-AUX proof of work failed - hash=%s, algo=%d (%s), nVersion=%d, PoWHash=%s", __func__, block.GetHash().ToString(), nAlgo, GetAlgoName(nAlgo), block.nVersion, block.GetPoWHash().ToString());
            }
            else
            {
                // Check the header
                if (!CheckProofOfWork(block.GetPoWHash(), block.nBits, params, nAlgo))
                    return error("%s : non-AUX proof of work failed - hash=%s, algo=%d (%s), nVersion=%d, PoWHash=%s", __func__, block.GetHash().ToString(), nAlgo, GetAlgoName(nAlgo), block.nVersion, block.GetPoWHash().ToString());
            }
        }
        else
        {
            if(nAlgo == ALGO_SHA256D)
            {
                // Check the header
                if (!CheckProofOfWork(block.GetPoWHash(), block.nBits, params, ALGO_SHA256D))
                    return error("%s : non-AUX proof of work failed - hash=%s, algo=%d (%s), nVersion=%d, PoWHash=%s", __func__, block.GetHash().ToString(), nAlgo, GetAlgoName(nAlgo), block.nVersion, block.GetPoWHash().ToString());
            }
            else
            {
                return error("%s : Algo %s not allowed because Hardfork is not activated.", __func__, GetAlgoName(nAlgo));
            }
        }

        return true;
    }
    
    /* We have auxpow.  Check it.  */
    
    if(!hardfork)
        return error("%s : Found AuxPOW! - AuxPOW not valid yet, It will be activated with the Hardfork.", __func__);

    if(nAlgo == ALGO_EQUIHASH || nAlgo == ALGO_ZHASH)
    {
        const size_t sol_size = Params().EquihashSolutionWidth(nAlgo);
        if (!block.IsAuxpow())
            return error("%s : auxpow on block with non-auxpow version", __func__);

        /* Temporary check:  Disallow parent blocks with auxpow version.  This is
           for compatibility with the old client.  */
        /* FIXME: Remove this check with a hardfork later on.  */
        if (block.auxpow->getEquihashParentBlock().IsAuxpow())
            return error("%s : auxpow parent block has auxpow version", __func__);
        
        // The GLT block should have no nonce, just the auxpow block stores it.
        if (block.nBigNonce != uint256())
            return error("%s : auxpow - Found nonce in GlobalToken block!", __func__);

        if (!block.auxpow->check(block.GetHash(), block.GetChainId(), params))
            return error("%s : AUX POW is not valid", __func__);
        
        if(block.auxpow->getEquihashParentBlock().nSolution.size() != sol_size) {
            ehsolutionvalid = false;
            return error("%s: AUX proof of work - %s solution has invalid size have %d need %d", __func__, GetAlgoName(nAlgo), block.nSolution.size(), sol_size);
        }

        if(nAlgo == ALGO_ZHASH)
        {
            // Check Zhash solution
            if (!CheckEquihashSolution(&block.auxpow->getEquihashParentBlock(), Params(), true, block.auxpow->strZhashConfig)) {
                ehsolutionvalid = false;
                return error("%s: AUX proof of work - %s solution failed. (bad %s solution)", __func__, GetAlgoName(nAlgo), GetAlgoName(nAlgo));
            }
        }
        else
        {
            // Check Equihash solution
            if (!CheckEquihashSolution(&block.auxpow->getEquihashParentBlock(), Params(), false, DEFAULT_EQUIHASH_PERSONALIZE)) {
                ehsolutionvalid = false;
                return error("%s: AUX proof of work - %s solution failed. (bad %s solution)", __func__, GetAlgoName(nAlgo), GetAlgoName(nAlgo));
            }
        }
        
        // Check the header
        // Also check the Block Header after Equihash solution check.
        if (!CheckProofOfWork(block.auxpow->getParentBlockPoWHash(nAlgo), block.nBits, params, nAlgo))
            return error("%s : AUX proof of work failed (Algo : %s)", __func__, GetAlgoName(nAlgo));
    }
    else
    {
        if (!block.IsAuxpow())
            return error("%s : auxpow on block with non-auxpow version", __func__);

        /* Temporary check:  Disallow parent blocks with auxpow version.  This is
           for compatibility with the old client.  */
        /* FIXME: Remove this check with a hardfork later on.  */
        if (block.auxpow->getDefaultParentBlock().IsAuxpow())
            return error("%s : auxpow parent block has auxpow version", __func__);

        if (!block.auxpow->check(block.GetHash(), block.GetChainId(), params))
            return error("%s : AUX POW is not valid", __func__);

        // Check the header
        if (!CheckProofOfWork(block.auxpow->getParentBlockPoWHash(nAlgo), block.nBits, params, nAlgo))
            return error("%s : AUX proof of work failed (Algo : %s)", __func__, GetAlgoName(nAlgo));
    }

    return true;
}

const CBlockIndex* GetLastBlockIndexForAlgo(const CBlockIndex* pindex, uint8_t algo)
{
	for (;;)
	{
		if (!pindex)
			return nullptr;
        if (!IsHardForkActivated(pindex->nTime) && algo != ALGO_SHA256D)
            return nullptr;
		if (pindex->GetAlgo() == algo)
			return pindex;
		pindex = pindex->pprev;
	}
	return nullptr;
}

const CBlockIndex* GetNextBlockIndexForAlgo(const CBlockIndex* pindex, uint8_t algo)
{
    AssertLockHeld(cs_main);
	for (;;)
	{
		if (!pindex)
			return nullptr;
		if (pindex->GetAlgo() == algo)
			return pindex;
		pindex = chainActive.Next(pindex);
	}
	return nullptr;
}

int CalculateDiffRetargetingBlock(const CBlockIndex* pindex, int retargettype, uint8_t algo, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
	    return 0;
	
	const CBlockIndex* pindexAlgo = GetLastBlockIndexForAlgo(pindex, algo);
    const CBlockIndex* pindexLastAlgo;
    if(pindexAlgo != nullptr)
        if(pindexAlgo->pprev)
            pindexLastAlgo = GetLastBlockIndexForAlgo(pindexAlgo->pprev, algo);
        else
            pindexLastAlgo = nullptr;
    else
        pindexLastAlgo = pindexAlgo;
	if(retargettype == RETARGETING_LAST)
	{
		for(;;)
		{
			if(pindexAlgo == nullptr || pindex == nullptr)
				return -1;
		
			if(pindexLastAlgo == nullptr)
				return pindexAlgo->nHeight; 
			
			if(pindexAlgo->nBits != pindexLastAlgo->nBits)
				return pindexAlgo->nHeight;	
		
			pindexAlgo = pindexLastAlgo;
			pindexLastAlgo = GetLastBlockIndexForAlgo(pindexAlgo->pprev, algo);
		}
		return -3;
	}
	else if(retargettype == RETARGETING_NEXT)
	{
	    const CBlockIndex* pindexone = nullptr;
	    const CBlockIndex* pindextwo = nullptr;
            int blockdifference = 0, runtimes = 0, round = 0, blockssinceret = 0;
            bool blockcount = false;
	    // Calculate last 2 block heights to calculate retargeting
            for(;;)
            {
                if(pindexAlgo == nullptr)
                {
                    if(pindex != nullptr && pindex)
                        return pindex->nHeight;
                    else
                        return -1;
			
                    if(pindexLastAlgo == nullptr)
                        return -1; 
                }
				else
				{
				    if(pindexLastAlgo == nullptr)
                        return -1; 
				
                    if(pindexAlgo->nBits != pindexLastAlgo->nBits)
                    {
                        if(pindexone == nullptr && pindextwo == nullptr)
                        {
                            pindexone = pindexAlgo;
                            blockcount = true;
                            round = 1;
                        }
                        else if(pindexone != nullptr && pindextwo == nullptr)
                        {
                            pindextwo = pindexAlgo;
                            blockcount = false;
                            round = 2;
                        }
                        else if(pindexone != nullptr && pindextwo != nullptr)
                            blockdifference = pindexone->nHeight - pindextwo->nHeight;
                        else
                            return -2;
                    }
			
                    if(pindexAlgo->nBits == pindexLastAlgo->nBits && blockcount)
                    {
                        runtimes++;
                        if(round == 0)
                        {
                            blockssinceret++;
                        }
                    }
			
                    if(blockdifference != 0)
                    {
                        int nextheight = runtimes-blockssinceret;
                        return pindex->nHeight + nextheight;
                    }
				}
				pindexAlgo = pindexLastAlgo;
                pindexLastAlgo = GetLastBlockIndexForAlgo(pindexAlgo->pprev, algo);
	    }
	    return -3;
    }
    return -4; // function error
}
