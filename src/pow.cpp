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

bool IsAuxPowAllowed(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, const uint8_t algo)
{
    if(!pblock->IsAuxpow())
        return true; // This is not an auxpow block! - The block is allowed!
    
    if(params.Hardfork2.IsActivated(pindexLast->nTime))
    {
        if(params.nMaxAuxpowBlocks == ~uint32_t(0)) // Max value of uint32_t means, there is no limit for auxpow blocks.
            return true;
        
        unsigned int npowWorkLimit = params.aPOWAlgos[algo].GetArithPowLimit().GetCompact();
        const CBlockIndex* pIndexLastAlgo = GetLastBlockIndexForAlgo(pindexLast, algo, params);
        if(pIndexLastAlgo == nullptr)
            return false; // No block yet, auxpow unallowed!
        
        // If this block has genesis diff, it is allowed to mine auxpow!
        if(GetNextWorkRequired(pindexLast, pblock, params, algo) == npowWorkLimit)
            return true;
        
        uint32_t blocksfound = 0;
        for(uint32_t i = 0; i < params.nMaxAuxpowBlocks; i++)
        {
            bool fIsAuxPow = CPureBlockVersion(pIndexLastAlgo->nVersion).IsAuxpow();
            
            if(fIsAuxPow)
            {
                blocksfound++;
                
                if(pIndexLastAlgo->nBits == npowWorkLimit)
                {
                    break;
                }
                pIndexLastAlgo = GetLastBlockIndexForAlgo(pIndexLastAlgo->pprev, algo, params);
                
                if(pIndexLastAlgo == nullptr)
                    return false;
            }
            else
            {
                // the chain includes normal mining without auxpow. auxpow is not allowed.
                return false;
            }
        }
        
        if(blocksfound == params.nMaxAuxpowBlocks-1)
        {
            // The current pindex must be genesis diff, because max auxpow block is genesis diff.
            if(pIndexLastAlgo->nBits != npowWorkLimit)
                return false; // The block is not at genesis diff, block not allowed!
        }
        
        if(blocksfound == params.nMaxAuxpowBlocks)
        {
            return false;
        }
        return (blocksfound < params.nMaxAuxpowBlocks);
    }
    else
    {
        if(params.Hardfork1.IsActivated(pindexLast->nTime))
            return true; // Hardfork 1 has full auxpow support.
        else
            return false; // Before hardfork 1, there was no auxpow.
    }
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, const uint8_t algo)
{
    if(params.Hardfork2.IsActivated(pblock->nTime))
       return GetNextWorkRequiredV3(pindexLast, pblock, params, algo);
    else if(params.Hardfork1.IsActivated(pblock->nTime))
       return GetNextWorkRequiredV2(pindexLast, pblock, params, algo);
    else
       return GetNextWorkRequiredV1(pindexLast, pblock, params, algo);
}

unsigned int GetNextWorkRequiredV1(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, const uint8_t algo)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = params.aPOWAlgos[ALGO_SHA256D].GetArithPowLimit().GetCompact(); // Before the Hardfork starts, there is just SHA256D

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

unsigned int GetNextWorkRequiredV2(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, const uint8_t algo)
{
	unsigned int npowWorkLimit = params.aPOWAlgos[algo].GetArithPowLimit().GetCompact();

	// Genesis block
	if (pindexLast == nullptr)
		return npowWorkLimit;

    // We removed the special testnet rule, because Multishield will automatically go to npowWorkLimit if there are no blocks found with this algo.
    // But regtest, should not retarget and get always the same genesis diff.
	if (params.fPowNoRetargeting)
	{
		const CBlockIndex* pindexLastAlgo = GetLastBlockIndexForAlgo(pindexLast, algo, params);
		if(pindexLastAlgo == nullptr)
		{
		    return npowWorkLimit;
		}
		else
		{
		    return pindexLastAlgo->nBits;	
		}
	}

	// find first block in averaging interval
	// Go back by what we want to be nAveragingInterval blocks per algo
	const CBlockIndex* pindexFirst = pindexLast;
	for (int i = 0; pindexFirst && i < NUM_ALGOS_OLD*params.nAveragingInterval; i++)
	{
		pindexFirst = pindexFirst->pprev;
	}

	const CBlockIndex* pindexPrevAlgo = GetLastBlockIndexForAlgo(pindexLast, algo, params);
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
	int nAdjustments = pindexPrevAlgo->nHeight + NUM_ALGOS_OLD - 1 - pindexLast->nHeight;
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

	if (bnNew > params.aPOWAlgos[algo].GetArithPowLimit())
	{
		bnNew = params.aPOWAlgos[algo].GetArithPowLimit();
	}

	return bnNew.GetCompact();
}

unsigned int GetNextWorkRequiredV3(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, const uint8_t algo)
{
	unsigned int npowWorkLimit = params.aPOWAlgos[algo].GetArithPowLimit().GetCompact();

	// Genesis block
	if (pindexLast == nullptr)
		return npowWorkLimit;

    // We removed the special testnet rule, because Multishield will automatically go to npowWorkLimit if there are no blocks found with this algo.
    // But regtest, should not retarget and get always the same genesis diff.
	if (params.fPowNoRetargeting)
	{
		const CBlockIndex* pindexLastAlgo = GetLastBlockIndexForAlgo(pindexLast, algo, params);
		if(pindexLastAlgo == nullptr)
		{
		    return npowWorkLimit;
		}
		else
		{
		    return pindexLastAlgo->nBits;	
		}
	}

	// find first block in averaging interval
	// Go back by what we want to be nAveragingInterval blocks per algo
	const CBlockIndex* pindexFirst = pindexLast;
	for (int i = 0; pindexFirst && i < NUM_ALGOS*params.nAveragingInterval; i++) // unchanged, nAveragingInterval is still the same
	{
		pindexFirst = pindexFirst->pprev;
	}

	const CBlockIndex* pindexPrevAlgo = GetLastBlockIndexForAlgo(pindexLast, algo, params);
	if (pindexPrevAlgo == nullptr || pindexFirst == nullptr)
	{
		return npowWorkLimit;
	}

	// Limit adjustment step
	// Use medians to prevent time-warp attacks
	int64_t nActualTimespan = pindexLast-> GetMedianTimePast() - pindexFirst->GetMedianTimePast();
	nActualTimespan = params.nAveragingTargetTimespanV2 + (nActualTimespan - params.nAveragingTargetTimespanV2)/4;

	if (nActualTimespan < params.nMinActualTimespanV2)
		nActualTimespan = params.nMinActualTimespanV2;
	if (nActualTimespan > params.nMaxActualTimespanV2)
		nActualTimespan = params.nMaxActualTimespanV2;

	//Global retarget
	arith_uint256 bnNew;
	bnNew.SetCompact(pindexPrevAlgo->nBits);

	bnNew *= nActualTimespan;
	bnNew /= params.nAveragingTargetTimespanV2;

	//Per-algo retarget
	int nAdjustments = pindexPrevAlgo->nHeight + NUM_ALGOS - 1 - pindexLast->nHeight;
	if (nAdjustments > 0)
	{
		for (int i = 0; i < nAdjustments; i++)
		{
			bnNew *= 100;
			bnNew /= (100 + params.nLocalTargetAdjustment); // unchanged
		}
	}
	else if (nAdjustments < 0)//make it easier
	{
		for (int i = 0; i < -nAdjustments; i++)
		{
			bnNew *= (100 + params.nLocalTargetAdjustment); // unchanged
			bnNew /= 100;
		}
	}

	if (bnNew > params.aPOWAlgos[algo].GetArithPowLimit())
	{
		bnNew = params.aPOWAlgos[algo].GetArithPowLimit();
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
    const arith_uint256 bnPowLimit = params.aPOWAlgos[ALGO_SHA256D].GetArithPowLimit();
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckEquihashSolution(const CEquihashBlockHeader *pblock, const CChainParams& params, uint8_t nAlgo, const std::string stateString)
{
    unsigned int n = params.GetEquihashAlgoN(nAlgo);
    unsigned int k = params.GetEquihashAlgoK(nAlgo);

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
    uint8_t nAlgo = pblock->GetAlgo();
    CEquihashBlockHeader pequihashblock;
    pequihashblock = pblock->GetEquihashBlockHeader();
    return CheckEquihashSolution(&pequihashblock, params, nAlgo, GetEquihashBasedDefaultPersonalize(nAlgo));
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params, const uint8_t algo)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > params.aPOWAlgos[algo].GetArithPowLimit())
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
    bool hardfork   = params.Hardfork1.IsActivated(block.nTime);
    bool hardfork2  = params.Hardfork2.IsActivated(block.nTime);
    uint8_t nAlgo   = block.GetAlgo();
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
                     
    if(!hardfork2 && !IsAlgoAllowedBeforeHF2(nAlgo))
        return error("%s : Algo %s not allowed because Hardfork 2 is not activated.", __func__, GetAlgoName(nAlgo));

    /* If there is no auxpow, just check the block hash.  */
    if (!block.auxpow)
    {
        if (block.IsAuxpow())
            return error("%s : no auxpow on block with auxpow version",
                         __func__);
        
        if(hardfork)
        {
            if(IsEquihashBasedAlgo(nAlgo))
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

    if(IsEquihashBasedAlgo(nAlgo))
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
        
        // The GLT block should have no solution, just the auxpow block stores it.
        if (block.nSolution.size() != 0)
            return error("%s : auxpow - Found solution in GlobalToken block!", __func__);

        if (!block.auxpow->check(block.GetHash(), block.GetChainId(), params, nAlgo))
            return error("%s : AUX POW is not valid", __func__);
        
        if(block.auxpow->getEquihashParentBlock().nSolution.size() != sol_size) {
            ehsolutionvalid = false;
            return error("%s: AUX proof of work - %s solution has invalid size have %d need %d", __func__, GetAlgoName(nAlgo), block.nSolution.size(), sol_size);
        }

        if(nAlgo != ALGO_EQUIHASH && IsEquihashBasedAlgo(nAlgo))
        {
            // Check Equihash solution, where Personalize String can be different.
            if (!CheckEquihashSolution(&block.auxpow->getEquihashParentBlock(), Params(), nAlgo, block.auxpow->strEquihashPersString)) {
                ehsolutionvalid = false;
                return error("%s: AUX proof of work - %s solution failed. (bad %s solution)", __func__, GetAlgoName(nAlgo), GetAlgoName(nAlgo));
            }
        }
        else
        {
            // Check Equihash solution
            if (!CheckEquihashSolution(&block.auxpow->getEquihashParentBlock(), Params(), nAlgo, GetEquihashBasedDefaultPersonalize(nAlgo))) {
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

        if (!block.auxpow->check(block.GetHash(), block.GetChainId(), params, nAlgo))
            return error("%s : AUX POW is not valid", __func__);

        // Check the header
        if (!CheckProofOfWork(block.auxpow->getParentBlockPoWHash(nAlgo), block.nBits, params, nAlgo))
            return error("%s : AUX proof of work failed (Algo : %s)", __func__, GetAlgoName(nAlgo));
    }

    return true;
}

const CBlockIndex* GetLastBlockIndexForAlgo(const CBlockIndex* pindex, const uint8_t algo, const Consensus::Params& params)
{
	for (;;)
	{
		if (!pindex)
			return nullptr;
        if (!params.Hardfork1.IsActivated(pindex->nTime) && algo != ALGO_SHA256D)
            return nullptr;
        if (!params.Hardfork2.IsActivated(pindex->nTime) && !IsAlgoAllowedBeforeHF2(algo))
            return nullptr;
		if (pindex->GetAlgo() == algo)
			return pindex;
		pindex = pindex->pprev;
	}
	return nullptr;
}

const CBlockIndex* GetNextBlockIndexForAlgo(const CBlockIndex* pindex, const uint8_t algo)
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

int CalculateDiffRetargetingBlock(const CBlockIndex* pindex, int retargettype, const uint8_t algo, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
	    return 0;
	
	const CBlockIndex* pindexAlgo = GetLastBlockIndexForAlgo(pindex, algo, params);
    const CBlockIndex* pindexLastAlgo;
    if(pindexAlgo != nullptr)
        if(pindexAlgo->pprev)
            pindexLastAlgo = GetLastBlockIndexForAlgo(pindexAlgo->pprev, algo, params);
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
			pindexLastAlgo = GetLastBlockIndexForAlgo(pindexAlgo->pprev, algo, params);
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
                pindexLastAlgo = GetLastBlockIndexForAlgo(pindexAlgo->pprev, algo, params);
	    }
	    return -3;
    }
    return -4; // function error
}
