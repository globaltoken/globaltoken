// Copyright (c) 2018 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <globaltoken/hardfork.h>
#include <uint256.h>
#include <arith_uint256.h>
#include <chainparams.h>
#include <primitives/block.h>

const Consensus::Params& consensusParams = Params().GetConsensus();

arith_uint256 GetAlgoPowLimit(int algo)
{
	if (algo == ALGO_SHA256D)
		return UintToArith256(consensusParams.powLimit_SHA256);
	else if (algo == ALGO_SCRYPT)
		return UintToArith256(consensusParams.powLimit_SCRYPT);
	else if (algo == ALGO_X11)
		return UintToArith256(consensusParams.powLimit_X11);
	else if (algo == ALGO_NEOSCRYPT)
		return UintToArith256(consensusParams.powLimit_NEOSCRYPT);
	else if (algo == ALGO_EQUIHASH)
		return UintToArith256(consensusParams.powLimit_EQUIHASH);
	else if (algo == ALGO_YESCRYPT)
		return UintToArith256(consensusParams.powLimit_YESCRYPT);
	else if (algo == ALGO_HMQ1725)
		return UintToArith256(consensusParams.powLimit_HMQ1725);
	else
		return UintToArith256(consensusParams.powLimit_SHA256);
}

bool IsHardForkActivated(uint32_t height)
{
	if(height >= (uint32_t)consensusParams.HardforkHeight)
	{
		return true;
	}
	return false;
}

int64_t GetPoWTargetTimeSpan(uint32_t height)
{
	if(IsHardForkActivated(height))
	{
		return consensusParams.nPowTargetTimespanV2;
	}
	else
	{
		return consensusParams.nPowTargetTimespan;
	}
}

int64_t GetPoWTargetSpacing(uint32_t height)
{
	if(IsHardForkActivated(height))
	{
		return consensusParams.nPowTargetSpacingV2;
	}
	else
	{
		return consensusParams.nPowTargetSpacing;
	}
}