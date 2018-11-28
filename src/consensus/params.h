// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2009-2017 The DigiByte Core developers
// Copyright (c) 2018 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <uint256.h>
#include <limits>
#include <map>
#include <string>

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
    DEPLOYMENT_SEGWIT, // Deployment of BIP141, BIP143, and BIP147.
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    int nMasternodeMinimumConfirmations;
    int nMasternodeColleteralPaymentAmount;
    int nMasternodePayeeReward;
    int nInstantSendConfirmationsRequired;
    int nInstantSendKeepLock;
    int nTreasuryAddressChange;
    int nTreasuryAddressChangeStart;
    int nTreasuryAmount;
    /** Block height at which BIP16 becomes active */
    int BIP16Height;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
	/** Block height at which BIP66 becomes active */
    int HardforkHeight;
    uint256 HardforkHash;
    uint32_t HardforkTime;
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit_SHA256;
    uint256 powLimit_SCRYPT;
    uint256 powLimit_X11;
    uint256 powLimit_NEOSCRYPT;
    uint256 powLimit_EQUIHASH;
    uint256 powLimit_YESCRYPT;
    uint256 powLimit_HMQ1725;
    uint256 powLimit_XEVAN;
    uint256 powLimit_NIST5;
    uint256 powLimit_TIMETRAVEL10;
    uint256 powLimit_PAWELHASH;
    uint256 powLimit_X13;
    uint256 powLimit_X14;
    uint256 powLimit_X15;
    uint256 powLimit_X17;
    uint256 powLimit_LYRA2RE;
    uint256 powLimit_BLAKE2S;
    uint256 powLimit_BLAKE2B;
    uint256 powLimit_ASTRALHASH;
    uint256 powLimit_PADIHASH;
    uint256 powLimit_JEONGHASH;
    uint256 powLimit_KECCAK;
    uint256 powLimit_ZHASH;
    uint256 powLimit_GLOBALHASH;
    uint256 powLimit_QUBIT;
    uint256 powLimit_SKEIN;
    uint256 powLimit_GROESTL;
    uint256 powLimit_SKUNKHASH;
    uint256 powLimit_QUARK;
    uint256 powLimit_X16R;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nTargetTimespan;
    int64_t nTargetSpacing;
    int64_t nInterval;
    int64_t nAveragingInterval;
    int64_t nAveragingTargetTimespan;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetSpacingV2;
    int64_t nPowTargetTimespan;
    int64_t nMaxAdjustDown;
    int64_t nMaxAdjustUp;
    int64_t nMinActualTimespan;
    int64_t nMaxActualTimespan;
    int64_t nLocalTargetAdjustment;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;
    
    /** Auxpow parameters */
    int32_t nAuxpowChainId;
    bool fStrictChainId;
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
