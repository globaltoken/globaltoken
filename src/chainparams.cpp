// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2017-2018 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <uint256.h>
#include <arith_uint256.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

// For equihash_parameters_acceptable.
#include <crypto/algos/equihash/equihash.h>
#include <net.h>
#include <validation.h>
#define equihash_parameters_acceptable(N, K) \
    ((CBlockHeader::HEADER_SIZE + equihash_solution_size(N, K))*MAX_HEADERS_RESULTS < \
     MAX_PROTOCOL_MESSAGE_LENGTH-1000)

#include <assert.h>

#include <chainparamsseeds.h>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = ArithToUint256(arith_uint256(nNonce));
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "05.12.2016 18.27h UTC plus 1 created Globaltoken";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.BIP16Height = 100000;
        consensus.BIP34Height = 299999;
        // not hashed yet ... consensus.BIP34Hash = uint256S("0x00");
        consensus.BIP65Height = 380000; // not hashed yet ...
        consensus.BIP66Height = 360000; // not hashed yet ...
		consensus.HardforkHeight = 300000;
        // not hashed yet ... consensus.HardforkHash = uint256S("0x00");
		
		// Algo PoW Stuff
		
        consensus.powLimit_SHA256 = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		consensus.powLimit_SCRYPT = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		consensus.powLimit_X11 = uint256S("00000fffff000000000000000000000000000000000000000000000000000000");
		consensus.powLimit_NEOSCRYPT = uint256S("00001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		consensus.powLimit_EQUIHASH = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		consensus.powLimit_YESCRYPT = uint256S("0003ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		consensus.powLimit_HMQ1725 = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 10 * 60; // ten minutes
        consensus.nPowTargetSpacing = 60;
		consensus.nPowTargetTimespanV2 = 5 * 60; // just changed to faster retargeting (5 minutes)
		consensus.nPowTargetSpacingV2 = 60 * 7;
		consensus.nInterval = consensus.nPowTargetTimespanV2 / consensus.nPowTargetSpacingV2;
		consensus.nAveragingInterval = 5; // 5 blocks
		consensus.nAveragingTargetTimespan = consensus.nAveragingInterval * consensus.nPowTargetSpacingV2;
		consensus.nMaxAdjustDown = 16; // 16% adjustment down
        consensus.nMaxAdjustUp = 8; // 8% adjustment up
		consensus.nMinActualTimespan = consensus.nAveragingTargetTimespan * (100 - consensus.nMaxAdjustUp) / 100;
		consensus.nMaxActualTimespan = consensus.nAveragingTargetTimespan * (100 + consensus.nMaxAdjustDown) / 100;
		consensus.nLocalDifficultyAdjustment = 4; //difficulty adjustment per algo
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 8; // 95% of 2016 // Changed to 8 because 9.5 is up to ten.
        consensus.nMinerConfirmationWindow = 10; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1506729600; // Sat, 30 Sep 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1509494400; // Wed, 01 Nov 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1509494400; // Wed, 01 Nov 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1519862400; // Thu, 01 Mar 2018.
		
		// Deployment of GlobalToken Hardfork Block Upgrade
        consensus.vDeployments[Consensus::DEPLOYMENT_HARDFORK_SIZING].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_HARDFORK_SIZING].nStartTime = 1526342400; // Tue, 15 May 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_HARDFORK_SIZING].nTimeout = 1530403200; // Sun, 01 Jul 2018.

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000006ca5a7a5a45e8f8b9c");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000000000000014cf4dc216dcc925bf0c6d7096aa6ab82e1af64e946d876df7d"); //200000

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xc7;
        pchMessageStart[1] = 0x08;
        pchMessageStart[2] = 0xd3;
        pchMessageStart[3] = 0x2d;
        nDefaultPort = 9319;
        nPruneAfterHeight = 750000;
		const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
		nEquihashN = N;
        nEquihashK = K;

        genesis = CreateGenesisBlock(1480961109, 2864352084, 0x1d00ffff, 1, 100 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000000fe3e3e93344a6b73888137397413eb11f601b4231b5196390d24d3b6"));
        assert(genesis.hashMerkleRoot == uint256S("0xe217ce769444458c180ca6a5944cbbc22828f377cfd0e1790158034299827ffc"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("134.255.221.7"); // Globaltoken base node
		vSeeds.emplace_back("lameserver.de"); // GlobalToken Node by Astrali

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,38);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,166);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "gt";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                {     0, uint256S("0x00000000fe3e3e93344a6b73888137397413eb11f601b4231b5196390d24d3b6")},
				{   253, uint256S("0x000000000001a9597538194df736eda73c35c17d78ec14ac99b9d392d0892ce3")},
				{ 44446, uint256S("0x000000000004ddd47d2e6033af4d034e63171d61e4eaca2702f9e8b9a8ffdb5a")},
				{ 87757, uint256S("0x000000000001356d0e351660b8356f8f6a12a5b029b2c10a5b47d753b8cd8f29")},
				{174987, uint256S("0x0000000000004a80520dfce6d2017d6f403a9def13fe99629d31f6b7a90b7c31")},
				{214590, uint256S("0x00000000000003886a3080ff818eb6027a98f1ac33c532b730fbe4c0fde704ca")},
				{282595, uint256S("0x00000000000000e335a60ca393eee3445f551d5bf6987e47d3a70e043b8dff5b")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block 0000000000000069c70702db06f86040268d0fdbfbf86b80ce35caa1dc9893c8 (height 282590).
            1516650620, // * UNIX timestamp of last known number of transactions
            343863,  // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.0045        // * estimated number of transactions per second after that timestamp
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.BIP16Height = 1;
        consensus.BIP34Height = 1;
        // consensus.BIP34Hash = uint256S("0x00000000fe3e3e93344a6b73888137397413eb11f601b4231b5196390d24d3b6"); // not hashed
        consensus.BIP65Height = 100; // not hashed yet.
        consensus.BIP66Height = 10; // not hashed yet.
		consensus.HardforkHeight = 2999;
        // not hashed yet ... consensus.HardforkHash = uint256S("0x00");
		consensus.powLimit_SHA256 = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		consensus.powLimit_SCRYPT = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		consensus.powLimit_X11 = uint256S("00000fffff000000000000000000000000000000000000000000000000000000");
		consensus.powLimit_NEOSCRYPT = uint256S("00001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		consensus.powLimit_EQUIHASH = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		consensus.powLimit_YESCRYPT = uint256S("0003ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		consensus.powLimit_HMQ1725 = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 10 * 60; // ten minutes
        consensus.nPowTargetSpacing = 60;
		consensus.nPowTargetTimespanV2 = 5 * 60; // just changed to faster retargeting (5 minutes)
		consensus.nPowTargetSpacingV2 = 60 * 7;
		consensus.nInterval = consensus.nPowTargetTimespanV2 / consensus.nPowTargetSpacingV2;
		consensus.nAveragingInterval = 5; // 5 blocks
		consensus.nAveragingTargetTimespan = consensus.nAveragingInterval * consensus.nPowTargetSpacingV2;
		consensus.nMaxAdjustDown = 16; // 16% adjustment down
        consensus.nMaxAdjustUp = 8; // 8% adjustment up
		consensus.nMinActualTimespan = consensus.nAveragingTargetTimespan * (100 - consensus.nMaxAdjustUp) / 100;
		consensus.nMaxActualTimespan = consensus.nAveragingTargetTimespan * (100 + consensus.nMaxAdjustDown) / 100;
		consensus.nLocalDifficultyAdjustment = 4; //difficulty adjustment per algo
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 8; // 75% for testchains
        consensus.nMinerConfirmationWindow = 10; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1506729600; // Sat, 30 Sep 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1509494400; // Wed, 01 Nov 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1509494400; // Wed, 01 Nov 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1519862400; // Thu, 01 Mar 2018.
		
		// Deployment of GlobalToken Hardfork Block Upgrade
        consensus.vDeployments[Consensus::DEPLOYMENT_HARDFORK_SIZING].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_HARDFORK_SIZING].nStartTime = 1526342400; // Tue, 15 May 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_HARDFORK_SIZING].nTimeout = 1530403200; // Sun, 01 Jul 2018.

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000100010001");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000000fe3e3e93344a6b73888137397413eb11f601b4231b5196390d24d3b6"); //0

        pchMessageStart[0] = 0x3a;
        pchMessageStart[1] = 0x6f;
        pchMessageStart[2] = 0x37;
        pchMessageStart[3] = 0x5b;
        nDefaultPort = 19319;
        nPruneAfterHeight = 1000;
		const size_t N = 200, K = 9;  // Same as mainchain.
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        genesis = CreateGenesisBlock(1480961109, 2864352084, 0x1d00ffff, 1, 100 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000000fe3e3e93344a6b73888137397413eb11f601b4231b5196390d24d3b6"));
        assert(genesis.hashMerkleRoot == uint256S("0xe217ce769444458c180ca6a5944cbbc22828f377cfd0e1790158034299827ffc"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top

        vSeeds.emplace_back("134.255.221.7");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tg";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {
                {0, uint256S("00000000fe3e3e93344a6b73888137397413eb11f601b4231b5196390d24d3b6")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block 00000000fe3e3e93344a6b73888137397413eb11f601b4231b5196390d24d3b6 (height 0)
            1480961109,
            1,
            1
        };

    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Height = 0; // always enforce P2SH BIP16 on regtest
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
		consensus.HardforkHeight = 15;
        consensus.HardforkHash = uint256(); // there is no hardfork hash for regtest, it will be just activated after height
		consensus.powLimit_SHA256 = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		consensus.powLimit_SCRYPT = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		consensus.powLimit_X11 = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		consensus.powLimit_NEOSCRYPT = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		consensus.powLimit_EQUIHASH = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
		consensus.powLimit_YESCRYPT = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		consensus.powLimit_HMQ1725 = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 10 * 60; // ten minutes
        consensus.nPowTargetSpacing = 60;
		consensus.nPowTargetTimespanV2 = 5 * 60; // just changed to faster retargeting (5 minutes)
		consensus.nPowTargetSpacingV2 = 60 * 7;
		consensus.nInterval = consensus.nPowTargetTimespanV2 / consensus.nPowTargetSpacingV2;
		consensus.nAveragingInterval = 5; // 5 blocks
		consensus.nAveragingTargetTimespan = consensus.nAveragingInterval * consensus.nPowTargetSpacingV2;
		consensus.nMaxAdjustDown = 16; // 16% adjustment down
        consensus.nMaxAdjustUp = 8; // 8% adjustment up
		consensus.nMinActualTimespan = consensus.nAveragingTargetTimespan * (100 - consensus.nMaxAdjustUp) / 100;
		consensus.nMaxActualTimespan = consensus.nAveragingTargetTimespan * (100 + consensus.nMaxAdjustDown) / 100;
		consensus.nLocalDifficultyAdjustment = 4; //difficulty adjustment per algo
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_HARDFORK_SIZING].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_HARDFORK_SIZING].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_HARDFORK_SIZING].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0x14;
        pchMessageStart[1] = 0x76;
        pchMessageStart[2] = 0x69;
        pchMessageStart[3] = 0xd6;
        nDefaultPort = 20144;
        nPruneAfterHeight = 1000;
		const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        genesis = CreateGenesisBlock(1480961109, 2, 0x207fffff, 1, 100 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x1ba3490ecf1653fbe7a53d1e0fb7e051c2a1c506d84f4dd3b01522544cd1fc6f"));
        assert(genesis.hashMerkleRoot == uint256S("0xe217ce769444458c180ca6a5944cbbc22828f377cfd0e1790158034299827ffc"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {0, uint256S("1ba3490ecf1653fbe7a53d1e0fb7e051c2a1c506d84f4dd3b01522544cd1fc6f")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "gtrt";
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
