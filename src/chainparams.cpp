// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2009-2017 The DigiByte Core developers
// Copyright (c) 2016-2017 The Zcash developers
// Copyright (c) 2018 The Bitcoin Private developers
// Copyright (c) 2017-2018 The Bitcoin Gold developers
// Copyright (c) 2017-2018 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h> // For CTxDestination
#include <chainparams.h>
#include <consensus/merkle.h>
#include <primitives/mining_block.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

// For equihash_parameters_acceptable.
#include <crypto/algos/equihash/equihash.h>
#include <net.h>
#include <validation.h>
#define equihash_parameters_acceptable(N, K) \
    ((CEquihashBlockHeader::HEADER_SIZE + equihash_solution_size(N, K))*MAX_HEADERS_RESULTS < \
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
    genesis.nNonce   = nNonce;
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
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.nMasternodeColleteralPaymentAmount = 50000;
        consensus.nMasternodePayeeReward = 25;
        consensus.nInstantSendConfirmationsRequired = 6;
        consensus.nInstantSendKeepLock = 24;
        consensus.nTreasuryAddressChange = 133920;
        consensus.nTreasuryAddressChangeStart = 500000;
        consensus.nTreasuryAmount = 15;
        consensus.BIP16Height = 100000;
        consensus.BIP34Height = 299999;
        consensus.BIP34Hash = uint256S("0x0000000000000181717c02ef5cebbfb3568887de4e6cb30525ac7b6f5a0b998c");
        consensus.BIP65Height = 380000; // not hashed yet ...
        consensus.BIP66Height = 360000; // not hashed yet ...
        consensus.HardforkHeight = 327036;
        consensus.HardforkTime = 1537617600;
        consensus.HardforkHash = uint256S("0xfa2a1f17edbb39496a4d1c9ee643797bc2b0d72dd9038e3646872c0fd7d3fd56");	
        consensus.powLimit_SHA256 = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_SCRYPT = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X11 = uint256S("00000fffff000000000000000000000000000000000000000000000000000000");
        consensus.powLimit_NEOSCRYPT = uint256S("00001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_EQUIHASH = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_YESCRYPT = uint256S("0003ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_HMQ1725 = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_XEVAN = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_NIST5 = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_TIMETRAVEL10 = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_PAWELHASH = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X13 = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X14 = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X15 = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X17 = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_LYRA2RE = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_BLAKE2S = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_BLAKE2B = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_ASTRALHASH = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_PADIHASH = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_JEONGHASH = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_ZHASH = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_KECCAK = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_GLOBALHASH = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_QUBIT = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_SKEIN = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_GROESTL = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_SKUNKHASH = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_QUARK = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X16R = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nTargetSpacing = 60; // 1 minute
        consensus.nTargetTimespan =  60; // 5 minutes
        consensus.nPowTargetTimespan = 10 * 60; // ten minutes
        consensus.nPowTargetSpacing = 60;
        consensus.nPowTargetSpacingV2 = 60 * NUM_ALGOS; // NUM_ALGOS * 60
        consensus.nInterval = consensus.nTargetTimespan / consensus.nTargetSpacing;
        consensus.nAveragingInterval = 5; // 5 blocks
        consensus.nAveragingTargetTimespan = consensus.nAveragingInterval * consensus.nPowTargetSpacingV2;
        consensus.nMaxAdjustDown = 16; // 16% adjustment down
        consensus.nMaxAdjustUp = 8; // 8% adjustment up
        consensus.nMinActualTimespan = consensus.nAveragingTargetTimespan * (100 - consensus.nMaxAdjustUp) / 100;
        consensus.nMaxActualTimespan = consensus.nAveragingTargetTimespan * (100 + consensus.nMaxAdjustDown) / 100;
        consensus.nLocalTargetAdjustment = 4; //difficulty adjustment per algo
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

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000006ca5a7a5a45e8f8b9c");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000000000000014cf4dc216dcc925bf0c6d7096aa6ab82e1af64e946d876df7d"); //200000
        
        consensus.nAuxpowChainId = 0x003c; 
        consensus.fStrictChainId = false;

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
        const size_t ZN = 144, ZK = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(ZN, ZK));
        nEquihashN = N;
        nEquihashK = K;
        nZhashN = ZN;
        nZhashK = ZK;

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
        vSeeds.emplace_back("globaltoken.org"); // GlobalToken base node II
        vSeeds.emplace_back("explorer.globaltoken.org"); // GlobalToken base node III
        vSeeds.emplace_back("lameserver.de"); // GlobalToken Node by Astrali
        vSeeds.emplace_back("pool.cryptopowered.club"); // GlobalToken Cryptopowered node
        vSeeds.emplace_back("bit2pool.com"); // GlobalToken Bit2Pool node
        // Hardfork Seednodes
        vSeeds.emplace_back("185.206.144.200"); // GlobalToken Hardfork node: 01/18
        vSeeds.emplace_back("185.206.145.201"); // GlobalToken Hardfork node: 02/18
        vSeeds.emplace_back("185.206.146.200"); // GlobalToken Hardfork node: 03/18
        vSeeds.emplace_back("185.206.147.203"); // GlobalToken Hardfork node: 04/18
        vSeeds.emplace_back("185.205.209.67");  // GlobalToken Hardfork node: 05/18
        vSeeds.emplace_back("185.206.147.202"); // GlobalToken Hardfork node: 06/18
        vSeeds.emplace_back("185.205.209.137"); // GlobalToken Hardfork node: 07/18
        vSeeds.emplace_back("185.203.119.194"); // GlobalToken Hardfork node: 08/18
        vSeeds.emplace_back("185.203.119.195"); // GlobalToken Hardfork node: 09/18
        vSeeds.emplace_back("185.206.144.201"); // GlobalToken Hardfork node: 10/18
        vSeeds.emplace_back("185.141.62.86");   // GlobalToken Hardfork node: 11/18
        vSeeds.emplace_back("185.141.62.87");   // GlobalToken Hardfork node: 12/18
        vSeeds.emplace_back("185.141.62.88");   // GlobalToken Hardfork node: 13/18
        vSeeds.emplace_back("185.141.62.89");   // GlobalToken Hardfork node: 14/18
        vSeeds.emplace_back("185.141.62.90");   // GlobalToken Hardfork node: 15/18
        vSeeds.emplace_back("185.141.62.91");   // GlobalToken Hardfork node: 16/18
        vSeeds.emplace_back("185.141.62.92");   // GlobalToken Hardfork node: 17/18
        vSeeds.emplace_back("185.203.118.117"); // GlobalToken Hardfork node: 18/18

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
        fAllowMultiplePorts = false;
        
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour
        
        strSporkAddress = "GP4r6YBda72vWgmK7m9z8JGkq3smhipTYb";

        checkpointData = {
            {
                {     0, uint256S("0x00000000fe3e3e93344a6b73888137397413eb11f601b4231b5196390d24d3b6")},
                {   253, uint256S("0x000000000001a9597538194df736eda73c35c17d78ec14ac99b9d392d0892ce3")},
                { 44446, uint256S("0x000000000004ddd47d2e6033af4d034e63171d61e4eaca2702f9e8b9a8ffdb5a")},
                { 87757, uint256S("0x000000000001356d0e351660b8356f8f6a12a5b029b2c10a5b47d753b8cd8f29")},
                {174987, uint256S("0x0000000000004a80520dfce6d2017d6f403a9def13fe99629d31f6b7a90b7c31")},
                {214590, uint256S("0x00000000000003886a3080ff818eb6027a98f1ac33c532b730fbe4c0fde704ca")},
                {282595, uint256S("0x00000000000000e335a60ca393eee3445f551d5bf6987e47d3a70e043b8dff5b")},
                {300000, uint256S("0x00000000000000c22e9be2faab7b2f05b0e834f434b0a82b0a12b55351b9d3c4")},
                {327035, uint256S("0x0000000000000072f4e5960b252d812991c4c13810b2324d623f824572cb5251")}, // last old chain height
                {327036, uint256S("0xfa2a1f17edbb39496a4d1c9ee643797bc2b0d72dd9038e3646872c0fd7d3fd56")}, // firt hardfork chain block
                {328101, uint256S("0x320c067ac8c5cdebbd12df990556b1237f0b41c7dac54a232906f4ce7a180655")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block 320c067ac8c5cdebbd12df990556b1237f0b41c7dac54a232906f4ce7a180655 (height 328101).
            1537709820, // * UNIX timestamp of last known number of transactions
            393073,     // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.0022863   // * estimated number of transactions per second after that timestamp
        };
        
        // Founders reward script expects a vector of 4-of-6 multisig addresses
        vFoundersRewardAddress = {
            "38yCbLtxZiWybYjJB8msaASL8a9DqSGH9e", /* main-index: 0*/
            "3LCZiCbkiyAH1saEXEnMC6XFVanVX6gftc", /* main-index: 1*/
            "3E99o64BavBxN855kFqbVcaiTmu3jBtnqp", /* main-index: 2*/
            "34KAMoFSwzKppWBg3u3XFMg1b6z3Xza9X6", /* main-index: 3*/
            "37Yy1xuVTWgPjUi6spagvkDqHZS6e3e6a6", /* main-index: 4*/
            "35NRzPB3NebkDgWu2w8vPNtDxVUixWpWTN", /* main-index: 5*/
            "3ARcDbReyavaETa42ZRQivARWp6Mh5jDSX", /* main-index: 6*/
            "3PFZ1oudGLkWg7kkV9qgosseuYsrhJd6ou", /* main-index: 7*/
            "34EBnTUYk3kzhwn6oNni1eyQ83vap4iVxZ", /* main-index: 8*/
            "37hNzkCuYGiVxP2AuMEmrBWQem4NQVUcJD", /* main-index: 9*/
            "35eZ5UFfdb5687GTdAK29hthEyzuXNcbcv", /* main-index: 10*/
            "37bUB14wvftu2c5mhgQbDh55rTDrGZQo4s", /* main-index: 11*/
            "38Xr5NCzbyJ1LJsouj2qNiuebyS4tNpwMJ", /* main-index: 12*/
            "3LpGTXpTi6aTTNsUyP58JwTSMyVYN2WBAd", /* main-index: 13*/
            "3NUuqPCcsPq66DQzD235pQGKTDyYg5zu93", /* main-index: 14*/
            "3DbSjJiJrVHpWEkhtPGtrdL73KFZRxmxuY", /* main-index: 15*/
            "33MnpZW33r5AUaQmxaTHpnV8KRVTTokC5p", /* main-index: 16*/
            "3HpDAy9591ykTcswgNKzPEBttc2cbMicdu", /* main-index: 17*/
            "3BmCBFZGwBNmEjL5hYW8ptQdU9pLKeQ8h3", /* main-index: 18*/
            "3Gm2qwZ8d26er6iLqFD3MQpwwNcbxQDnqW", /* main-index: 19*/
            "3LDQzQ5FguS8GiyDNgzSGz5oxHacoFYmTg", /* main-index: 20*/
            "3QMu3phWfKuM3Y5qTPjrexKBCDp1mU71JP", /* main-index: 21*/
            "35sHQwj5XRXMSqiiPhFipuifaKKUJSpbqS", /* main-index: 22*/
            "3NXRgZLxLjfFuBhrMHyMrjbJ2U83bChY1K", /* main-index: 23*/
            "3MjcgCvwtA2hkFKmVYhhfB3xvDASWpCPq4", /* main-index: 24*/
            "3L6zcGQii1Agabk37GFRPzMF6n9L9SsubM", /* main-index: 25*/
            "3QRa51mmERnT9voP9xq9sbpxmjAs1XWgqy", /* main-index: 26*/
            "39RnxJpsjRqgMyVd4Rg1gu1KyJHcQVsxTW", /* main-index: 27*/
            "373wRiUZ5DWCnGYp6Qf9hJU7K8LE5XT69h", /* main-index: 28*/
            "39QNaNjyrs6Jx5wxyZyaF7trXqRzAqYsKq", /* main-index: 29*/
            "3AdstaMFw2XEJCTQt8C5VE9dfDiLNs5TTC", /* main-index: 30*/
            "33SKqqm2eQ3yZd51L5SSKVJwNaG72ZW2xv", /* main-index: 31*/
            "3GMJ9wm8J7rHmAFkV4r7G3syr3ieK6ogZd", /* main-index: 32*/
            "3JekMeXUX156Tzf2itjpNzvJAQAU2YGn4q", /* main-index: 33*/
            "3EAkDi4uGhQML1XgjZQPPsVXHfGshSrfZc", /* main-index: 34*/
            "33QXMVBT7ChcHAjNHSzG71BSgrmmBxo6sH", /* main-index: 35*/
            "3DCmFMrw5PGAPcUbqbYoCKCpmBMyRvCpZA", /* main-index: 36*/
            "32mFdQSLFrM4fkUeFi4qWU1aim8ZPL36FL", /* main-index: 37*/
            "3FX9wE8aKQhHTMrWyqHEB7hKsGukEazvkW", /* main-index: 38*/
            "38rqrKRmVwgbeiz2zx6RVpPQqb4Xskx7zA", /* main-index: 39*/
            "3Mo2sPeDnfWTLRaNNom8Dcm9WMxRz3qYw3", /* main-index: 40*/
            "3LfpQbQRjRsHozwriAwsRBtvH2wLRJVtN4", /* main-index: 41*/
            "3Hq1SeTKqLdSLBNPo6JYBj4X7Ce7tAee9Q", /* main-index: 42*/
            "36V9JMDw1UBzwvmpvctG5DzfB6QhfsEA5g", /* main-index: 43*/
            "37Bf7wZju2JPvufDNDhoK64CjuCWhDkXoi", /* main-index: 44*/
            "36yU1RMzDnn9RYDqtxBvuiysH2UzXMVRRG", /* main-index: 45*/
            "34F9MmqFATfkHffTbh3hMze8itvpRZ1WHf", /* main-index: 46*/
            "3J15bzgdCjEJ5AiaAu6bbeYTvVP631F5Sd", /* main-index: 47*/
            "3NLZZ5aMd8ECQuKjyYBTtJT9XCavKYj4x2", /* main-index: 48*/
            "38SDhMU2h1z72h7kf1JMVWMoRbTRMDf4qD", /* main-index: 49*/
            "3Ft4BdrgT89yb4HU7mg4zdUtDsFJDrE2bg", /* main-index: 50*/
            "3NUjF1nqsSKsAHfD61Bu5AyTepH4jaeny1", /* main-index: 51*/
            "34Y8HjpExiR4snTM4pezn1s5MSiqyvWJwG", /* main-index: 52*/
            "336xErmdsAG8fckmWQ8dhCGjvjzLSmvXQK", /* main-index: 53*/
            "3LzwXBrDEUHaWU5ypz3MhKvwzUYopP3iML", /* main-index: 54*/
            "3CFqWmqXc6C4k5HU7W4cQH5E8pGsXkPMXH", /* main-index: 55*/
            "37irAKWm8wHRMxGCpo6VQHhaPV8d9CSyTV", /* main-index: 56*/
            "33zVmA7kqNy5ZsywXDYRDFuxY3ZJ2Q9UTX", /* main-index: 57*/
            "38FjYkPW6wpm5Vrw5pS8AQ9Jcbm16oT7ru", /* main-index: 58*/
            "36G3vR74nV3dXBhxgEGuSarGVMCMojnVCf", /* main-index: 59*/
            "3MKxQuvvCixyM5a27ERNTGEhUij88hscfe", /* main-index: 60*/
            "3KSsWWKaK3XiN7aS6dfRw7W6Ef1KxxnZkr", /* main-index: 61*/
            "3GVgdLd8XnWpEpGzfuiqkfcDfSEq6LHtzJ", /* main-index: 62*/
            "3N3w8v82mCF84Wu45Z3zvJJ4EpvrJB71Uv", /* main-index: 63*/
            "3D8gswKQTky51SZMDcmGjDohve8N9RH72B", /* main-index: 64*/
            "3CtjcQrKQC5j66eUy2E5ymGAhtoRfMjmr5", /* main-index: 65*/
            "3GYCnw2iTB1dWz4Z2Z7CGXg95owRHn82Pv", /* main-index: 66*/
            "3F5SdCzkRqhJsv3AZP4xV64vunNbMbMUuG", /* main-index: 67*/
            "3E7dHx6woKaGGXDCwodM8QVR7enYNMFyne", /* main-index: 68*/
            "3MzPTBgAfURb2BsySjwyLBa5n2rtX74LCp", /* main-index: 69*/
            "3CZQi1e25Tw6QZFcgy6qmcdBC8JPyyheJA", /* main-index: 70*/
            "3LHWbo1XQsnRWbUGRLo7NMtXoLhAXUdQDM", /* main-index: 71*/
            "38JMwNmtak2oPxMy8u665i7eRCRKYfLtwS", /* main-index: 72*/
            "3NfVcpwGu4vKFTEEc6XtTSGGkXaZphwsiW", /* main-index: 73*/
            "3PZhXT5afY4m8UzGhS6wuXgTsXHvGXAhEL", /* main-index: 74*/
            "31nKyg493rhMLrZxcKrzizSZTV1qBs1VnQ", /* main-index: 75*/
            "375HCkSJisQofpEneriuJDkbt97fd7oJVU", /* main-index: 76*/
            "32trHnakrEDMp7xf91tMNPwB88L47GQ3Jg", /* main-index: 77*/
            "3LzeWEYdVBafjHddMQbzFBTVZBjfVS926H", /* main-index: 78*/
            "36veTRcKaBQuFmzYABWQoQq5XXsFkRgWaX", /* main-index: 79*/
            "3PfrFds2bBjswYAWBztumZbVz8Y2gekgNu", /* main-index: 80*/
            "33XAjHXXhQSGKScXNqmEyJsmDGC9hFFTek", /* main-index: 81*/
            "3KEqMwV4zPcNREK2oMP6E9qKrrexKLd2Tp", /* main-index: 82*/
            "3B32oQkvkeCNA219T6ttVig6HxudHkqqeC", /* main-index: 83*/
            "37iH8TGH8pCQ4vUQ5t2whNZ22nhAv5bZac", /* main-index: 84*/
            "35Z9pCN6R5x8SEgMuBxCya8VYpZbHQ7Ra4", /* main-index: 85*/
            "3P1AGz15cQEj55cmE2kvhqaVUCCxR5LiAn", /* main-index: 86*/
            "3Ff1b5PBx1nWcXJnXPqBeGLmZvnHfpN5Jp", /* main-index: 87*/
            "32FBSE2RhWuGmASt5M1hsJHCCpTmQKnNsw", /* main-index: 88*/
            "3GNp5VfjvzKEyF4bhEqtRDfng7LVkj8fMf", /* main-index: 89*/
            "3DHuLMn7iXKUqYFSnMx8wambSN5nZLDy9F", /* main-index: 90*/
            "3Kt2iYY2Ujst29pwer4wYskaRDhVQ7vEsj", /* main-index: 91*/
            "3JfspqpmJvKa8jxv17RGuei3LgKAYZeQKm", /* main-index: 92*/
            "3NTiXYwM29SN1sYuRTV1KbPhG7jxwNWdo8", /* main-index: 93*/
            "3Pyn2vtC7ENYbQJCich9eixAXoLUPP9VVL", /* main-index: 94*/
            "3LCVYJfakAWb7uVzDmh35HxZaZMEdGtqE7", /* main-index: 95*/
            "3MkjEJpNs6raj5YyeZ5NjkmZZAnCSf5RUo", /* main-index: 96*/
            "3QUfD1upYLwXNSbvbc2ZwQhpGooCpN67nw", /* main-index: 97*/
            "3B5EWNUb8aTbztYn5VweMJjYh82EKiw3NN", /* main-index: 98*/
            "3QkgSVDCFtGUKXqSHmJkvoJJTSGYPuKsiT", /* main-index: 99*/
            "3NtpMQftrj5NFY49m42QR699ph7uXdYdKs", /* main-index: 100*/
            "3P2FjKAq4P8wvFY64354wbjXyngfAkfcfE", /* main-index: 101*/
            "38TtbsrtDyxCa16FbKDXSvPYsaPKaC54Zw", /* main-index: 102*/
            "3BXBYeZsLdztGHJTLyyyAewriMSeM529GN", /* main-index: 103*/
            "3R2UnNnYkfFCsSe4tfguwMgxZR7p76tef8", /* main-index: 104*/
            "3CRxYmcyRgs54g6PRhrQPWnda6qPuhTVwW", /* main-index: 105*/
            "3NqKS177B8yniKTdE3bnAZRiTE6QuWUrDq", /* main-index: 106*/
            "3LD9T3zZsZAfHKosT6fHomhgqL1Rcmzetu", /* main-index: 107*/
            "3Fcmd1Z9uwJa1hUs2H7PpPb8PcgvFG3Lwf", /* main-index: 108*/
            "3MYmT97nVhCPyV1jK3rzEcwuzUdWE6j7pC", /* main-index: 109*/
            "36Q6d3FCdcUvfri26cTmx6DomT1SGWMv7V", /* main-index: 110*/
            "34fWxLeGy1rPYCP8EX2V84uTo99iv7PBf8", /* main-index: 111*/
            "34gAdue4wjGU38j2NLtqrchPbtbRdGnnj8", /* main-index: 112*/
            "3QnuyuFcfMjfWYMQkdcrNEmuupqBWE43A6", /* main-index: 113*/
            "35xZdSqFbNxyFG5CH1UtHpxtZdJraATUac", /* main-index: 114*/
            "327VsBYqw7nKn7bQe7vBDvAvkqGuPTBvRf", /* main-index: 115*/
            "3Gz5JCEAdoRzLQ4x3Mki9VuFJ5iWgMvJqM", /* main-index: 116*/
            "3MRKgkhjtLepNAmMdzVZoRY66KC9DQh5SR", /* main-index: 117*/
            "3M8U8SMaANXgRsqHRw8D7PDYnxfjaPatu5", /* main-index: 118*/
            "3CPkwFYp3Nv8G4fFmMpxjp7ZDUHvUNgVtR", /* main-index: 119*/
            "38kCS1cEHGV7shQonScjA9REFE88Xk8Poq", /* main-index: 120*/
            "3AdMio1L9GkFxNm25N7tzc9GL2a3akhLwg", /* main-index: 121*/
            "3EZDNuhf9e4jT5txxrYwEivupvq26oZTVC", /* main-index: 122*/
            "3PUnYwwDQqqbWduDk8RusM6UVMZfR7uydw", /* main-index: 123*/
            "32LhJjEgUaLMCsr9awopBYpkb2buRLUNJA", /* main-index: 124*/
            "3Q87bZLS8rGhdns5e7PU7in43gzCtdqqxp", /* main-index: 125*/
            "3GkNnmj2uaCvJgXLfcByboHMzAAzuMug9j", /* main-index: 126*/
            "3KghqCpYbvVuZnSMDYWJ2iTEemNMZLVk99", /* main-index: 127*/
            "35yQVs2mxuGzwmDWkEmJnZbzui3gE97vd6", /* main-index: 128*/
            "3C8fEzaQez9LbXTvkrnPyQhtv42tT1u6Jg", /* main-index: 129*/
            "3KzGQ318dwDy4seHvERBaWzB4Mwe6rz4jM", /* main-index: 130*/
            "36sYYKBT3hzbSMMDatr26iNTseiNx2NBA9", /* main-index: 131*/
            "37UBBLqfZFEAYtTXBdb2Zmn3TVj4iXa4KG", /* main-index: 132*/
            "3CEmppDduSBCupN5oGCsXr7qhWE74nmH3K", /* main-index: 133*/
            "3K42gh3pUDtkCGSt1ZXmmEt4tu1xo19e7K", /* main-index: 134*/
            "339pSdqFQegx7E7Z7CVtna1DQMPfc2bu6S", /* main-index: 135*/
            "352xrPMNAHXqbS8K2Pt1yPvYm6y3NZHSpt", /* main-index: 136*/
            "3QzcsuMSm8QNpNW4fRC1W5UsN5W4ZnGEsC", /* main-index: 137*/
            "3QyJA8vS1oJVPEzPhbah1KpDBEtWEgkLdb", /* main-index: 138*/
            "35Twiyhrer1w78wSt1hT2HwgqMXkr2STb5", /* main-index: 139*/
            "3MX8G7CwTrZuzWpzC7CSdryA9tbSbKyg52", /* main-index: 140*/
            "3AQ4GwPn8UVTix52XpNArGssctSZjYhFXQ", /* main-index: 141*/
            "36NYWYzaETPF9qt6gEM8QW6bVzK4TT5duj", /* main-index: 142*/
            "3Q8kDeGrnCRhxwPHvk6Wy2M2joScKqAAoM", /* main-index: 143*/
            "3QrTVzA4MYZcvVABrZtWD71CdkkChZYyFn", /* main-index: 144*/
            "3FgH71NP6ZkYjrKB8eEAZxEzidDxpekLPx", /* main-index: 145*/
            "3McqZ9r4PBErSJgbhVPRhoHwg5sPmQErzV", /* main-index: 146*/
            "33DQx8iB9RgvqS7ekXMWuaZjrC28RQTrTR", /* main-index: 147*/
            "32A3GmN3FPgxXSnGv93aMrKTsH1ZUt6J1s", /* main-index: 148*/
            "3DA61HhbJR1Kuuk2AA99ToKRecNG7ojqBf", /* main-index: 149*/
            "3ECMvfpT3MREQPckbv61t9xCBRA5Y1xJdQ", /* main-index: 150*/
            "36catUTZcgS23swgjh1AeDcDC7ancRJnm8", /* main-index: 151*/
            "3EyxzsG66NkXKmUWs3n3WcbarwoShbvJ5r", /* main-index: 152*/
            "3HcHkdhMM1AEMc79aWVw92YVMHwv5aLDsP", /* main-index: 153*/
            "3P2XqLodgkvdgoXqKwa6Ge69hdFq92bVQ7", /* main-index: 154*/
            "3EkgzCSmeUDtamedhgbVooHDyKhgj43QXW", /* main-index: 155*/
            "3MvzDkWopJ3Vh5i7KiiZDwbowVJEa8NZrh", /* main-index: 156*/
            "34BSQn3jZwUr8VK7bkkFGQxsw4Vv7tkgf3", /* main-index: 157*/
            "3Htvtz2rFKRkAqabPgaiRyLbnajjegqWin", /* main-index: 158*/
            "3CYxb4SzypvwzjtvuhbHibf1ZmZ6EYSjCx", /* main-index: 159*/
            "3PxcP5rEKdH4tNPdN3UiJCuTPHZXW9MXij", /* main-index: 160*/
            "3EsJDBYSZCnaB9v1hDeqPckqeKXy8QySRm", /* main-index: 161*/
            "3D828EGfChcinqQeqbFb5TLSUwdnYo1dfX", /* main-index: 162*/
            "3PxLuz6HdV88Lxn3HVyVnnjhC2xdmSKetx", /* main-index: 163*/
            "3Ks8X1w9WHUW5JemRS4HLGZxQM9zRwwkXR", /* main-index: 164*/
            "3JQtuE2YsGeEob7VJ4cQninbpnEKdSJSEV", /* main-index: 165*/
            "3HnLB293NiLB9uKbSNm6UBgJ4fRJQ9EorZ", /* main-index: 166*/
            "3J2xEh8uZvUFedXjPfAM7TsaH5CW3rTZyi", /* main-index: 167*/
            "31s3vQS6rsaMvZVdw8vvrwdTDE2aTvaxRD", /* main-index: 168*/
            "34hXfyWd7nxvZpoZL5oQ49D6f5gv2Mgmi5", /* main-index: 169*/
            "3A2KjgCoRPQoRFGPFAYXALL41XV61qLgTZ", /* main-index: 170*/
            "3Eec4xaDYzqscKn6yHYQcLqn1dQWFARJGD", /* main-index: 171*/
            "34EQdEijpysNa2raQSWmWYkGuqC9HsyBPi", /* main-index: 172*/
            "3BEtieHw9zTbgqQ4SWKY3NgLWKocJQin14", /* main-index: 173*/
            "397LfRVUUv4bPg87bAicX2ZJNjmXAeTsaX", /* main-index: 174*/
            "3CpVtxLuqWahpizQvoL5FagES87eQYMdv1", /* main-index: 175*/
            "3MiWgep6PN9ER6m5Q9M2BF1ue2P8EWoDur", /* main-index: 176*/
            "3QjaTkSjh9wpQeoJQDawuPnYmzBi2cdk8E", /* main-index: 177*/
            "399efdC8i96ty7eSmGz9BY7LeLgqxaJVex", /* main-index: 178*/
            "37TAUMisXVPRSfn5V4zVctMUfShXsN4hb1", /* main-index: 179*/
            "3JUDpkvLQ5H4A9sHErsBZYAD1pqqenjcd3", /* main-index: 180*/
            "3AAKNjncAgDzgdUopt8VSPtSW1pZgMG3bh", /* main-index: 181*/
            "3M3GpeV1zdXrLKuHPkF5dd7hx2hCoPDHHm", /* main-index: 182*/
            "3CjdThLEGY64ae8QSPdXkLdc6PcWmR4uyg", /* main-index: 183*/
            "3Dq5Vpf8vHMyTTqjdvQ8QmdJ1xuDJCHxmH", /* main-index: 184*/
            "39Vp9y8Zs6y3KGsQ1TYGnVpmvxnbtnExrh", /* main-index: 185*/
            "3Eh3ZgdriS2VC7zhFxriwegHZFP5VfKvbf", /* main-index: 186*/
            "37CdPV77gqAeRvhJ6g3A42tCjzRScvaDN6", /* main-index: 187*/
            "38njzLR5e4DmxYdse7nuTNrvX7mB3S1i4D", /* main-index: 188*/
            "3KsjXu34QqmecopuTpijUbjoAKUEfjKr3K", /* main-index: 189*/
            "34kGxzuyqanj9JxySGb7P5CYQAsj5DM866", /* main-index: 190*/
            "3QvkWcatgwx1xtW6gwkESv6cRzRuvgho29", /* main-index: 191*/
            "3F28fn9QbPWUFZe54BPpLAeydWZZrTQSZV", /* main-index: 192*/
            "38ywnbmBA8Zqiw57zNHbcZLZhHrYFe3sGE", /* main-index: 193*/
            "3BoSPyyt64hmty3KXuTezfSFPqPdYkZZ5H", /* main-index: 194*/
            "3LytkmUYQrA9kw9zUECQPN3YnQyCPZ8Zo4", /* main-index: 195*/
            "3QdBFrQ98dCiVAwNnKiunqiJjQKdZscCbb", /* main-index: 196*/
            "35zeh5YrRTv67g6Eb71wvbWLzRBTLtTTQJ", /* main-index: 197*/
            "369wiY66VZvHeTmv2JSCnyNSgQQXxqFcDG", /* main-index: 198*/
            "3J8CH2gJJ9KKQdBPwqcDaSKH6R7yHK1Wrc", /* main-index: 199*/
            "381GBtX7CJktiY9XaXvwgP5FuJtbtmJHeS", /* main-index: 200*/
            "39a3kTwQe6j3yTiC4obVBHsunNeYj2btBU", /* main-index: 201*/
            "3G1EDWEo26qgbANigEHuHaVZLVsgAb14BV", /* main-index: 202*/
            "3DSr5GZWrCyUUX2JFL4DTxd2wHGWfZQ9GD", /* main-index: 203*/
            "3KLFgnN1uJ4DyYch6yX5rtjbiGrPJvW2cx", /* main-index: 204*/
            "3QjrACUhn2KtHCSkcEFk1qSymMDB2YzpFc", /* main-index: 205*/
            "3KE11DMprkJKVzktQtAnqGVaEJf49W2LrW", /* main-index: 206*/
            "3P5nH2fqsiT1a6id2W5h3Ztd3gF2zPMjfh", /* main-index: 207*/
            "3KAd9J9Fotju5BUKxgMNcAvTcWkNEU2THD", /* main-index: 208*/
            "38JGPLA5QaKvT68iwsySrHhvgWo6hcU4wv", /* main-index: 209*/
            "35euaC6WRJpGctAqNA8CY1VXGueysFX43o", /* main-index: 210*/
            "3CVwgKuLJ759fEqEhT2vvRan2z6Kk44sZh", /* main-index: 211*/
            "373qoQnWB2Czgw5uxhjstdTDg5XxJTB517", /* main-index: 212*/
            "39PHUZosWU1dmoX3BLLknQMek39drr4H97", /* main-index: 213*/
            "3MCFLUfeg3hU5D72LRwXTytyfyD7HgKDyV", /* main-index: 214*/
            "3KJg3umjhB4PkQ7SpgpA595EENzR1f8nUg", /* main-index: 215*/
            "3NUKYEAKVDPtRs4m9dzNsJWJv8UfnHoJ1c", /* main-index: 216*/
            "3R1Fq1pcQ8cF3GsBDFfUQNeAA3F32R4nP8", /* main-index: 217*/
            "3LaaRVv9pEuvahAFMh7GYxxzkTczTRovkd", /* main-index: 218*/
            "3GUnM2CJtgFmJYhGmhcSwobpHEFgjG86sU", /* main-index: 219*/
            "3BDwSefYRgJByDmFdpciSQMW2ssxLxfj3H", /* main-index: 220*/
            "3E686878MUybFh41PyboqeUiPwzngpTEPM", /* main-index: 221*/
            "3Et5zaNcFbeQnpqBzwkDaeiMRSDkuc9Gh8", /* main-index: 222*/
            "3FnMhVsk9rk4EgZxsevURdwKdiYWA3Mmmw", /* main-index: 223*/
            "3HFAturVtmQKe37nQdx7V8XhHpoioXbkCz", /* main-index: 224*/
            "3PYHwsDfzFAUsiH62tCzxPKcwD6E2DuiMK", /* main-index: 225*/
            "3BiPHWPCkdREchi3YqG7zULbDDRRMdAXVi", /* main-index: 226*/
            "36ZvRygdAi7iDpBEzfFRSSxAMEFGmXwy3C", /* main-index: 227*/
            "3LXRER8Jd9HVJxB2ozbbs1SFJsPLYsZ7tB", /* main-index: 228*/
            "3F55HwRyhksHseNuJDJd4zaRQajw5N8912", /* main-index: 229*/
            "36vvS9rjLnsocaNH3JMHzp1H4ioAgJdH66", /* main-index: 230*/
            "34qSCUEvhSa9J9uzXN9TaiuRfSwGSAaPnH", /* main-index: 231*/
            "366wHf5Fjo5NWR5jAYGJbPTiz829auez47", /* main-index: 232*/
            "3Hzh8qRXvp7BzJZLWHp2kCxaThgBiitSxH", /* main-index: 233*/
            "36xKdfiCwb4YD8XHgRMDPHuHaS5rDHquJ9", /* main-index: 234*/
            "3PtXzAj8UJYfT9SVJWvBtDdoKozQ5V9Gzx", /* main-index: 235*/
            "34TRXSmup6wV2SKpExd5jHwi548QCvtD34", /* main-index: 236*/
            "3Lx1RBHZWZRbkTQQfhU2eoCUoRJUG2CTfu", /* main-index: 237*/
            "37otJGC1jaGf5ZznuftnUWavMKYHuxStcy", /* main-index: 238*/
            "3Hf2LU8JZVDLQy5KpXfjaHzBc2AYfZMgch", /* main-index: 239*/
            "3MUteP9qMPvLxngqwoHihzzFtamt96eGKg", /* main-index: 240*/
            "31m63dqrMTtmnZiUUtEymEwdoBHcvzSUWN", /* main-index: 241*/
            "3FM18WCSECPxUS3zBRZttDxMJpmnAXo6YY", /* main-index: 242*/
            "34oRKmhgepK9C1BYsbjw3ZaD9bX7SVUeXu", /* main-index: 243*/
            "3HFTKbTFYBPBetdEriBsi8tsdHF5cMnWad", /* main-index: 244*/
            "32rWU7EAdpa6jKtYoz3XTCX2fHe5mnR6q5", /* main-index: 245*/
            "39Fenwocb7veTRhZhFMeBtMBoKnNSksM5V", /* main-index: 246*/
            "3HZhkeTckS9xJCDnYQk5uWc5Hi3EMr7Kr3", /* main-index: 247*/
            "3FtJmjpVBB3AwRgpV7khiT34aRs9Dxiodi", /* main-index: 248*/
            "31ugxYKGQXsofqwnXaft2fZHJPyEWsnvh5", /* main-index: 249*/
            "3PqNm37UuKExZn6XxmLUq6a6U1Bo4FzSuC", /* main-index: 250*/
            "3LR2Yx15V4mj3nTCrYWCRudiwgGSMfVySP", /* main-index: 251*/
            "37nuPE3JnPmF8bAAhwf5atX3xoHezhza3p", /* main-index: 252*/
            "3NG5SU6FnjQQSdC8s6sWBaPUeBivEXBo3s", /* main-index: 253*/
            "3MPZVFZ7JBsnKYQbXqNzVH7u3mVNLLpQVM", /* main-index: 254*/
            "3Dt9zLTJTBoua9Bt667jdpYYgHeFBmVxUs", /* main-index: 255*/
            "32CVTt3Fj8RBqfY8MwPS94UqALG4ncgS2E", /* main-index: 256*/
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
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nMasternodeColleteralPaymentAmount = 12500;
        consensus.nMasternodePayeeReward = 32;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nTreasuryAddressChange = 600000;
        consensus.nTreasuryAddressChangeStart = 100000;
        consensus.nTreasuryAmount = 18;
        consensus.BIP16Height = 1;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("00000000238f0fdbc6d992a183ecf735ce0009f5ae2088ce8014370fcaaec7e8");
        consensus.BIP65Height = 100; // not hashed yet.
        consensus.BIP66Height = 10; // not hashed yet.
        consensus.HardforkHeight = 2153; // not final
        consensus.HardforkTime = 1537185600;
        consensus.HardforkHash = uint256S("0x944140d0c734a7a94ca0b306cd3ad8c9bfe70889c927ca6c4852e5644b621733");
        consensus.powLimit_SHA256 = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_SCRYPT = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X11 = uint256S("00000fffff000000000000000000000000000000000000000000000000000000");
        consensus.powLimit_NEOSCRYPT = uint256S("00001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_EQUIHASH = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_YESCRYPT = uint256S("0003ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_HMQ1725 = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_XEVAN = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_NIST5 = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_TIMETRAVEL10 = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_PAWELHASH = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X13 = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X14 = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X15 = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X17 = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_LYRA2RE = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_BLAKE2S = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_BLAKE2B = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_ASTRALHASH = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_PADIHASH = uint256S("00007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_JEONGHASH = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_ZHASH = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_KECCAK = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_GLOBALHASH = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_QUBIT = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_SKEIN = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_GROESTL = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_SKUNKHASH = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_QUARK = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X16R = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nTargetSpacing = 60; // 1 minute
        consensus.nTargetTimespan =  60; // 5 minutes
        consensus.nPowTargetTimespan = 10 * 60; // ten minutes
        consensus.nPowTargetSpacing = 60;
        consensus.nPowTargetSpacingV2 = 60 * NUM_ALGOS; // NUM_ALGOS * 60
        consensus.nInterval = consensus.nTargetTimespan / consensus.nTargetSpacing;
        consensus.nAveragingInterval = 5; // 5 blocks
        consensus.nAveragingTargetTimespan = consensus.nAveragingInterval * consensus.nPowTargetSpacingV2;
        consensus.nMaxAdjustDown = 16; // 16% adjustment down
        consensus.nMaxAdjustUp = 8; // 8% adjustment up
        consensus.nMinActualTimespan = consensus.nAveragingTargetTimespan * (100 - consensus.nMaxAdjustUp) / 100;
        consensus.nMaxActualTimespan = consensus.nAveragingTargetTimespan * (100 + consensus.nMaxAdjustDown) / 100;
        consensus.nLocalTargetAdjustment = 4; //difficulty adjustment per algo
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

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000100010001");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000000fe3e3e93344a6b73888137397413eb11f601b4231b5196390d24d3b6"); //0
        
        consensus.nAuxpowChainId = 0x0078; 
        consensus.fStrictChainId = false;

        pchMessageStart[0] = 0x3a;
        pchMessageStart[1] = 0x6f;
        pchMessageStart[2] = 0x37;
        pchMessageStart[3] = 0x5b;
        nDefaultPort = 19319;
        nPruneAfterHeight = 1000;
        const size_t N = 200, K = 9;  // Same as mainchain.
        const size_t ZN = 144, ZK = 5;  // Same as mainchain.
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(ZN, ZK));
        nEquihashN = N;
        nEquihashK = K;
        nZhashN = ZN;
        nZhashK = ZK;

        genesis = CreateGenesisBlock(1480961109, 2864352084, 0x1d00ffff, 1, 100 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000000fe3e3e93344a6b73888137397413eb11f601b4231b5196390d24d3b6"));
        assert(genesis.hashMerkleRoot == uint256S("0xe217ce769444458c180ca6a5944cbbc22828f377cfd0e1790158034299827ffc"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top

        vSeeds.emplace_back("134.255.221.7");
        vSeeds.emplace_back("lameserver.de"); // GlobalToken Node by Astrali
        // Hardfork Seednodes
        vSeeds.emplace_back("185.206.144.200"); // GlobalToken Hardfork node: 01/18
        vSeeds.emplace_back("185.206.145.201"); // GlobalToken Hardfork node: 02/18
        vSeeds.emplace_back("185.206.146.200"); // GlobalToken Hardfork node: 03/18
        vSeeds.emplace_back("185.206.147.203"); // GlobalToken Hardfork node: 04/18
        vSeeds.emplace_back("185.205.209.67");  // GlobalToken Hardfork node: 05/18
        vSeeds.emplace_back("185.206.147.202"); // GlobalToken Hardfork node: 06/18
        vSeeds.emplace_back("185.205.209.137"); // GlobalToken Hardfork node: 07/18
        vSeeds.emplace_back("185.203.119.194"); // GlobalToken Hardfork node: 08/18
        vSeeds.emplace_back("185.203.119.195"); // GlobalToken Hardfork node: 09/18
        vSeeds.emplace_back("185.206.144.201"); // GlobalToken Hardfork node: 10/18
        vSeeds.emplace_back("185.141.62.86");   // GlobalToken Hardfork node: 11/18
        vSeeds.emplace_back("185.141.62.87");   // GlobalToken Hardfork node: 12/18
        vSeeds.emplace_back("185.141.62.88");   // GlobalToken Hardfork node: 13/18
        vSeeds.emplace_back("185.141.62.89");   // GlobalToken Hardfork node: 14/18
        vSeeds.emplace_back("185.141.62.90");   // GlobalToken Hardfork node: 15/18
        vSeeds.emplace_back("185.141.62.91");   // GlobalToken Hardfork node: 16/18
        vSeeds.emplace_back("185.141.62.92");   // GlobalToken Hardfork node: 17/18
        vSeeds.emplace_back("185.203.118.117"); // GlobalToken Hardfork node: 18/18

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
        fAllowMultiplePorts = false;
        
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        
        strSporkAddress = "mnGzwQeK4FkhQfYGMYKfuXHq29DJN1MVzd";


        checkpointData = {
            {
                {0, uint256S("00000000fe3e3e93344a6b73888137397413eb11f601b4231b5196390d24d3b6")},
                {1000, uint256S("00000000001f423e19a5ce9d10a1263dfbd83654da9183c25f7fcfd7fc25e458")},
                {2152, uint256S("000000002439acbc366328335e435f25e78ff1f884fabd00f359a66c7865a1f2")},
                {2153, uint256S("944140d0c734a7a94ca0b306cd3ad8c9bfe70889c927ca6c4852e5644b621733")},
                {2155, uint256S("41b4196ea0d0b0c3651e3129d5757f0336f7f016f75a5e14e37988d5f1e35173")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block 41b4196ea0d0b0c3651e3129d5757f0336f7f016f75a5e14e37988d5f1e35173 (height 2155)
            1537710402,
            2215,
            0.0005422
        };
        
        vFoundersRewardAddress = {
            "2N6nSQHMMF3NQnFvxoogeDjpmENQjF9nog9", /* main-index: 0*/
            "2N1CchGDNvDtPjKwyvm34L3gPhMzLNip4eA", /* main-index: 1*/
            "2NDSp2itA9Xv9BZ9yFnFqDDRyCtKog7Ug1y", /* main-index: 2*/
            "2Mv7i5QAKiaMNcCDTC2BGKsdB7h1XYRorAv", /* main-index: 3*/
            "2N7na2VR3W8AdUcyYub7budhpAgQegj4Ebs", /* main-index: 4*/
            "2Mt2cQk7siP82Vwymve4uyv2mNwdaKGCXsv", /* main-index: 5*/
            "2NAu9pYUgFPZFCXqbSKDGiiqjG5X99RkiMh", /* main-index: 6*/
            "2N4qQ8zhcCQzJuPnfUeiqx6ExnMFk5G9Aq3", /* main-index: 7*/
            "2NFHSiw1Hrhihn5zX9cGPfr3bRJAqTN5DNo", /* main-index: 8*/
            "2N9kiEtFxEkxec1DjUkG2tjzaUEATJ57ygm", /* main-index: 9*/
            "2N3PkBx66qK6qi8L9PvPss9rWUiYJWtaELp", /* main-index: 10*/
            "2MtcN9haxXiXqRwJRiWuP5QhV6tkSUA2Hwv", /* main-index: 11*/
            "2N3hhbgGXHMDQm1Egmo3o3dt1PppcwfYAc3", /* main-index: 12*/
            "2Mv4rrJ1Bo5vs4qovXCtyGP5CWwhGgZpsbL", /* main-index: 13*/
            "2N4JyRxX9Cz74KTEtx1K8ZaaDCDq2T4Qz19", /* main-index: 14*/
            "2MuvZ6bhLAb2pWoVC5Ap4gpYVuHaAVduPxn", /* main-index: 15*/
            "2N9EXDmSQQ6BSyaNN3ecVDD793PqsYWoobs", /* main-index: 16*/
            "2N4AeeQHSsvYjaVTLCmUrXpNH98kGVmizLr", /* main-index: 17*/
            "2Mya39mqGJFDfgB4iSMrL79of9RduAEttpn", /* main-index: 18*/
            "2MsW4Jaao3n1Wc9u6NdbDtmSBSeCSZzQzhx", /* main-index: 19*/
            "2N71JnNDBydxigACT7TvzHcfwKQaW58C5YS", /* main-index: 20*/
            "2N6JcvqA8hw5mm8THx81EJM266BnH1fho6G", /* main-index: 21*/
            "2ND96srprgjCeCewJi6tDj9Mf4i3VsXiPqa", /* main-index: 22*/
            "2Msj3KdY3RnGkWzLfq5dGGVKgDVjUePqF9S", /* main-index: 23*/
            "2N71JKjPbV4Paufy3birWC51VZpqhA1tFi4", /* main-index: 24*/
            "2N9yUwjE3CnBJUbaqy5nXs4zz6yxjjFHH9o", /* main-index: 25*/
            "2N4hrw6RxCo2XM3d4CERH8WZmj3cnHNd2Ab", /* main-index: 26*/
            "2NETQSHGkko5Gy3pddRSEPaZJE4vjhKHa2s", /* main-index: 27*/
            "2NCyAmoxXjeN7Av28CVLyiBjvpuDFCmWvU1", /* main-index: 28*/
            "2NFusZxcfv2V4cXNHZs4NWbCpYEn1JZNTAQ", /* main-index: 29*/
            "2NBLBHFLXJaogwmd2ZnVNhWtmVuehrrb1C4", /* main-index: 30*/
            "2Mz2hxWjiSzw1V4MZPHJnk6xY7mouAdzC4B", /* main-index: 31*/
            "2My43kohYz8mnkQhuahoXX4S3LBuK6iqubN", /* main-index: 32*/
            "2MziArrv6mVkfw2rNne4cCgq5Wx3kDR75F4", /* main-index: 33*/
            "2NFyL3RgqATHvwHZMMcguMKqv38pvBoLZZp", /* main-index: 34*/
            "2MuvwkwWueLHco6eny1tGPJbZDFaftdAMu9", /* main-index: 35*/
            "2NGQRwYXtRWzpAyzRddkUjpSZwv6CugwS3v", /* main-index: 36*/
            "2MzbDJcQwFuahgyn8uhDsrWgZQa2LX5afUz", /* main-index: 37*/
            "2MwjC2sRdJBoGtLWpkMBMTve6Kzwcgup7iq", /* main-index: 38*/
            "2NEFwdaqigmQo9eYR3RsJbHdTd9XHgYTGn7", /* main-index: 39*/
            "2N8xhuE4ttwmQ3EBQexLn2dTMUn5F6g6mQp", /* main-index: 40*/
            "2N9F1YR2N8qhgxRnbHWfSo5uE1Zav8baQJX", /* main-index: 41*/
            "2N3X4STbQFHDGhbrcSXJ3FDcmL9C7Z8wKwx", /* main-index: 42*/
            "2ND81xRBFzQhsBxti8czfEsMMDjGVhhecnH", /* main-index: 43*/
            "2MwMnfsoPgJGcuWTnWXEFvmWdirSJjJ8uFk", /* main-index: 44*/
            "2NFhZd963FfqAZjqEvnB3VTBinYns4Mj6L2", /* main-index: 45*/
            "2N9MncS59rbmMVkK5V7u7CwffC2vkNdaBDg", /* main-index: 46*/
            "2N8WprmmMvMFtbLG9Sga1Swg4VVsVSCARhs", /* main-index: 47*/
            "2MvJBb8DzRy7EmEQFNfqrLsUeGxeBSuNWPi", /* main-index: 48*/
            "2Mv8L9n3q5RySj4Z3WJfiHsSPp3Y91A99rb", /* main-index: 49*/
            "2MsoeuyESW3LsQH6tPymencHS6DKDSoUBEm", /* main-index: 50*/
            "2MxRBfTHdAoUJhJ5Yi2iM92PRz1vZBX6Jsg", /* main-index: 51*/
            "2N8AysBVxBKY6pFbkHdMgJDsDvBEW33FKmu", /* main-index: 52*/
            "2NAXCrwtX1BYZ12Yik2XLkww4pt1gijgYDg", /* main-index: 53*/
            "2N87Zfk8tcw6dRydDQiWnU43yWijnrdJz3d", /* main-index: 54*/
            "2Mu1UdV7mq1YC7tEVP8mNuAioBCgoBEQGPz", /* main-index: 55*/
            "2MvaWuM5e7ieWrjQF8RfYNQDVi4LSbcREPs", /* main-index: 56*/
            "2MtehGipvc79Hv8BcGNiCAFY3WZzM8EMpxs", /* main-index: 57*/
            "2MsotzefamhAqwZZLd7XF2dLWRavesNHDBi", /* main-index: 58*/
            "2NG2dzJCjdGjSGaWBvn7kfR5CsrDYMaCCcz", /* main-index: 59*/
            "2N7KxJheSRJsE5F9eAG1pfYcVDGEShcYxwj", /* main-index: 60*/
            "2N8TFnEFhLi8XzvVWu9VNu3wDJge8Du1Zzo", /* main-index: 61*/
            "2MxKLNdZ4sEo5rfPAgnijC8TJPWZQwy8pVT", /* main-index: 62*/
            "2MyMMx8b1QkaoZZoSouBpB2GyN8FC3VJJTU", /* main-index: 63*/
            "2NGKuypUQbr3yN3Qg3HFBzLoCQGmh2CzLVe", /* main-index: 64*/
            "2NEJYN4Gh9u6aUr7bj3bQkFs3oWJdwWJrP1", /* main-index: 65*/
            "2NDBwizUHAxxVDg3EVfwEwccDSxLKy5NsYf", /* main-index: 66*/
            "2NAzub1EwJ2SA2Qk2Qf3dZuXpFD4veyUMwG", /* main-index: 67*/
            "2Mwq5KE6iy2vi6usaA4ThDoN2kDT72ix4FX", /* main-index: 68*/
            "2MxvVUnwQERhC8MwdzJFAbAxDCHa1bmJHzd", /* main-index: 69*/
            "2N3xMWDcweTYKKRJRr4yZEfCojespY7dAsB", /* main-index: 70*/
            "2N8s5SHUw7wh9vHpDgKRfTndZvKyAXCD7E2", /* main-index: 71*/
            "2N5GGm8EoNgSojQzjdnnhd9SisB6UiYkV9F", /* main-index: 72*/
            "2Mw9HobqWZAwYmms3Q62LXam9nSHeWEGKgg", /* main-index: 73*/
            "2NBP1d5FkhwSS1K2A3hfNUpkQt8hvTTCJp9", /* main-index: 74*/
            "2N6m49LLVcexmdGbiiFFY3EmUgsSbSVnYZ1", /* main-index: 75*/
            "2NA7CKF4ixnBb6Mh3SLuzNpRpkhebgHB5E7", /* main-index: 76*/
            "2Mw9Pc8gA6AAv4YPDEUq21qvZJhMnTbpXoX", /* main-index: 77*/
            "2N6TV46jwMTCxPMxzaZy64LFZouEXX85bbh", /* main-index: 78*/
            "2N4vUqRCu36ffuE6RL67s2yWcYmCY32tr5G", /* main-index: 79*/
            "2N1dD9RBXzADmPvJ1K9hXPrQcNXqryRY8Ce", /* main-index: 80*/
            "2N4LUCym4RE6p46GZjCbpMZFDLkjMLDcvn5", /* main-index: 81*/
            "2Mta7893Leh8PW5opag6AyG9pgfDZS78qFA", /* main-index: 82*/
            "2N4kXPRQHeUNGBbeSUbLoCLUcxwDWtfkpuW", /* main-index: 83*/
            "2MubArQ9Vp9GUJzqgDadvoAG54SdE51josh", /* main-index: 84*/
            "2NEouGwU1gFTg4Pp7uYSgnMu5Q7FQQXJncq", /* main-index: 85*/
            "2N5pdWbhs6RFGXYCZEqGc9mZ1K5oYd8eCAT", /* main-index: 86*/
            "2NBzEYiBiu271pJGxY9KFLVHVp8TDDbreCe", /* main-index: 87*/
            "2Mss4zWJzRC5pBTASCTtL82165tcUiWJmWw", /* main-index: 88*/
            "2N4DtELXQXFFwbVYmRvQ8cU3CDSEiwF2YVA", /* main-index: 89*/
            "2N6tbupRn6z9UftwHkemd3zqP4AT5SwCuG8", /* main-index: 90*/
            "2NEBpB8aUEy5KspeActFheWrgR2SYhTn3WX", /* main-index: 91*/
            "2MwxtfkZrbHrYNNpVJW1h77upo8SxtYtKeA", /* main-index: 92*/
            "2N26z9SAuQwgEtDqN45rrB86wtCRDc7FyEw", /* main-index: 93*/
            "2NAqZkyp2LLAqok2vYeByoABkyFvxUam7aJ", /* main-index: 94*/
            "2N8QkMbi7gifS8pXBv5rnENbtsq1Ux8aGxc", /* main-index: 95*/
            "2MwjErwGsMJTcg3pksx7RQRrZqdJQttaaUi", /* main-index: 96*/
            "2MtmpK62qWzFVXgqqNSPMMRyow8rr3ifrVW", /* main-index: 97*/
            "2N7zutg27jJGRbDgjV9ZFBEp6rJpBfdpD8u", /* main-index: 98*/
            "2N8bTNbVhofoHnYWFcd4zs9YdKgTu2MfVe1", /* main-index: 99*/
            "2Mxhe9tkfub8eX63Fo3UyH5JGmLnu3UJmd4", /* main-index: 100*/
            "2NCRGcCftCSyFd7ynmCC3T5AHRse2LWtGZw", /* main-index: 101*/
            "2Mu12d4HbUYBVwZjv5acFF8fN7jSTPEe1tL", /* main-index: 102*/
            "2N1BAwnQidR7aeapXDknHEmYMzHvYyTrcSR", /* main-index: 103*/
            "2NE1kakMYo2EZqmRk2uJC3hU5qZBTz7q82n", /* main-index: 104*/
            "2MwV3KrpbppJXPW19zEMC9HGDkK48wARYSq", /* main-index: 105*/
            "2Mxc4v4rniNS94scqFy3dDNJrQFiKapbij2", /* main-index: 106*/
            "2MxuP8YR9sVRmX8X3xGr3g55CLjWKeQ9rgn", /* main-index: 107*/
            "2Mumja3gVGJKWJjssjT6w5mWGtTEQKPrq9p", /* main-index: 108*/
            "2N9D8JudCF77eufrkWE5zgjJzgRtXgED4Nj", /* main-index: 109*/
            "2Mxqxfu2Zsj48MFd8c6P7gan3XjrPYDWsqt", /* main-index: 110*/
            "2MxmrWijmkZFPekyhgcKiduwX5sGHCYkaw5", /* main-index: 111*/
            "2Mtymm4vTTQPHbLtupna15p4j77XebCzeJF", /* main-index: 112*/
            "2N25jhMQUuVVzQqYxzfov4p6vexqHapwkFD", /* main-index: 113*/
            "2NCdVFgmtCg8U4bnX8GLKFoz5SnY3nbZ28F", /* main-index: 114*/
            "2N5x3iEVKXUye1a38WRbjZFDoQyLNzuoFTv", /* main-index: 115*/
            "2N8BZKfm8H2QwDrzqiEx384TDNstdh3zXjP", /* main-index: 116*/
            "2MxDrmeqoxw8ArBf91m5SQ6FzGbrZBLcFft", /* main-index: 117*/
            "2NBms9yukti7ZyBz6RjZDu5tjHDmBt8pS6D", /* main-index: 118*/
            "2MwNxRAaQrW3kev2w3yezoo5ENN4khF5LV7", /* main-index: 119*/
            "2NBiXixRefva8EaDnarijKhsphqZ64jszWu", /* main-index: 120*/
            "2N87cwpgipBPGD7T5SDHJHDbZiUZz2Z1UcK", /* main-index: 121*/
            "2N6EVXUS9WzJfEUnjsNhT6ohXDrYGhJ4mJx", /* main-index: 122*/
            "2N4fDaHLXXpD1MCjCnzGykf4xNzRsQHgkoz", /* main-index: 123*/
            "2N8YbBDxv3PTAkREia2Daca6zoN8bSSX5Kf", /* main-index: 124*/
            "2N7YscmMjDZErEDKg6K3eXM7h7aqkB4ATcw", /* main-index: 125*/
            "2ND1SeRZBqF3Dx2vDVrLj8KbZvBSYy2G9q6", /* main-index: 126*/
            "2MyRMcE4r31KJkeGXUSq9iJoLqawgHCMDZD", /* main-index: 127*/
            "2N5LRNsB2v5P4Bs8MVjDuUYoBCtAXCPDcb3", /* main-index: 128*/
            "2N7oSHXVcSu1QsYJRsjeyTrMWivRCftxyjt", /* main-index: 129*/
            "2ND4hBc7fLhsd7PZBpSJCxr3ZyBwAY1YG57", /* main-index: 130*/
            "2N6h7hkJ5fE5isxEixzPqwqxoXibWaAkX9K", /* main-index: 131*/
            "2N8H6YfMRjpkQ5MNV1WG7sAtQne3sRNdd3z", /* main-index: 132*/
            "2N6Ji3pJ4qsqWLJttNfnJMkpNb5eoXnbW2w", /* main-index: 133*/
            "2MymYj4zAzd8rRftcza8GyYm6VTdynu5YVs", /* main-index: 134*/
            "2NFG44JVfLPeCgSYgKanHoqkrsX6m39TRtx", /* main-index: 135*/
            "2Mt4XDN9Ws2xyhGPLy2F5USitbjgS5soFy1", /* main-index: 136*/
            "2NAyNpaL5GkHx6aipY5ATpDTHbgbjFv9kLG", /* main-index: 137*/
            "2MxncYnzvUuKPDCYnTPhV3RzrhgBKpmpLTr", /* main-index: 138*/
            "2NDWVGBq8f8T5uLKJs7RWZHcisEV4iWAPkm", /* main-index: 139*/
            "2NG1CMjDTzJf3mkdEhDn26u2X5carEciKzu", /* main-index: 140*/
            "2N3aYnqAVThUxf9rShRTxS7xV9e9GNz73BC", /* main-index: 141*/
            "2NERLnkU8W6jkqW171nF4uoKDMN3b6G2qp5", /* main-index: 142*/
            "2N1apozdVbELkvRaHPKf7U6q41FQDmLyG83", /* main-index: 143*/
            "2MxafzJqXxcUhaQvH4TZVZww6DhqbVc2W5S", /* main-index: 144*/
            "2N33Erz5113EtufxLPG1WWzWwhywx1F47jK", /* main-index: 145*/
            "2MwFV1eXJmVX5gVfnAYYQ4TQGnvyJ5f4WRf", /* main-index: 146*/
            "2N65pwhweYwnnowaRWgJHFjUf3sYj7138gL", /* main-index: 147*/
            "2MyjBQKSXJs62omG5NK2dmT6w9VAMJyxaAR", /* main-index: 148*/
            "2N9Zmx3hHvBP9aRJChJPMXD8prTbwm1xC21", /* main-index: 149*/
            "2MweygRuPp3XDpFGQKgLARee9bNeC9aGFmA", /* main-index: 150*/
            "2N5qoa9xULV7b3f9HhCA5CCGWATj1bwM3FM", /* main-index: 151*/
            "2Mvdh1bCsNvCkDmUp7cob8dwa2gXRmU6Uwn", /* main-index: 152*/
            "2MzPUMykkiQThZgRc19on1CUpPLZbXagwkG", /* main-index: 153*/
            "2N7cZGgqML6hYeGKAtp9zKJzM52Kz8fy6ZQ", /* main-index: 154*/
            "2NCyKSsmRrrmCqFA9nqTLx3KvwRGAWTYPHT", /* main-index: 155*/
            "2Mvr2ps6punKtaLGEDEBMcsVQCVMF5kEntL", /* main-index: 156*/
            "2NFfVY9fvNfoHoPTA4cB2RTagpkvDpziH1y", /* main-index: 157*/
            "2Mtu5veCSWjFDEu82ZfcBrVGzZg8FVGNpzc", /* main-index: 158*/
            "2N1jni2NyYZGdA6F5C1asDzf2y7GQdV1SqF", /* main-index: 159*/
            "2N8MVnYyocfGQu4Ygo6b5LZdzPV1ZBjxyLX", /* main-index: 160*/
            "2NBBjCwq3Es4sDDYA3DYmHT47YQrJAFJ9nS", /* main-index: 161*/
            "2Myz9MQVU1HiXuYWaSiThEQhnNoJ6237JEp", /* main-index: 162*/
            "2Mw2tur9GAuhSpNsDJAkFrrht5DfFSFnfjo", /* main-index: 163*/
            "2N9Sn9Nfqnkxa8nqySVT25fsjUy4oXBaSf1", /* main-index: 164*/
            "2NFNRj5ZR7PeLvvBZi5nPCep5XdV7WphPaG", /* main-index: 165*/
            "2MwUUuVEhYM65VLmuQgk9PUUbC1dDCepMdM", /* main-index: 166*/
            "2N3u5ashpqhMLKcC3G3RzQ4VZAEGPPPr7Hv", /* main-index: 167*/
            "2MxhNaFSgJ2tKWNDq9x8rJz5jbawgEKjYqc", /* main-index: 168*/
            "2N1UiMFH3KVwJFVfKNUQzrJ29Qp9Kvui33g", /* main-index: 169*/
            "2NFhLLY6jUmwV9suhToKkbJTXy1y5z7nPAH", /* main-index: 170*/
            "2Mtm3GjgMGV2MHFyCDrHA9doX6sys4vfw6T", /* main-index: 171*/
            "2NBdWTbUZXmGz8aV5jXfyJaDd3xHzAk9QqB", /* main-index: 172*/
            "2N7JW79mEf953zBJ2G2W8orHEJ5Be4pXQUH", /* main-index: 173*/
            "2N7yzub9apLs4RWe8zdJLrEDmBmHXrxUYTD", /* main-index: 174*/
            "2N5tcU4c4hNFwVnLna4uT47JcxQfxERJftF", /* main-index: 175*/
            "2N17FeDBUaRTD6iJ5Ucoh2JL7xrsJgBnQhn", /* main-index: 176*/
            "2N6BL4KSgdpQC7s1cfwmqF5mmhBwkhAfgDR", /* main-index: 177*/
            "2MyCuzDkbMTpGaEpy4zq2A8Cy5aqTtUoUq3", /* main-index: 178*/
            "2N1e1YZYmSAMfTQGA7CsvBN8wRnCRESQuLm", /* main-index: 179*/
            "2N72iVkXyxSw3x9JDgWy8piFLbTHupFj5R1", /* main-index: 180*/
            "2Mvv9Qa4oaZxCB4yMMD3x1fCuiRL9LCxLsy", /* main-index: 181*/
            "2N4u74etrgAfxSNMSAZ8DotUZfZcRuoq6Ao", /* main-index: 182*/
            "2N3miCyotEG5GGhKB3eeZH5qT6So1Xebepy", /* main-index: 183*/
            "2MuVNNVy3oDksYo7hJkvYASXNwZDfdgCk6S", /* main-index: 184*/
            "2NBRxXiMXXyeDRakfqMywTipDHC3UsNnXhv", /* main-index: 185*/
            "2N2PbdzNn4Xzs1LU7SqjWVzeP3AuA2sn3fQ", /* main-index: 186*/
            "2Mz5qo1MkM8vGc5HtREj2R2VvNm85Mk6TBm", /* main-index: 187*/
            "2N3YwTYSWK44kUtdEV1FgmiZqCypUoLkyNx", /* main-index: 188*/
            "2NG3ftN5s3dKMEqirieYYprZaPVvy6NuFLL", /* main-index: 189*/
            "2N5Q1iapoSak9gkG3KXA4UMVmxHeJ3gugXt", /* main-index: 190*/
            "2MtkXMS5fEBVGF8SNRH65NmzVmMHBxpe2Fk", /* main-index: 191*/
            "2N4CHJ7SgPW6k3Q1Yv6HbpGWavMmn5uzF6P", /* main-index: 192*/
            "2N6EgUVoVcqMUpzJMHhicvp9sbeQEN69paU", /* main-index: 193*/
            "2Mv6tCCR6mA4NQbP8cv1U9ChzV75y9VoNjF", /* main-index: 194*/
            "2NDLGY1C1dZcUzAr41mUDz85sK4Ly1zZ63X", /* main-index: 195*/
            "2Mw7g6REaRSqa9yTHgqwBftxdjxaUrpmQra", /* main-index: 196*/
            "2MuDTmYSNuFQUPBLCo2yFWQ2vfk5cmdMS6S", /* main-index: 197*/
            "2N1GMWngyCfLUsnCzQxAAD44unDWHDAEyNu", /* main-index: 198*/
            "2N1SfRVtvCxPtbmbviM5a6TJ8VPJYaW7TDC", /* main-index: 199*/
            "2NCUs7QvCAYpYU9spCMF4XxTH4vBmxK5id7", /* main-index: 200*/
            "2NDpCiQBrfzejrM1CA35GHX1hMQ1tUdq29Q", /* main-index: 201*/
            "2NFMzmJVJdncuaAvGrLvnPQzGyR3dg1UVNA", /* main-index: 202*/
            "2N5JEwCiqutyL1WXPXJ88Hbuujan12smo93", /* main-index: 203*/
            "2NCJ7uuSF7xatVZxzYLcsBhUUyTsotNkgCx", /* main-index: 204*/
            "2N4HohhPS9xvuvV3joSAC9fkHXTq9W75j1p", /* main-index: 205*/
            "2MxxPJgk4YfCaDemW9dLFqs93CJWDKCVdGJ", /* main-index: 206*/
            "2NFPNxfW68xyP5GMkbm94eCZfVV7q8auiPX", /* main-index: 207*/
            "2NBUgBRfCSr8FJQ9VbLDbCreo1iNqxQ4h4U", /* main-index: 208*/
            "2N3DitNFNXKDK5QbGmsRhCf8Ha9bWPtkLux", /* main-index: 209*/
            "2NGWZcgrVndeQ1dwdVML3qqArJQo9Jb5oUb", /* main-index: 210*/
            "2N3h9dmCZqggK2ooTU9kLeZS339uMqtpEiH", /* main-index: 211*/
            "2NBCczriyCcTcPwuYx8Ni3pFcz3mwTPXC1Q", /* main-index: 212*/
            "2ND6MQC1WEPyDBNF9MPc9irCsq8nSKHSfCS", /* main-index: 213*/
            "2MtdKTkFn89yWGraWCV8YyeXdmY6vPHLci8", /* main-index: 214*/
            "2MywEsinmmMTJ2MBrBsX6x1h6Hk2vmYT2E6", /* main-index: 215*/
            "2N9aBGLVeuqWzhw4RTqbDEZLqgYZSCCoPAC", /* main-index: 216*/
            "2NFg2c78dyFtM3CKgJgv5kyWsbFkKKh57KD", /* main-index: 217*/
            "2MyrghShUhvShpj5d8vjcB39onR8vx8wNgA", /* main-index: 218*/
            "2Muo36GM2vMe5mifSKfs4PXz584erm4YTu1", /* main-index: 219*/
            "2N3TiZHFZoJnHUzHFpFNFe32dmaSdBh62QY", /* main-index: 220*/
            "2N9BVqzoE3RET1wdUXQ57CqnCbiFFLYtqYQ", /* main-index: 221*/
            "2MyaA5pywScDy6NZvwQHKYWn2butMNyJXzq", /* main-index: 222*/
            "2N5jUvGau9wy1uPPakXJzHh3yAMCPUmRENs", /* main-index: 223*/
            "2N7mcNuPD2DVGXctgmvmxY34YQGiVKs73iH", /* main-index: 224*/
            "2NDgTBHcHMutVjh51wV45g5izxDkrgmq5Ee", /* main-index: 225*/
            "2N2YkuUzvNs68KtjtSFUYTD3uEkmnYRR9wM", /* main-index: 226*/
            "2NEDguV2tj7cptMsWZKkGD2tDgqM42QWXHp", /* main-index: 227*/
            "2NCNx4U7Tpq6qwYweJnSjYm6cD6kv2p7gyc", /* main-index: 228*/
            "2N8PSgw6SHvDcpXG6xwBorNQi9AwWUvTmT7", /* main-index: 229*/
            "2MxS3sP2DjCSMoho6aKb3e2fU5yhKUePMhY", /* main-index: 230*/
            "2N8wyU29TZXeB8xDhNvFqicdEcWyQJZYyvG", /* main-index: 231*/
            "2Mztd4SShShdKWzMopK5FeWKzxTkXseX4dC", /* main-index: 232*/
            "2N3YhYfNKzFNVGkx8sV9WkVF6ZfHobjzu3z", /* main-index: 233*/
            "2N2KHzTZR8FhSBs8JWdg5XNdkv9DK5WQk6x", /* main-index: 234*/
            "2N98i6wh4AWouUVTYMKuaZL8rNzKyvemm36", /* main-index: 235*/
            "2NG2GPUs4kzSo59v1CCZMvLzYnigKMDSSLF", /* main-index: 236*/
            "2N5rQJBXomEXYVCu7viiTGvk9GWJ1qKgQVa", /* main-index: 237*/
            "2N494WSn1rwuE9didpR4acGYRWVwU5Bwk1N", /* main-index: 238*/
            "2N1eoZCLDUqUzgBup9LzVKir8fQneWfx1Mn", /* main-index: 239*/
            "2Mv9jZorqrLVu1wQHTNjmjrf65awTcTdcei", /* main-index: 240*/
            "2NFgjKPtZqnUrPw4qthDUVrPoSqNXQCYhMt", /* main-index: 241*/
            "2N25kgKoYtdSMPDQcgqGzesTszUEnKuBCAf", /* main-index: 242*/
            "2N7eEwaQpSRnduH3zFk5yC25seAQ13pgzu5", /* main-index: 243*/
            "2N8PKx7FCyiMV5fejNSkjNNnyJN2wJbAD4b", /* main-index: 244*/
            "2NAK9oCZUM1NoYorTjdtKu6VU9E3f9ED2Xx", /* main-index: 245*/
            "2N7MtfpCK1MCrBmGKnHoVGWjDP7u7pTtqbi", /* main-index: 246*/
            "2Mxf5sq1JkL6z88TfX5Vo2NqqnW9pbyG1eG", /* main-index: 247*/
            "2N41iG9aDDwLk4KZMgMgX9xTQNNsjq1nggj", /* main-index: 248*/
            "2MzqfjtZ8snHnmAYGKanLtwrKmeypHZEqBM", /* main-index: 249*/
            "2NAishB8D6WDCmo58sQtih38obGk3bearqu", /* main-index: 250*/
            "2Mx6ETXMgYbi77oaCkTC2EuZfgyN5pySZa9", /* main-index: 251*/
            "2NA3C4x66BidXsi3FgR565jDSQFgHeHyc11", /* main-index: 252*/
            "2NCoNsXZCeVhCfLhBDmFftJ7uHTakjv8Nxj", /* main-index: 253*/
            "2N4rnQxeqxUtRt4f6PMLZuheHZnMaEtYd8V", /* main-index: 254*/
            "2NBhiyi6mohK8F63nRWczfoPRWSC97YDDzH", /* main-index: 255*/
            "2MtTFJ2zSR1bLQWz9qt2JKjzGriVUFKvNDr", /* main-index: 256*/
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
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nMasternodeColleteralPaymentAmount = 7500;
        consensus.nMasternodePayeeReward = 30;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nTreasuryAddressChange = 350;
        consensus.nTreasuryAddressChangeStart = 500;
        consensus.nTreasuryAmount = 10;
        consensus.BIP16Height = 0; // always enforce P2SH BIP16 on regtest
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.HardforkHeight = 100000000; // activate hardfork here by the given timestamp.
        consensus.HardforkTime = 1537048800;
        consensus.HardforkHash = uint256(); // there is no hardfork hash for regtest, it will be just activated with the timestamp.
        consensus.powLimit_SHA256 = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_SCRYPT = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X11 = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_NEOSCRYPT = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_EQUIHASH = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.powLimit_YESCRYPT = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_HMQ1725 = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_XEVAN = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_NIST5 = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_TIMETRAVEL10 = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_PAWELHASH = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X13 = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X14 = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X15 = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X17 = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_LYRA2RE = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_BLAKE2S = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_BLAKE2B = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_ASTRALHASH = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_PADIHASH = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_JEONGHASH = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_ZHASH = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.powLimit_KECCAK = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_GLOBALHASH = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_QUBIT = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_SKEIN = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_GROESTL = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_SKUNKHASH = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_QUARK = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit_X16R = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 10 * 60; // ten minutes
        consensus.nPowTargetSpacing = 60;
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

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");
        
        consensus.nAuxpowChainId = 0x00b4; 
        consensus.fStrictChainId = false;

        pchMessageStart[0] = 0x14;
        pchMessageStart[1] = 0x76;
        pchMessageStart[2] = 0x69;
        pchMessageStart[3] = 0xd6;
        nDefaultPort = 20144;
        nPruneAfterHeight = 1000;
        const size_t N = 48, K = 5;
        const size_t ZN = 96, ZK = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(ZN, ZK));
        nEquihashN = N;
        nEquihashK = K;
        nZhashN = ZN;
        nZhashK = ZK;

        genesis = CreateGenesisBlock(1480961109, 2, 0x207fffff, 1, 100 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x1ba3490ecf1653fbe7a53d1e0fb7e051c2a1c506d84f4dd3b01522544cd1fc6f"));
        assert(genesis.hashMerkleRoot == uint256S("0xe217ce769444458c180ca6a5944cbbc22828f377cfd0e1790158034299827ffc"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fAllowMultiplePorts = true;
        
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        
        strSporkAddress = "mqakdpV7YNSnfobctsdSt6GmDzmQTEMois";

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
        
        vFoundersRewardAddress = {
            "2N17UdNZBM2U4FXNjecYVV1mPUwQWtg1XzH", /* main-index: 0*/
            "2MwtUKWUjmVsLWtaj51fbJEtrd2DNbYqDK2", /* main-index: 1*/
            "2N8nwjXu9AdmbCwGQJu9aKhmiXWykTEhRkS", /* main-index: 2*/
            "2Mv5eVh9SsnMfsy1N5QYduPCGDRNp6Kj39S", /* main-index: 3*/
            "2N3RfcjrKAsDsGwFFN5JsfgPxodQk1HxLzn", /* main-index: 4*/
            "2NGJCAL9hFtWj6acfU6C91jFaLxBsWyHaaP", /* main-index: 5*/
            "2N7FsHXu67uPbttMAgwSgAcpYsrFFAyCGYB", /* main-index: 6*/
            "2MwQVBDcKm7CjdZ67S8dEEQiwbeeQLuT4rF", /* main-index: 7*/
            "2Msn8SaEduyQevmWWTTrZRKVZGJibbLdzvw", /* main-index: 8*/
            "2N8kP8VkASJuhUDHxpdN95VqPCyEnFCi3N4", /* main-index: 9*/
            "2MtAsa9V4ertX7DGfjgvdNwr8GNXqUw7rZz", /* main-index: 10*/
            "2N6hnmzHtBzRu2RYFsLYmcuNceFXmq4jBfV", /* main-index: 11*/
            "2MvzC4tWxYUgT6Fc2iWzmGeRs3U3LVEkaw3", /* main-index: 12*/
            "2NEDz28G1HEEwK1vdEHiy2oYSokuFZvvRr2", /* main-index: 13*/
            "2MsVB2LFLQPA7tXZLZXNvPJX5yhtZtueMs1", /* main-index: 14*/
            "2MwFsPHTQQ1xFDxMar4b4YNn7bWo7VHL4RU", /* main-index: 15*/
            "2MxMEUUgk8EQN3Lxofb5V4sDUdFAgq9rfaQ", /* main-index: 16*/
            "2NCJGRv3geiQAQwvXpHiSHUi6hjUvhSvq7e", /* main-index: 17*/
            "2MvqZnzar7WsHLZnUDbVum2YJVy61fttQoS", /* main-index: 18*/
            "2NF4cakN8q11foekqPhhfoHVaexCuqpf1qx", /* main-index: 19*/
            "2NCU5MZmr1tJBK3pPAwKuefukas5KdyDPfH", /* main-index: 20*/
            "2NAjMvhCRLkyzJTUmTKJr1BLyTe24yKw6af", /* main-index: 21*/
            "2N4pqGNhQyny4tvWzMV9NxrLyWq4XGF7dri", /* main-index: 22*/
            "2N9Heh7Y8goSKDLkJU7Wxp3MnJZbT7Njcyx", /* main-index: 23*/
            "2NC85tMoGP4aiturXZq17wemK1WrVNESDUy", /* main-index: 24*/
            "2MxHFHaG6CbdnHtsERXaYZW1gSFrpPnE3BD", /* main-index: 25*/
            "2MyVx85jgwYAQxfnVxHXF2Km4Ci3BoLvrvn", /* main-index: 26*/
            "2N1y5MZVcyXTc1yF9wcvQAe8jRiYTUHwnTY", /* main-index: 27*/
            "2N39MVuvLwHqpjjYzN4dAZSucoSArYSBzCz", /* main-index: 28*/
            "2MvUnTMcdgtBsqvvEFBBtRqZW51Bu1AVkMf", /* main-index: 29*/
            "2MtJLiYsBWgRqdu7EzDzKbUKaR7HkbUopYC", /* main-index: 30*/
            "2MzwnoxWYmTFLP4tfZPWxy6jfCV2mwigjG6", /* main-index: 31*/
            "2Mu6Km35fTzX16XMj4XjGGXfNgdLBZHdMVt", /* main-index: 32*/
            "2MxRJu8qJw3YCDr6m1Eb6v7k4SazjSiWRm2", /* main-index: 33*/
            "2NG2YBMkapGWLf8S3cgF2T2DAQErVjaCa2F", /* main-index: 34*/
            "2NEqCUpURCeFjvWqTiruWifco2vq6T99eHy", /* main-index: 35*/
            "2N5SjT4ssUVipJBnexjy5brcJXCbbU19xyZ", /* main-index: 36*/
            "2N2zwsEj9Y3K2G8ESL1JmgwoyHPq7HS8Aya", /* main-index: 37*/
            "2MvQ73eibyiJtWWTbcZ1chwFZLw3wWC2y38", /* main-index: 38*/
            "2N7zud9cBS7RLNLonrfvgRrSbyA7Mpcj4Av", /* main-index: 39*/
            "2MzisRthqhMivhb8JrjgdCXAm8LjGNxgpmM", /* main-index: 40*/
            "2N8M417a48dZQUXckopWfx1ABirajsKUHA5", /* main-index: 41*/
            "2NGJi8qrVfmVhKofENj1DLmfW4VrEM8tydz", /* main-index: 42*/
            "2MyxLP15DzNt5ofCBS7KVNBE8t5ZNNZ7on5", /* main-index: 43*/
            "2MsFjrA3fhVdjmGnRARKa852ZLVfkAts49G", /* main-index: 44*/
            "2MvgG8ta4dQNvZNjWghq3g2Qz25ACYoXGXT", /* main-index: 45*/
            "2MwD3BJRaWLQXLASKijdG76s37BeaT9Dos1", /* main-index: 46*/
            "2MsvKX5UcFoGLusryTkgeFe74qzA2nJUbag", /* main-index: 47*/
            "2MskMaN6CaDgqNGQLzHd2Jc9tFaEckqLNKg", /* main-index: 48*/
            "2N34AfY2b5iAX8e1Dj6FRWFxanHteU61yD9", /* main-index: 49*/
            "2MuvtJVs3DLEjsquAkfZt6nETbuaUqh8U7B", /* main-index: 50*/
            "2NDTRVJCjdGuQWJzxMty9MERnyHc3zZ7yEH", /* main-index: 51*/
            "2N2urPffKZix5g1kKBqkubshQHrQQrtVNjR", /* main-index: 52*/
            "2MzwN1n4DEVN1j1QFDVsfHBqNKCKVgpH38y", /* main-index: 53*/
            "2MzayuRCNqUKH2SEgM1XQPP4PdDjEbGv77z", /* main-index: 54*/
            "2N6UgEsqQN7ncSw2sSJ6yMGC6WZLRcuG4Sp", /* main-index: 55*/
            "2ND8AJw4ihAcUQzxjiDBMmb7JFJF3t8jnVn", /* main-index: 56*/
            "2NCQaffpEniR5zxkZNk1dwDb5MDP1dEU6VQ", /* main-index: 57*/
            "2NEmZo5PtTRtDzMj82goB8XVJcfZ3y4csrV", /* main-index: 58*/
            "2N7AuNJuvmgGQEo8Lbrhx1TQoypK4YieCBq", /* main-index: 59*/
            "2NAAs8FiJ2ZdKY7az6vdcWpCADRCN7vMX1v", /* main-index: 60*/
            "2N5FrQJwqWJ95yRhuuwK9wx7PkC9F9NsjnA", /* main-index: 61*/
            "2N9Wkci3xfcg9e83nGVfrbeNkGfJ3ody83V", /* main-index: 62*/
            "2NBkA7Eo8kPRi8RmNWHBPfaTTkRdFJFbhvq", /* main-index: 63*/
            "2NDzuCENr8cSoUG1v4ZRJKxfo9cYfFnN78X", /* main-index: 64*/
            "2N25xuGmQ4NJBxudqnQ1Z9PCXkWhPNnXZVZ", /* main-index: 65*/
            "2NF9UBsMsCUvmMaPTpn24YtNmi26vx3ydcZ", /* main-index: 66*/
            "2MxzuED1zYgAiFHcWkG4JVHVy8YcDxa1Mk6", /* main-index: 67*/
            "2MwPVtH6WPhzHVg8fUDXWSCgUp1HG3sniW1", /* main-index: 68*/
            "2N873Sk7Cfv2g8wYZdPAWFmv8MeSA5CAvd8", /* main-index: 69*/
            "2N7fezW9sBGJwrdBfdutZc5cWTxTwGaBqMx", /* main-index: 70*/
            "2N98bmMiV38t4iCHUqrGkePE2xFzuC4nQGF", /* main-index: 71*/
            "2N3aWFwXpwEsDVV6fSbatqrCmt8veisKPdq", /* main-index: 72*/
            "2MvqujCxXwgxGV3tdnRUuPAdAaQNM6nLcpS", /* main-index: 73*/
            "2MuPHLSdLCgo4MbjtPUoZ1ZryzFSfgw4e4N", /* main-index: 74*/
            "2Mz4a1KPbz7cDuwLbLogdkiCJxHtC1F3HUS", /* main-index: 75*/
            "2NBPzn4y2koGNE6kfxnLsbmyqor3ZbKKaig", /* main-index: 76*/
            "2NENzoxQhZ6oD2UHu8vrxFbivDXzCLULCZg", /* main-index: 77*/
            "2MxV8CpUv8QeaHReE1NcfsaJuBshAT6b46C", /* main-index: 78*/
            "2MtEQSnuA917X9Fww3381PbKyPxYr2ga3Ws", /* main-index: 79*/
            "2NGZXVc5jhS1buJPgJx8GqN2vpeceu5G75C", /* main-index: 80*/
            "2NAtEAtkVykwGyh44NNxSdKfN1TT3PkF3Vu", /* main-index: 81*/
            "2Msykr4wyRoi2SNE3MBWrubP9RP2GGNL22w", /* main-index: 82*/
            "2N6ooCwEKzUc2qmLiPyt646sZRZXB8Aq8MH", /* main-index: 83*/
            "2NA6yFACsgDRvDqGfF92p2TCGsTYRS693Se", /* main-index: 84*/
            "2NCrpVrXcP4ADWkE6pHGN9kdHq69QS3hfje", /* main-index: 85*/
            "2MtevGQ48XnX3KcV2WDf9KCK8hb24Nv9Yk9", /* main-index: 86*/
            "2NFhsXYCEuJzZP7QeVqTmV4Prj9x5TpRWHM", /* main-index: 87*/
            "2N4P1novB5uDNoDx3jw4McURP6B7bPssdCx", /* main-index: 88*/
            "2N8c21LoqQCM1vawYtCL8MJw6xZynfJcprU", /* main-index: 89*/
            "2N68fZBqddJPDLEzpGYhtk8zEahKXw1y9Vy", /* main-index: 90*/
            "2N3S9fRgSCTbtrRpPn55pKw3HxEM2jcJGvh", /* main-index: 91*/
            "2NFeu9hRw37dsKDTKvX7kXgx8uVPS7vYW5z", /* main-index: 92*/
            "2N2NG5mn4Ec4Za4eL3nwGtM6mvuxmngJ3ax", /* main-index: 93*/
            "2MtYXDC39QJs9cc8uMupwPguugHtKPwchr1", /* main-index: 94*/
            "2N7NUWz7k5YBq6NTnLZz4BBdi1gUVHePT6b", /* main-index: 95*/
            "2MyJBaXMPFTCY5zdXJoyscuy1kv2T9WS4Z7", /* main-index: 96*/
            "2MsdBsSuCe1FiMmQQ2SHXCzGhJwmcHRqzdb", /* main-index: 97*/
            "2NBGauWNzKmnT6T1WW6UCf6bUSAP3ENn72B", /* main-index: 98*/
            "2MxwQztxFVFfrxR7eNdJHomZN4LJuv3o6pJ", /* main-index: 99*/
            "2MxegXJJbp3jDqiSGki1jNuxUY3r21CWAiW", /* main-index: 100*/
            "2NBKQt8qrLJ8G2cHwY3rJY6CSY2fosXP2D6", /* main-index: 101*/
            "2N6GNYR9ppTrmNZitfE2i3vX9B8qwMoaype", /* main-index: 102*/
            "2MwJbzPCutqp4LDXEr3wVFiyJaMNFVhke9P", /* main-index: 103*/
            "2MvEuLWWzu6gyjomm6TwE6kRyydnSz5JQYM", /* main-index: 104*/
            "2N9HBtrmap9f4k93aYg5C8KF6oaYiD4v2j7", /* main-index: 105*/
            "2NBaHWZh59gMs6Tw9nFAZCVLD4cQVvzHEey", /* main-index: 106*/
            "2N2QjTu9k9nV6pCywy62Vd61P2upoHmjqcY", /* main-index: 107*/
            "2NE6fNsmaqbAD4XTSa7zQdRsDAttThjeVDj", /* main-index: 108*/
            "2N4N7gWmWBmT5U4GqAc6eRqPYKUjX3UP7eT", /* main-index: 109*/
            "2MtnCGmDFytgM5TchmFxhDKu7ErtohXEjcP", /* main-index: 110*/
            "2NAPLquNpBFbTFUbk8Y5En14FPWXhjRgafz", /* main-index: 111*/
            "2N8DbCRm8juJResyRjmyd1oH42oGKsAYVxt", /* main-index: 112*/
            "2N3A5cRw65gkYXjgvNAofWsmN5Jy9QWCmWB", /* main-index: 113*/
            "2MzuT97EeYD5HgFWLmmNayNSaEEVHBC6BYi", /* main-index: 114*/
            "2N5HwgatefXaowGCNuQAPgkDA9RWivzgkw9", /* main-index: 115*/
            "2N2b3rHBivaGDXV2rQpXXoexBs5DFBEWwYh", /* main-index: 116*/
            "2N76RSYNAgJ7ByWBmaojyy32Pzt89qSSRrj", /* main-index: 117*/
            "2NA69XUrFmJMGjfmNuk4ZPU9SSvFv22Z2gJ", /* main-index: 118*/
            "2NBJgphahNZUC8byd8N8jiLYjvY4hEAPTFo", /* main-index: 119*/
            "2N62aZkjhDgqw5nXgH23L2EtcpMSY4poZP3", /* main-index: 120*/
            "2Mzts3Rjsm9GojPo1JrkSfQmXfJ8ZjSKz2p", /* main-index: 121*/
            "2NFFc5RCVZah2oBMUw62or1HvkCJAvcgdeE", /* main-index: 122*/
            "2N56EZD718NHXxLFA3qKLgLvyoqTwAFDHCV", /* main-index: 123*/
            "2MwDb7EPW2kCPy1zh6h8Jcq2FVPHEQNFKoP", /* main-index: 124*/
            "2NCsZE27c3Jq25pjbnUWCJcVwZ4mBW4eQkh", /* main-index: 125*/
            "2N4YuzB3qqaLJFjGRaiGrCtwG3cNcSzZFgt", /* main-index: 126*/
            "2NC1KWiaUrwfFHCYJttkfuuUn49eSuZTUcX", /* main-index: 127*/
            "2NDFzoV3pCgz9b83BMM6UwdcuzqkgM6ZCbh", /* main-index: 128*/
            "2NEGnqWDCXceEwNZqFLj1pZUYPpwMJioGZp", /* main-index: 129*/
            "2N7DuRB5E3Mgse9ymBRF6HtvYhFfJaMFFCL", /* main-index: 130*/
            "2N7gU2HVAJf2xm7WHZpZLZ8KzyVBrGTQfMf", /* main-index: 131*/
            "2N5dKRDjfrRH9xUqwqPcD1iDAjwLBCnXo3d", /* main-index: 132*/
            "2NCxBGq3Tms9azkNLPLdKtmciuU1C8pXG8e", /* main-index: 133*/
            "2MsH5Fo92hj9XofFXSNPEuNoEwqLNKn8Da4", /* main-index: 134*/
            "2Mv2EHyfsE4zjB2KFYRcQtE942kcfxDXGcN", /* main-index: 135*/
            "2NADwQoFUDhWmzF65wLkEf5kZiDWKTzAH61", /* main-index: 136*/
            "2N4F1uyESwLKNs9mJ8RiVrDoGZBse7pdqPr", /* main-index: 137*/
            "2N9AXUa5KvWdNywVDrCSmG142duEkmnPKii", /* main-index: 138*/
            "2MyVwbm7rUjFur6dBev6cWcwcNjBLNP4Yqb", /* main-index: 139*/
            "2N4PKAnSievyBW4Gsysbu7YH5AqjpV44xgw", /* main-index: 140*/
            "2N1FfmSuk4vTbM7Pbf8fNv87N1qYdE5SNnW", /* main-index: 141*/
            "2MsZtedPuJNADreK3wpm41zrmQNzwbX68KU", /* main-index: 142*/
            "2N8TKbkHn8YmJGymo1ZHChLMGnVkSaVF5kD", /* main-index: 143*/
            "2N2onhjJBAW8jxuUwPVcgdYxsKhs3s5teQP", /* main-index: 144*/
            "2N8Gj25tg9ceV2qGhkZQCTtE54Q5qPYb4SF", /* main-index: 145*/
            "2N6nc7QGHqZzeukKbHcMnwhYm2HYdrKZ8tk", /* main-index: 146*/
            "2NBJL1kBsb9whxZPBKkGAbkfkLm1cEevwsL", /* main-index: 147*/
            "2N6mVVzGqSE9CTJud12Pw38eWNBpY2fvb2Q", /* main-index: 148*/
            "2NEFJu85Fc5REAzHU6ASuUj4YcHaqxD3KSE", /* main-index: 149*/
            "2NA94Ld3xnBRmDtS5tcEEZBrSXm9trJbEAK", /* main-index: 150*/
            "2NEpHiupJJGtXf6XCSw7KRDCD9SaCcuTj67", /* main-index: 151*/
            "2N7xXBy4NV5do5DGEGAJuTPfAENzHZy6YBr", /* main-index: 152*/
            "2N3rEH1U2UyfvhYbVw5uvyxWtmQ5vHfp8p3", /* main-index: 153*/
            "2MwG2PoMv9cTHHd3QdhWVNK5z2MfTJNFHjR", /* main-index: 154*/
            "2N9EqMr9CpD4fanNopZxuvPtTCH6mkExaYU", /* main-index: 155*/
            "2MzkDeU5r7BwfMTDcHYCRTd7XSrVEpAkjhV", /* main-index: 156*/
            "2MyWvk2Tux7CjLiMN94EF6iPYwKccG5eRfB", /* main-index: 157*/
            "2NG3BjtwBD8zi9dsNKj8z6U2grQB2u62uWW", /* main-index: 158*/
            "2MsyBuJWiWBL27WPbhbPJAXLTxSXYodSSn5", /* main-index: 159*/
            "2N1tTvHPA91q1cUe4aDeawf6SzeXK27a4Kh", /* main-index: 160*/
            "2N53aR9KYQrEbe6Dc986YDYBmdD2WKKBPRj", /* main-index: 161*/
            "2MzNLHFgg3SCUqpPZfT6sJxJj2zUR1j4g3B", /* main-index: 162*/
            "2NFxDiZi7x4L6QQyN8DB3ppcaJGHM8PJTet", /* main-index: 163*/
            "2NDjD5ahEvThhAy2K2efAuznCe1br6dHMQm", /* main-index: 164*/
            "2MzcGuFhzkJTjGNGidaFS78a7uQdsgr2Rot", /* main-index: 165*/
            "2N8XuXHTUjfoWwyKQ3pdgtKvB3vf6wkWw6a", /* main-index: 166*/
            "2N4AaeG9ZExsE5cumci1w2MB8zGsLyMjTy2", /* main-index: 167*/
            "2MuK7B9nHP5mbhhHgYY3i7Mv6JXH4hj67jY", /* main-index: 168*/
            "2Mt8Ee7bxDzXP4vHZjnftjWxpfCmDMk1ghB", /* main-index: 169*/
            "2N1N1bDnCSPLKzZNSUTCuQ6aEg9ZW1kKW3c", /* main-index: 170*/
            "2Muiw7eBKjWWG6WWNQuw9vc7c4ZpRf4djWK", /* main-index: 171*/
            "2MydEMCZaZe6vnqDJaNVyemo3AjcnD5hdf7", /* main-index: 172*/
            "2NDgayCxUv5TJZZrdS9R9s3V51ftLEQSsWL", /* main-index: 173*/
            "2N6VAHjN3x3jTzGaS6xLrqgunk5hE9pbmCF", /* main-index: 174*/
            "2ND5FtCcDWxG6KPfq7gS2FzPQnZHV9nEriL", /* main-index: 175*/
            "2N91kZ1B5XYVmE5AaUAbvgYdmgcqECHtezU", /* main-index: 176*/
            "2Mz9evqmNfYij3NTjB5bJAF79wCQ5659fhW", /* main-index: 177*/
            "2NCRUTeJjrxMjaaj9VxyAV8XW8z2o5pmquK", /* main-index: 178*/
            "2N3bSv4784obsidgFd6moZVwuuAFQ88hY3x", /* main-index: 179*/
            "2N6Y9WHNEtY5FPUSt8ooHhvEQ8KfQpZoDoK", /* main-index: 180*/
            "2MzfTDYJuuW1XD8Fu7gffrMnH1K2AdnCPht", /* main-index: 181*/
            "2N3Dmn6osxGVymQwjHriidXsZ5NgJJdBT4c", /* main-index: 182*/
            "2N5nm9n9dy6cc5JSqsWpNJmH8ZrPrVj2EJU", /* main-index: 183*/
            "2N3ivAJiv29AY7GVGsi9fmr7ZmdfEmbbaA4", /* main-index: 184*/
            "2NCfS1D8Y49GJX2HRx9Bv8Zj93zXp5XfH2Y", /* main-index: 185*/
            "2N7wnHBpqh4bUPsQyrcCyF2DnnsyEPhD13j", /* main-index: 186*/
            "2N5dXu4eeeQeTJQPRckHyNVzcVmDFwHyoR1", /* main-index: 187*/
            "2Mx8D3hiEphH1LAWCwYEX1yEAGkT95s2HQx", /* main-index: 188*/
            "2NBBtqg93gciWgh5dpgkc2DzDm7aa4gkUhZ", /* main-index: 189*/
            "2NF2obRuvHXcxyNC6L4voqdyqBRd9pFv8av", /* main-index: 190*/
            "2NBw7bjJ1Xh6A74U1x9HYDEuu1TG56E3FAp", /* main-index: 191*/
            "2N4eJ7bgQQYAMAnMkCizAqGnJgA6E4W8ToG", /* main-index: 192*/
            "2NCRY2WFiajUN162rjGyRaUWzZVYygBG5Rg", /* main-index: 193*/
            "2Mxm9jGSqZHjSFWmxbsfDjBMan9NqmpNTZc", /* main-index: 194*/
            "2MuxQnE1pEYUg9oVY1NEWy3wa7y8iDvw8sF", /* main-index: 195*/
            "2MzKwLr5wCcm2GBihdd3UPF3VWiPHPMNBxz", /* main-index: 196*/
            "2N4hPCKFMkJhXGtmpGVWufM1riSiDc7rDvn", /* main-index: 197*/
            "2MsHbF8H7AS8XgV4uzPjLTZkoj7v4HrUoHz", /* main-index: 198*/
            "2MuJPx2K5hgdim5CGeeRCdGKUCvqTHn9a76", /* main-index: 199*/
            "2NFnJfiKSUpLWN3vQgRpESFcFG6832PD1EF", /* main-index: 200*/
            "2N6oL2W1cPWwb8AEWjEa3yRyxfvCGFeoycD", /* main-index: 201*/
            "2MsQHTyERxcV4Ab8G1ybKL5tgh3pv9KVGoc", /* main-index: 202*/
            "2Mumug6wdBpgoHuzAPLfz4S4igJGK3bMgp2", /* main-index: 203*/
            "2N2G3TWcmw57NdbbhvZXPeghBVGs3dDKDEm", /* main-index: 204*/
            "2N9iYNtj1siEhoWNz1U18GeRw6JUPtmqTwj", /* main-index: 205*/
            "2NGD3x4krZPsFAAXxrePjwBhtt2NVK794c2", /* main-index: 206*/
            "2N5iFw2Cu7wjRRDFjNf4P9bD1dz1czw2NYd", /* main-index: 207*/
            "2N1D3RYEZbRyn1C7sXzpxVBFBHC2fYfaBgJ", /* main-index: 208*/
            "2NFHu6fmdhcFPVny8TqZrZKUrz6ok2px1Bo", /* main-index: 209*/
            "2MvukvexBwPwm2PjrXP7XeRCYNwaYfSq4L3", /* main-index: 210*/
            "2Mz6HdbznobW3zkzqMg8gDUXoyjZPmCqzem", /* main-index: 211*/
            "2N8BzoeCE8yuDNL7kEZciddEBo2TLQQuoR2", /* main-index: 212*/
            "2NE26srmRnRyq2VszabGmtPQRRMXqtDXsNB", /* main-index: 213*/
            "2N5p2L9SvewMQdNuWsnbTWzD189vm974VGv", /* main-index: 214*/
            "2N3QmFKMvoAKDJQfzDQcGykZWNxXekRW8gy", /* main-index: 215*/
            "2Mw7iDXbcWdgf5vzF9LE5E2Br2Wz2HX2sXG", /* main-index: 216*/
            "2NBHBTRsDeBbjJTEbyAj1qjjW5SWrQLhbPQ", /* main-index: 217*/
            "2Myiqm2MoDiePxp8pZzFaJEnyhHnvRbGPWp", /* main-index: 218*/
            "2MtcFk32U3beUjJzpDubQG2fe4LbMWv8wuk", /* main-index: 219*/
            "2MtNEzNvEVb3bXjcqwayKKJSCxhQro3zS1i", /* main-index: 220*/
            "2N7b4VQgzNHUWbvW1JUC57LtdZdicX4r9qT", /* main-index: 221*/
            "2N5vkmoF9tnUezwtq25yEyXkRHY24v5Yatd", /* main-index: 222*/
            "2NBmaVaEeW5vHM8XBuBds5BZJ5swJhvYgSJ", /* main-index: 223*/
            "2Mvq3WwYHEqjnrR7JFqtuuSJWNqBX6zhL5P", /* main-index: 224*/
            "2N8vHqa3f9WXFcKHFerwVzhEUBrAqovTQr9", /* main-index: 225*/
            "2NFDUaZ3MTpLgnV9ftCtTUrYgBzMRbyYhTL", /* main-index: 226*/
            "2NGEaQuFPEsh2mqEdeWxUTug4P5g949uXFp", /* main-index: 227*/
            "2NF1UyTd2ggXTj2yEqaFEp3ZqCtefoKUcg9", /* main-index: 228*/
            "2NAVZU3r3KymLneGCT2YqsVN4yDvtSPmiLm", /* main-index: 229*/
            "2MzAvVDH6YxsrvdimQgurDWoZiAK76zgHfM", /* main-index: 230*/
            "2MsimGjoLeASLpbNpt5LQKRBGZ6SVVg3pan", /* main-index: 231*/
            "2N4zwfsDDzUwYqqeRni82UFCkRNNyucNRXC", /* main-index: 232*/
            "2MsSKjGmbsN6MRcNhm4DAvKTZ2C4VLz8aQt", /* main-index: 233*/
            "2MzNLzeAVcd4j7bsbH22xptkqJYEerTFehW", /* main-index: 234*/
            "2NAjoLjCeQfppEJ1BshVBuNoCMrTc6YStaY", /* main-index: 235*/
            "2NFjbuGWELHQBWFxEaSGL8reptJ7ykgpCgv", /* main-index: 236*/
            "2N1VkEeUF2yEcgxwo4NkgQ5T9CEtjzaAofG", /* main-index: 237*/
            "2MwrwcFTLTK22otrJ749zVcbcMaexekvdQR", /* main-index: 238*/
            "2MzAteF7RK9WDDb4NcjMQYsAKEJUEs6VrnB", /* main-index: 239*/
            "2N1ZjJaohf2WKSvkxzr1NbbHbXjCiA6MePm", /* main-index: 240*/
            "2MypJMrbrcNfQNFjdqrAe6yLaBQpPHNM5Ub", /* main-index: 241*/
            "2N9Xiij6PXunJ73MnN5WNfFr2xZVERT25Lp", /* main-index: 242*/
            "2MwWdVshqsGLwyuKtN7idW2RwHy2JfKzwu3", /* main-index: 243*/
            "2NBPTwoEuAyzbFuxLHuDDa1TD1Nmr46Xvvp", /* main-index: 244*/
            "2MwH8AidxjpbjiWsh1PnFcBZAUDV42G8x44", /* main-index: 245*/
            "2MxpVpdcL7S4W5mjqqnq2eZvVKhvT43jebN", /* main-index: 246*/
            "2Mvi4xMAUP1wHHhu7AXi5jj3qcJi9mZZMui", /* main-index: 247*/
            "2N6hRHM3cAhGd9bPwoSjSPrMo63PtNKTMg9", /* main-index: 248*/
            "2N3caMMyNTmQbw12syN19RNovHaDZruNVCN", /* main-index: 249*/
            "2Mtc3Pw4tYh7yxEEXHHirGHS8ed92kHdW2M", /* main-index: 250*/
            "2MwodghEt1XykbDNmUQCxe8DM2WTPLr4R22", /* main-index: 251*/
            "2N5MR3oAD2p8meLbudV7Zb8kKpQCst2KLBv", /* main-index: 252*/
            "2MvPdEx1Ey3XNRbbeumLCLPqxmdYT3bwJeL", /* main-index: 253*/
            "2MsiFG83vcFL6MUw93JamraS2vpSAirRJRi", /* main-index: 254*/
            "2NBTpWNJ5oxMt4EyMqiXxovcxNCBUWsFnUv", /* main-index: 255*/
            "2NBh4t5qC1RuGeHPqziZwZan9f7yKLZ3ZVw", /* main-index: 256*/
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

const CChainParams CreateNetworkParams(const std::string& network) {
    if (network == CBaseChainParams::MAIN)
        return CMainParams();
    else if (network == CBaseChainParams::TESTNET)
        return CTestNetParams();
    else if (network == CBaseChainParams::REGTEST)
        return CRegTestParams();
    throw std::runtime_error(strprintf("%s: Unknown network %s.", __func__, network));
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

// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int addressChangeInterval = consensus.nTreasuryAddressChange;
    int addressChangeStartHeight = consensus.nTreasuryAddressChangeStart;
    int i = (nHeight - addressChangeStartHeight) / addressChangeInterval;
    
    if(i <= 0)
        i = 0;
    
    if(i >= 256)
        i = 256;
    
    return GetFoundersRewardAddressAtIndex(i);
}

// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    CTxDestination address = DecodeDestination(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}

CAmount CChainParams::GetTreasuryAmount(CAmount coinAmount) const
{
    return ((coinAmount / 100.0) * consensus.nTreasuryAmount);
}

unsigned int CChainParams::EquihashSolutionWidth(uint8_t nAlgo) const
{
    assert(nAlgo == ALGO_EQUIHASH || nAlgo == ALGO_ZHASH);
    
    if(nAlgo == ALGO_EQUIHASH)
        return EhSolutionWidth(EquihashN(), EquihashK());
    else if(nAlgo == ALGO_ZHASH)
        return EhSolutionWidth(ZhashN(), ZhashK());
    else
        return 0;
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
