// Copyright (c) 2019 The Globaltoken Core developers
// Copyright (c) 2014-2019 The DigiByte Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBALTOKEN_POW_ALGORITHM_H
#define GLOBALTOKEN_POW_ALGORITHM_H

#include <arith_uint256.h>
#include <uint256.h>


/** Algos */
enum : uint8_t { 
    ALGO_SHA256D         = 0,
    ALGO_SCRYPT          = 1,
    ALGO_X11             = 2,
    ALGO_NEOSCRYPT       = 3,
    ALGO_EQUIHASH        = 4,
    ALGO_YESCRYPT        = 5,
    ALGO_HMQ1725         = 6,
    ALGO_XEVAN           = 7,
    ALGO_NIST5           = 8,
    ALGO_TIMETRAVEL10    = 9,
    ALGO_PAWELHASH       = 10,
    ALGO_X13             = 11,
    ALGO_X14             = 12,
    ALGO_X15             = 13,
    ALGO_X17             = 14,
    ALGO_LYRA2REV2       = 15,
    ALGO_BLAKE2S         = 16,
    ALGO_BLAKE2B         = 17,
    ALGO_ASTRALHASH      = 18,
    ALGO_PADIHASH        = 19,
    ALGO_JEONGHASH       = 20,
    ALGO_KECCAKC         = 21,
    ALGO_ZHASH           = 22,
    ALGO_GLOBALHASH      = 23,
    ALGO_SKEIN           = 24,
    ALGO_GROESTL         = 25,
    ALGO_QUBIT           = 26,
    ALGO_SKUNKHASH       = 27,
    ALGO_QUARK           = 28,
    ALGO_X16R            = 29,
    ALGO_LYRA2REV3       = 30,
    ALGO_YESCRYPT_R16V2  = 31,
    ALGO_YESCRYPT_R24    = 32,
    ALGO_YESCRYPT_R8     = 33,
    ALGO_YESCRYPT_R32    = 34,
    ALGO_BCRYPT          = 35,
    ALGO_ARGON2D         = 36,
    ALGO_ARGON2I         = 37,
    ALGO_CPU23R          = 38,
    ALGO_YESPOWER        = 39,
    ALGO_X21S            = 40,
    ALGO_X16S            = 41,
    ALGO_X22I            = 42,
    ALGO_LYRA2Z          = 43,
    ALGO_HONEYCOMB       = 44,
    ALGO_EH192           = 45,
    ALGO_MARS            = 46,
    ALGO_X12             = 47,
    ALGO_HEX             = 48,
    ALGO_DEDAL           = 49,
    ALGO_C11             = 50,
    ALGO_PHI1612         = 51,
    ALGO_PHI2            = 52,
    ALGO_X16RT           = 53,
    ALGO_TRIBUS          = 54,
    ALGO_ALLIUM          = 55,
    ALGO_ARCTICHASH      = 56,
    ALGO_DESERTHASH      = 57,
    ALGO_CRYPTOANDCOFFEE = 58,
    ALGO_RICKHASH        = 59,
    NUM_ALGOS_IMPL };

enum {
    BLOCK_VERSION_ALGO              = 0x7E00,
    BLOCK_VERSION_SHA256D           = (1 << 9),
    BLOCK_VERSION_SCRYPT            = (2 << 9),
    BLOCK_VERSION_X11               = (3 << 9),
    BLOCK_VERSION_NEOSCRYPT         = (4 << 9),
    BLOCK_VERSION_EQUIHASH          = (5 << 9),
    BLOCK_VERSION_YESCRYPT          = (6 << 9),
    BLOCK_VERSION_HMQ1725           = (7 << 9),
    BLOCK_VERSION_XEVAN             = (8 << 9),
    BLOCK_VERSION_NIST5             = (9 << 9),
    BLOCK_VERSION_TIMETRAVEL10      = (10 << 9),
    BLOCK_VERSION_PAWELHASH         = (11 << 9),
    BLOCK_VERSION_X13               = (12 << 9),
    BLOCK_VERSION_X14               = (13 << 9),
    BLOCK_VERSION_X15               = (14 << 9),
    BLOCK_VERSION_X17               = (15 << 9),
    BLOCK_VERSION_LYRA2REV2         = (16 << 9),
    BLOCK_VERSION_BLAKE2S           = (17 << 9),
    BLOCK_VERSION_BLAKE2B           = (18 << 9),
    BLOCK_VERSION_ASTRALHASH        = (19 << 9),
    BLOCK_VERSION_PADIHASH          = (20 << 9),
    BLOCK_VERSION_JEONGHASH         = (21 << 9),
    BLOCK_VERSION_KECCAKC           = (22 << 9),
    BLOCK_VERSION_ZHASH             = (23 << 9),
    BLOCK_VERSION_GLOBALHASH        = (24 << 9),
    BLOCK_VERSION_SKEIN             = (25 << 9),
    BLOCK_VERSION_GROESTL           = (26 << 9),
    BLOCK_VERSION_QUBIT             = (27 << 9),
    BLOCK_VERSION_SKUNKHASH         = (28 << 9),
    BLOCK_VERSION_QUARK             = (29 << 9),
    BLOCK_VERSION_X16R              = (30 << 9),
    BLOCK_VERSION_LYRA2REV3         = (31 << 9),
    BLOCK_VERSION_YESCRYPT_R16V2    = (32 << 9),
    BLOCK_VERSION_YESCRYPT_R24      = (33 << 9),
    BLOCK_VERSION_YESCRYPT_R8       = (34 << 9),
    BLOCK_VERSION_YESCRYPT_R32      = (35 << 9),
    BLOCK_VERSION_BCRYPT            = (36 << 9),
    BLOCK_VERSION_ARGON2D           = (37 << 9),
    BLOCK_VERSION_ARGON2I           = (38 << 9),
    BLOCK_VERSION_CPU23R            = (39 << 9),
    BLOCK_VERSION_YESPOWER          = (40 << 9),
    BLOCK_VERSION_X21S              = (41 << 9),
    BLOCK_VERSION_X16S              = (42 << 9),
    BLOCK_VERSION_X22I              = (43 << 9),
    BLOCK_VERSION_LYRA2Z            = (44 << 9),
    BLOCK_VERSION_HONEYCOMB         = (45 << 9),
    BLOCK_VERSION_EH192             = (46 << 9),
    BLOCK_VERSION_MARS              = (47 << 9),
    BLOCK_VERSION_X12               = (48 << 9),
    BLOCK_VERSION_HEX               = (49 << 9),
    BLOCK_VERSION_DEDAL             = (50 << 9),
    BLOCK_VERSION_C11               = (51 << 9),
    BLOCK_VERSION_PHI1612           = (52 << 9),
    BLOCK_VERSION_PHI2              = (53 << 9),
    BLOCK_VERSION_X16RT             = (54 << 9),
    BLOCK_VERSION_TRIBUS            = (55 << 9),
    BLOCK_VERSION_ALLIUM            = (56 << 9),
    BLOCK_VERSION_ARCTICHASH        = (57 << 9),
    BLOCK_VERSION_DESERTHASH        = (58 << 9),
    BLOCK_VERSION_CRYPTOANDCOFFEE   = (59 << 9),
    BLOCK_VERSION_RICKHASH          = (60 << 9),
};
    
const int NUM_ALGOS_OLD = 30;
const int NUM_ALGOS = 60;

std::string GetAlgoName(uint8_t Algo);
uint8_t GetAlgoByName(std::string strAlgo, uint8_t fallback, bool &fAlgoFound);
std::string GetAlgoRangeString();
bool IsAlgoAllowedBeforeHF2(uint8_t nAlgo);
bool IsEquihashBasedAlgo(uint8_t nAlgo);
std::string GetEquihashBasedDefaultPersonalize(uint8_t nAlgo);

class CPOWAlgoProperties
{
private:
    
    // the algo ID
    uint8_t nAlgoID;
    
    // the powLimit hash
    uint256 powLimit;
    
    // the diff multiplier
    int nMultiplier;
    
public:

    CPOWAlgoProperties()
    {
        SetNull();
    }
    
    CPOWAlgoProperties(uint8_t nAlgo, uint256 proofOfWorkLimit, int diffMultiplier)
    {
        Initialize(nAlgo, proofOfWorkLimit, diffMultiplier);
    }
    
    void SetNull()
    {
        nAlgoID = 0;
        powLimit.SetNull();
        nMultiplier = 0;
    }
    
    bool IsNull() const
    {
        return (nMultiplier == 0);
    }
    
    void Initialize(uint8_t nAlgo, uint256 proofOfWorkLimit, int diffMultiplier)
    {
        nAlgoID = nAlgo;
        powLimit = proofOfWorkLimit;
        nMultiplier = diffMultiplier;
    }
    
    uint8_t GetAlgoID() const
    {
        return nAlgoID;
    }
    
    uint256 GetPowLimit() const
    {
        return powLimit;
    }
    
    arith_uint256 GetArithPowLimit() const
    {
        return UintToArith256(powLimit);
    }
    
    int GetMultiplier() const
    {
        return nMultiplier;
    }
};

#endif // GLOBALTOKEN_POW_ALGORITHM_H
