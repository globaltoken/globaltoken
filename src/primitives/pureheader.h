// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The DigiByte Core developers
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_PUREHEADER_H
#define BITCOIN_PRIMITIVES_PUREHEADER_H

#include <primitives/mining_block.h>
#include <globaltoken/powalgorithm.h>

#include <serialize.h>
#include <uint256.h>

/**
 * A block header without auxpow information.  This "intermediate step"
 * in constructing the full header is useful, because it breaks the cyclic
 * dependency between auxpow (referencing a parent block header) and
 * the block header (referencing an auxpow).  The parent block header
 * does not have auxpow itself, so it is a pure header.
 */
class CPureBlockHeader : public CPureBlockVersion
{
public:
    // header
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint256 hashReserved;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    uint256 nBigNonce;
    std::vector<unsigned char> nSolution;  // Equihash solution.

    CPureBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CPureBlockVersion*)this);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        if (IsEquihashBasedAlgo(GetAlgo())) {
            READWRITE(hashReserved);
        }
        READWRITE(nTime);
        READWRITE(nBits);
        if (IsEquihashBasedAlgo(GetAlgo()))
        {
            READWRITE(nBigNonce);
            READWRITE(nSolution);
        }
        if(!IsEquihashBasedAlgo(GetAlgo()))
        {
            READWRITE(nNonce);
        }
    }

    void SetNull()
    {
        CPureBlockVersion::SetNull();
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        hashReserved.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        nBigNonce.SetNull();
        nSolution.clear();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    uint256 GetPoWHash() const;
    uint256 GetPoWHash(uint8_t nAlgo) const;
    
    // Set Algo to use
    inline void SetAlgo(uint8_t algo)
    {
        switch(algo)
        {
            case ALGO_SHA256D:
                nVersion |= BLOCK_VERSION_SHA256D;
                break;
            case ALGO_SCRYPT:
                nVersion |= BLOCK_VERSION_SCRYPT;
                break;
            case ALGO_X11:
                nVersion |= BLOCK_VERSION_X11;
                break;
            case ALGO_NEOSCRYPT:
                nVersion |= BLOCK_VERSION_NEOSCRYPT;
                break;
            case ALGO_EQUIHASH:
                nVersion |= BLOCK_VERSION_EQUIHASH;
                break;
            case ALGO_YESCRYPT:
                nVersion |= BLOCK_VERSION_YESCRYPT;
                break;
            case ALGO_HMQ1725:
                nVersion |= BLOCK_VERSION_HMQ1725;
                break;
            case ALGO_XEVAN:
                nVersion |= BLOCK_VERSION_XEVAN;
                break;
            case ALGO_NIST5:
                nVersion |= BLOCK_VERSION_NIST5;
                break;   
            case ALGO_TIMETRAVEL10:
                nVersion |= BLOCK_VERSION_TIMETRAVEL10;
                break;     
            case ALGO_PAWELHASH:
                nVersion |= BLOCK_VERSION_PAWELHASH;
                break;   
            case ALGO_X13:
                nVersion |= BLOCK_VERSION_X13;
                break;  
            case ALGO_X14:
                nVersion |= BLOCK_VERSION_X14;
                break;  
            case ALGO_X15:
                nVersion |= BLOCK_VERSION_X15;
                break;
            case ALGO_X17:
                nVersion |= BLOCK_VERSION_X17;
                break;
            case ALGO_LYRA2REV2:
                nVersion |= BLOCK_VERSION_LYRA2REV2;
                break;
            case ALGO_BLAKE2S:
                nVersion |= BLOCK_VERSION_BLAKE2S;
                break;
            case ALGO_BLAKE2B:
                nVersion |= BLOCK_VERSION_BLAKE2B;
                break;
            case ALGO_ASTRALHASH:
                nVersion |= BLOCK_VERSION_ASTRALHASH;
                break;
            case ALGO_PADIHASH:
                nVersion |= BLOCK_VERSION_PADIHASH;
                break;
            case ALGO_JEONGHASH:
                nVersion |= BLOCK_VERSION_JEONGHASH;
                break;
            case ALGO_KECCAKC:
                nVersion |= BLOCK_VERSION_KECCAKC;
                break;
            case ALGO_ZHASH:
                nVersion |= BLOCK_VERSION_ZHASH;
                break;
            case ALGO_GLOBALHASH:
                nVersion |= BLOCK_VERSION_GLOBALHASH;
                break;
            case ALGO_GROESTL:
                nVersion |= BLOCK_VERSION_GROESTL;
                break;
            case ALGO_SKEIN:
                nVersion |= BLOCK_VERSION_SKEIN;
                break;
            case ALGO_QUBIT:
                nVersion |= BLOCK_VERSION_QUBIT;
                break;
            case ALGO_SKUNKHASH:
                nVersion |= BLOCK_VERSION_SKUNKHASH;
                break;
            case ALGO_QUARK:
                nVersion |= BLOCK_VERSION_QUARK;
                break;
            case ALGO_X16R:
                nVersion |= BLOCK_VERSION_X16R;
                break;
            case ALGO_LYRA2REV3:
                nVersion |= BLOCK_VERSION_LYRA2REV3;
                break;
            case ALGO_YESCRYPT_R16V2:
                nVersion |= BLOCK_VERSION_YESCRYPT_R16V2;
                break;
            case ALGO_YESCRYPT_R24:
                nVersion |= BLOCK_VERSION_YESCRYPT_R24;
                break;
            case ALGO_YESCRYPT_R8:
                nVersion |= BLOCK_VERSION_YESCRYPT_R8;
                break;
            case ALGO_YESCRYPT_R32:
                nVersion |= BLOCK_VERSION_YESCRYPT_R32;
                break;
            case ALGO_BCRYPT:
                nVersion |= BLOCK_VERSION_BCRYPT;
                break;
            case ALGO_ARGON2D:
                nVersion |= BLOCK_VERSION_ARGON2D;
                break;
            case ALGO_ARGON2I:
                nVersion |= BLOCK_VERSION_ARGON2I;
                break;
            case ALGO_CPU23R:
                nVersion |= BLOCK_VERSION_CPU23R;
                break;
            case ALGO_YESPOWER:
                nVersion |= BLOCK_VERSION_YESPOWER;
                break;
            case ALGO_X21S:
                nVersion |= BLOCK_VERSION_X21S;
                break;
            case ALGO_X16S:
                nVersion |= BLOCK_VERSION_X16S;
                break;
            case ALGO_X22I:
                nVersion |= BLOCK_VERSION_X22I;
                break;
            case ALGO_LYRA2Z:
                nVersion |= BLOCK_VERSION_LYRA2Z;
                break;
            case ALGO_HONEYCOMB:
                nVersion |= BLOCK_VERSION_HONEYCOMB;
                break;
            case ALGO_EH192:
                nVersion |= BLOCK_VERSION_EH192;
                break;
            case ALGO_MARS:
                nVersion |= BLOCK_VERSION_MARS;
                break;
            case ALGO_X12:
                nVersion |= BLOCK_VERSION_X12;
                break;
            case ALGO_HEX:
                nVersion |= BLOCK_VERSION_HEX;
                break;
            case ALGO_DEDAL:
                nVersion |= BLOCK_VERSION_DEDAL;
                break;
            case ALGO_C11:
                nVersion |= BLOCK_VERSION_C11;
                break;
            case ALGO_PHI1612:
                nVersion |= BLOCK_VERSION_PHI1612;
                break;
            case ALGO_PHI2:
                nVersion |= BLOCK_VERSION_PHI2;
                break;
            case ALGO_X16RT:
                nVersion |= BLOCK_VERSION_X16RT;
                break;
            case ALGO_TRIBUS:
                nVersion |= BLOCK_VERSION_TRIBUS;
                break;
            case ALGO_ALLIUM:
                nVersion |= BLOCK_VERSION_ALLIUM;
                break;
            case ALGO_ARCTICHASH:
                nVersion |= BLOCK_VERSION_ARCTICHASH;
                break;
            case ALGO_DESERTHASH:
                nVersion |= BLOCK_VERSION_DESERTHASH;
                break;
            case ALGO_CRYPTOANDCOFFEE:
                nVersion |= BLOCK_VERSION_CRYPTOANDCOFFEE;
                break;
            case ALGO_RICKHASH:
                nVersion |= BLOCK_VERSION_RICKHASH;
                break;
            default:
                break;
        }
    }
	
    uint8_t GetAlgo() const;
    
    CDefaultBlockHeader GetDefaultBlockHeader() const;    
    CEquihashBlockHeader GetEquihashBlockHeader() const;
    
    CDefaultBlock GetDefaultBlock() const;    
    CEquihashBlock GetEquihashBlock() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};

#endif // BITCOIN_PRIMITIVES_PUREHEADER_H
