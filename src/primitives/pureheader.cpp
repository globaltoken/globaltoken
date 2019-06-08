// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The DigiByte Core developers
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/pureheader.h>

#include <hash.h>
#include <utilstrencodings.h>
#include <chainparams.h>

uint256 CPureBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

CEquihashBlockHeader CPureBlockHeader::GetEquihashBlockHeader() const
{
    CEquihashBlockHeader block;
    block.nVersion       = nVersion;
    block.hashPrevBlock  = hashPrevBlock;
    block.hashMerkleRoot = hashMerkleRoot;
    block.hashReserved   = hashReserved;
    block.nTime          = nTime;
    block.nBits          = nBits;
    block.nNonce         = nBigNonce;
    block.nSolution      = nSolution;
    return block;
}

CDefaultBlockHeader CPureBlockHeader::GetDefaultBlockHeader() const
{
    CDefaultBlockHeader block;
    block.nVersion       = nVersion;
    block.hashPrevBlock  = hashPrevBlock;
    block.hashMerkleRoot = hashMerkleRoot;
    block.nTime          = nTime;
    block.nBits          = nBits;
    block.nNonce         = nNonce;
    return block;
}

uint256 CPureBlockHeader::GetPoWHash() const
{
    return GetPoWHash(GetAlgo());
}

uint256 CPureBlockHeader::GetPoWHash(uint8_t nAlgo) const
{
    if(IsEquihashBasedAlgo(nAlgo))
    {
        CEquihashBlockHeader block;
        block = CPureBlockHeader::GetEquihashBlockHeader();
        return block.GetHash();
    }
    CDefaultBlockHeader block;
    block = CPureBlockHeader::GetDefaultBlockHeader();
    return block.GetPoWHash(nAlgo);
}

uint8_t CPureBlockHeader::GetAlgo() const
{
    if(IsLegacyVersion(nVersion))
        return ALGO_SHA256D;
    
    switch (nVersion & BLOCK_VERSION_ALGO)
    {
        case BLOCK_VERSION_SHA256D:
            return ALGO_SHA256D;
        case BLOCK_VERSION_SCRYPT:
            return ALGO_SCRYPT;
        case BLOCK_VERSION_X11:
            return ALGO_X11;
        case BLOCK_VERSION_NEOSCRYPT:
            return ALGO_NEOSCRYPT;
        case BLOCK_VERSION_EQUIHASH:
            return ALGO_EQUIHASH;
        case BLOCK_VERSION_YESCRYPT:
            return ALGO_YESCRYPT;
        case BLOCK_VERSION_HMQ1725:
            return ALGO_HMQ1725;
        case BLOCK_VERSION_XEVAN:
            return ALGO_XEVAN;
        case BLOCK_VERSION_NIST5:
            return ALGO_NIST5;
        case BLOCK_VERSION_TIMETRAVEL10:
            return ALGO_TIMETRAVEL10;
        case BLOCK_VERSION_PAWELHASH:
            return ALGO_PAWELHASH;
        case BLOCK_VERSION_X13:
            return ALGO_X13;
        case BLOCK_VERSION_X14:
            return ALGO_X14;
        case BLOCK_VERSION_X15:
            return ALGO_X15;
        case BLOCK_VERSION_X17:
            return ALGO_X17;
        case BLOCK_VERSION_LYRA2REV2:
            return ALGO_LYRA2REV2;
        case BLOCK_VERSION_BLAKE2S:
            return ALGO_BLAKE2S;
        case BLOCK_VERSION_BLAKE2B:
            return ALGO_BLAKE2B;
        case BLOCK_VERSION_ASTRALHASH:
            return ALGO_ASTRALHASH;
        case BLOCK_VERSION_PADIHASH:
            return ALGO_PADIHASH;
        case BLOCK_VERSION_JEONGHASH:
            return ALGO_JEONGHASH;
        case BLOCK_VERSION_KECCAKC:
            return ALGO_KECCAKC;
        case BLOCK_VERSION_ZHASH:
            return ALGO_ZHASH;
        case BLOCK_VERSION_GLOBALHASH:
            return ALGO_GLOBALHASH;
        case BLOCK_VERSION_GROESTL:
            return ALGO_GROESTL;
        case BLOCK_VERSION_SKEIN:
            return ALGO_SKEIN;
        case BLOCK_VERSION_QUBIT:
            return ALGO_QUBIT;
        case BLOCK_VERSION_SKUNKHASH:
            return ALGO_SKUNKHASH;
        case BLOCK_VERSION_QUARK:
            return ALGO_QUARK;
        case BLOCK_VERSION_X16R:
            return ALGO_X16R;
        case BLOCK_VERSION_LYRA2REV3:
            return ALGO_LYRA2REV3;
        case BLOCK_VERSION_YESCRYPT_R16V2:
            return ALGO_YESCRYPT_R16V2;
        case BLOCK_VERSION_YESCRYPT_R24:
            return ALGO_YESCRYPT_R24;
        case BLOCK_VERSION_YESCRYPT_R8:
            return ALGO_YESCRYPT_R8;
        case BLOCK_VERSION_YESCRYPT_R32:
            return ALGO_YESCRYPT_R32;
        case BLOCK_VERSION_BCRYPT:
            return ALGO_BCRYPT;
        case BLOCK_VERSION_ARGON2D:
            return ALGO_ARGON2D;
        case BLOCK_VERSION_ARGON2I:
            return ALGO_ARGON2I;
        case BLOCK_VERSION_CPU23R:
            return ALGO_CPU23R;
        case BLOCK_VERSION_YESPOWER:
            return ALGO_YESPOWER;
        case BLOCK_VERSION_X21S:
            return ALGO_X21S;
        case BLOCK_VERSION_X16S:
            return ALGO_X16S;
        case BLOCK_VERSION_X22I:
            return ALGO_X22I;
        case BLOCK_VERSION_LYRA2Z:
            return ALGO_LYRA2Z;
        case BLOCK_VERSION_HONEYCOMB:
            return ALGO_HONEYCOMB;
        case BLOCK_VERSION_EH192:
            return ALGO_EH192;
        case BLOCK_VERSION_MARS:
            return ALGO_MARS;
        case BLOCK_VERSION_X12:
            return ALGO_X12;
        case BLOCK_VERSION_HEX:
            return ALGO_HEX;
        case BLOCK_VERSION_DEDAL:
            return ALGO_DEDAL;
        case BLOCK_VERSION_C11:
            return ALGO_C11;
        case BLOCK_VERSION_PHI1612:
            return ALGO_PHI1612;
        case BLOCK_VERSION_PHI2:
            return ALGO_PHI2;
        case BLOCK_VERSION_X16RT:
            return ALGO_X16RT;
        case BLOCK_VERSION_TRIBUS:
            return ALGO_TRIBUS;
        case BLOCK_VERSION_ALLIUM:
            return ALGO_ALLIUM;
        case BLOCK_VERSION_ARCTICHASH:
            return ALGO_ARCTICHASH;
        case BLOCK_VERSION_DESERTHASH:
            return ALGO_DESERTHASH;
        case BLOCK_VERSION_CRYPTOANDCOFFEE:
            return ALGO_CRYPTOANDCOFFEE;
        case BLOCK_VERSION_RICKHASH:
            return ALGO_RICKHASH;
    }
    return ALGO_SHA256D;
}