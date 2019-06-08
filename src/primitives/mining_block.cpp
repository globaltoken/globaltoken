// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2009-2017 The DigiByte Core developers
// Copyright (c) 2013-2014 Phoenixcoin Developers
// Copyright (c) 2016-2018 The CryptoCoderz Team / Espers
// Copyright (c) 2017-2018 The AmsterdamCoin developers
// Copyright (c) 2009-2016 The Litecoin Core developers
// Copyright (c) 2014-2017 The Mun Core developers
// Copyright (c) 2017 The Raven Core developers
// Copyright (c) 2018-2019 The GlobalToken Core developers
// Copyright (c) 2018-2018 The Pptp Core developers
// Copyright (c) 2017-2018 The XDNA Core developers
// Copyright (c) 2017-2018 The Denarius developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/mining_block.h>

#include <hash.h>
#include <tinyformat.h>
#include <utilstrencodings.h>
#include <chainparams.h>
#include <crypto/common.h>
#include <crypto/algos/hashlib/multihash.h>
#include <crypto/algos/neoscrypt/neoscrypt.h>
#include <crypto/algos/scrypt/scrypt.h>
#include <crypto/algos/yescrypt/yescrypt.h>
#include <crypto/algos/Lyra2RE/Lyra2RE.h>
#include <crypto/algos/Lyra2RE/Lyra2Z.h>
#include <crypto/algos/blake/hashblake.h>
#include <crypto/algos/bcrypt/bcrypt.h>
#include <crypto/algos/argon2d/hashargon.h>
#include <crypto/algos/yespower/yespower.h>
#include <crypto/algos/honeycomb/hash_honeycomb.h>
#include <crypto/algos/allium/allium.h>

uint256 CDefaultBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CEquihashBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CDefaultBlockHeader::GetPoWHash(uint8_t algo) const
{
    switch (algo)
    {
        case ALGO_SHA256D:
            return GetHash();
        case ALGO_SCRYPT:
        {
            uint256 thash;
            scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
            return thash;
        }
        case ALGO_X11:
        {
            return HashX11(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_NEOSCRYPT:
        {
            unsigned int profile = 0x0;
            uint256 thash;
            neoscrypt((unsigned char *) &nVersion, (unsigned char *) &thash, profile);				
            return thash;
        }
        case ALGO_EQUIHASH:
            return GetHash();
        case ALGO_YESCRYPT:
        {
            uint256 thash;
            yescrypt_hash(BEGIN(nVersion), BEGIN(thash));
            return thash;
        }
        case ALGO_HMQ1725:
        {
            return HMQ1725(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_XEVAN:
        {
            return XEVAN(BEGIN(nVersion), END(nNonce));	    
        }
        case ALGO_NIST5:
        {
            return NIST5(BEGIN(nVersion), END(nNonce));	    
        }
        case ALGO_TIMETRAVEL10:
        {
            return HashTimeTravel(BEGIN(nVersion), END(nNonce), nTime);	    
        }
        case ALGO_PAWELHASH:
        {
            return PawelHash(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_X13:
        {
            return HashX13(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_X14:
        {
            return HashX14(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_X15:
        {
            return HashX15(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_X17:
        {
            return HashX17(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_LYRA2REV2:
        {
            uint256 thash;
            lyra2re2_hash(BEGIN(nVersion), BEGIN(thash));
            return thash;
        }
        case ALGO_BLAKE2S:
        {
            return HashBlake2S(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_BLAKE2B:
        {
            return HashBlake2B(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_ASTRALHASH:
        {
            return AstralHash(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_PADIHASH:
        {
            return PadiHash(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_JEONGHASH:
        {
            return JeongHash(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_KECCAKC:
        {
            return HashKeccakC(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_ZHASH:
        {
            return GetHash();
        }
        case ALGO_GLOBALHASH:
        {
            return GlobalHash(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_GROESTL:
        {
            return HashGroestl(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_SKEIN:
        {
            return HashSkein(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_QUBIT:
        {
            return HashQubit(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_SKUNKHASH:
        {
            return SkunkHash5(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_QUARK:
        {
            return QUARK(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_X16R:
        {
            return HashX16R(BEGIN(nVersion), END(nNonce), hashPrevBlock);
        }
        case ALGO_LYRA2REV3:
        {
            uint256 thash;
            lyra2re3_hash(BEGIN(nVersion), BEGIN(thash));
            return thash;
        }
        case ALGO_YESCRYPT_R16V2:
        {
            uint256 thash;
            yescrypt_r16v2_hash(BEGIN(nVersion), BEGIN(thash));
            return thash;
        }
        case ALGO_YESCRYPT_R24:
        {
            uint256 thash;
            yescrypt_r24_hash(BEGIN(nVersion), BEGIN(thash));
            return thash;
        }
        case ALGO_YESCRYPT_R8:
        {
            uint256 thash;
            yescrypt_r8_hash(BEGIN(nVersion), BEGIN(thash));
            return thash;
        }
        case ALGO_YESCRYPT_R32:
        {
            uint256 thash;
            yescrypt_r32_hash(BEGIN(nVersion), BEGIN(thash));
            return thash;
        }
        case ALGO_BCRYPT:
        {
            uint256 thash;
            bcrypt(BEGIN(nVersion), BEGIN(thash));
            return thash;
        }
        case ALGO_ARGON2D:
        {
            uint256 thash;
            Argon2dHash(BEGIN(nVersion), BEGIN(thash), nTime);
            return thash;
        }
        case ALGO_ARGON2I:
        {
            uint256 thash;
            Argon2iHash(BEGIN(nVersion), BEGIN(thash), nTime);
            return thash;
        }
        case ALGO_CPU23R:
        {
            return HashCPU23R(BEGIN(nVersion), END(nNonce), hashPrevBlock);
        }
        case ALGO_YESPOWER:
        {
            uint256 thash;
            yespower_hash(BEGIN(nVersion), BEGIN(thash));
            return thash;
        }
        case ALGO_X21S:
        {
            return HashX21S(BEGIN(nVersion), END(nNonce), hashPrevBlock);
        }
        case ALGO_X16S:
        {
            return HashX16s(BEGIN(nVersion), END(nNonce), hashPrevBlock);
        }
        case ALGO_X22I:
        {
            return HashX22I(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_LYRA2Z:
        {
            uint256 thash;
            lyra2z_hash(BEGIN(nVersion), BEGIN(thash));
            return thash;
        }
        case ALGO_HONEYCOMB:
        {
            return HashHoneyComb(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_EH192:
        {
            return GetHash();
        }
        case ALGO_MARS:
        {
            return GetHash();
        }
        case ALGO_X12:
        {
            return HashX12(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_HEX:
        {
            return HashHEX(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_DEDAL:
        {
            return HashDedal(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_C11:
        {
            return HashC11(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_PHI1612:
        {
            return Phi1612(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_PHI2:
        {
            return PHI2(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_X16RT:
        {
            int32_t nTimeX16r = nTime & 0xffffff80;
            uint256 hashTime = Hash(BEGIN(nTimeX16r), END(nTimeX16r));
            return HashX16R(BEGIN(nVersion), END(nNonce), hashTime);
        }
        case ALGO_TRIBUS:
        {
            return Tribus(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_ALLIUM:
        {
            uint256 thash;
            allium_hash(BEGIN(nVersion), BEGIN(thash));
            return thash;
        }
        case ALGO_ARCTICHASH:
        {
            return ArcticHash(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_DESERTHASH:
        {
            return DesertHash(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_CRYPTOANDCOFFEE:
        {
            return cryptoandcoffee_hash(BEGIN(nVersion), END(nNonce));
        }
        case ALGO_RICKHASH:
        {
            return RickHash(BEGIN(nVersion), END(nNonce));
        }
    }
    return GetHash();
}

std::string CDefaultBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CDefaultBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

std::string CEquihashBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CEquihashBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%s, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce.GetHex(),
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}