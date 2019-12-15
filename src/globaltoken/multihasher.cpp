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
// Copyright (c) 2019 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <globaltoken/multihasher.h>
#include <globaltoken/powalgorithm.h>
#include <crypto/algos/hashlib/multihash.h>
#include <crypto/algos/neoscrypt/neoscrypt.h>
#include <crypto/algos/scrypt/scrypt.h>
#include <crypto/algos/yescrypt/yescrypt.h>
#include <crypto/algos/Lyra2RE/Lyra2RE.h>
#include <crypto/algos/Lyra2RE/Lyra2Z.h>
#include <crypto/algos/blake/hashblake.h>
#include <crypto/algos/argon2/hashargon.h>
#include <crypto/algos/yespower/yespower.h>
#include <crypto/algos/honeycomb/hash_honeycomb.h>
#include <crypto/algos/allium/allium.h>
#include <uint256.h>
#include <hash.h>
#include <version.h>


uint256 CMultihasher::GetSHA256Hash() const
{
    CHashWriter ss(nType, nVersion);
    for(size_t i = 0; i < buf.size(); i++)
        ss << buf[i];
    return ss.GetHash();
}

uint256 CMultihasher::GetHash() const 
{
    switch (nAlgo)
    {
        case ALGO_SHA256D:
        {
            return this->GetSHA256Hash();
        }
        case ALGO_SCRYPT:
        {
            uint256 thash;
            assert(buf.size() == 80);
            scrypt_1024_1_1_256((const char*)buf.data(), (char*)&thash);
            return thash;
        }
        case ALGO_X11:
        {
            return HashX11(buf.data(), buf.data() + buf.size());
        }
        case ALGO_NEOSCRYPT:
        {
            unsigned int profile = 0x0;
            uint256 thash;
            assert(buf.size() == 80);
            neoscrypt(buf.data(), (unsigned char *)&thash, profile);				
            return thash;
        }
        case ALGO_EQUIHASH:
        {
            return this->GetSHA256Hash();
        }
        case ALGO_YESCRYPT:
        {
            uint256 thash;
            assert(buf.size() == 80);
            yescrypt_hash((const char*)buf.data(), (char*)&thash);
            return thash;
        }
        case ALGO_HMQ1725:
        {
            return HMQ1725(buf.data(), buf.data() + buf.size());
        }
        case ALGO_XEVAN:
        {
            return XEVAN(buf.data(), buf.data() + buf.size());	    
        }
        case ALGO_NIST5:
        {
            return NIST5(buf.data(), buf.data() + buf.size());	    
        }
        case ALGO_TIMETRAVEL10:
        {
            assert(buf.size() == 80);
            uint32_t nTime;
            memcpy(&nTime, buf.data() + 68, 4);
            return HashTimeTravel(buf.data(), buf.data() + buf.size(), nTime);	    
        }
        case ALGO_PAWELHASH:
        {
            return PawelHash(buf.data(), buf.data() + buf.size());
        }
        case ALGO_X13:
        {
            return HashX13(buf.data(), buf.data() + buf.size());
        }
        case ALGO_X14:
        {
            return HashX14(buf.data(), buf.data() + buf.size());
        }
        case ALGO_X15:
        {
            return HashX15(buf.data(), buf.data() + buf.size());
        }
        case ALGO_X17:
        {
            return HashX17(buf.data(), buf.data() + buf.size());
        }
        case ALGO_LYRA2REV2:
        {
            assert(buf.size() == 80);
            uint256 thash;
            lyra2re2_hash((const char*)buf.data(), (char*)&thash);
            return thash;
        }
        case ALGO_BLAKE2S:
        {
            return HashBlake2S(buf.data(), buf.data() + buf.size());
        }
        case ALGO_BLAKE2B:
        {
            return HashBlake2B(buf.data(), buf.data() + buf.size());
        }
        case ALGO_ASTRALHASH:
        {
            return AstralHash(buf.data(), buf.data() + buf.size());
        }
        case ALGO_PADIHASH:
        {
            return PadiHash(buf.data(), buf.data() + buf.size());
        }
        case ALGO_JEONGHASH:
        {
            return JeongHash(buf.data(), buf.data() + buf.size());
        }
        case ALGO_KECCAKC:
        {
            return HashKeccakC(buf.data(), buf.data() + buf.size());
        }
        case ALGO_ZHASH:
        {
            return this->GetSHA256Hash();
        }
        case ALGO_GLOBALHASH:
        {
            return GlobalHash(buf.data(), buf.data() + buf.size());
        }
        case ALGO_GROESTL:
        {
            return HashGroestl(buf.data(), buf.data() + buf.size());
        }
        case ALGO_SKEIN:
        {
            return HashSkein(buf.data(), buf.data() + buf.size());
        }
        case ALGO_QUBIT:
        {
            return HashQubit(buf.data(), buf.data() + buf.size());
        }
        case ALGO_SKUNKHASH:
        {
            return SkunkHash5(buf.data(), buf.data() + buf.size());
        }
        case ALGO_QUARK:
        {
            return QUARK(buf.data(), buf.data() + buf.size());
        }
        case ALGO_X16R:
        {
            assert(buf.size() == 80);
            uint256 hashPrevBlock;
            memcpy(&hashPrevBlock, buf.data() + 4, 32);
            return HashX16R(buf.data(), buf.data() + buf.size(), hashPrevBlock);
        }
        case ALGO_LYRA2REV3:
        {
            assert(buf.size() == 80);
            uint256 thash;
            lyra2re3_hash((const char*)buf.data(), (char*)&thash);
            return thash;
        }
        case ALGO_YESCRYPT_R16V2:
        {
            assert(buf.size() == 80);
            uint256 thash;
            yescrypt_r16v2_hash((const char*)buf.data(), (char*)&thash);
            return thash;
        }
        case ALGO_YESCRYPT_R24:
        {
            assert(buf.size() == 80);
            uint256 thash;
            yescrypt_r24_hash((const char*)buf.data(), (char*)&thash);
            return thash;
        }
        case ALGO_YESCRYPT_R8:
        {
            assert(buf.size() == 80);
            uint256 thash;
            if(this->nVersion & MULTIHASHER_YESCRYPT_R8_NEW)
                yescrypt_r8_hash((const char*)buf.data(), (char*)&thash);
            else
                yescrypt_hash((const char*)buf.data(), (char*)&thash);
            return thash;
        }
        case ALGO_YESCRYPT_R32:
        {
            assert(buf.size() == 80);
            uint256 thash;
            yescrypt_r32_hash((const char*)buf.data(), (char*)&thash);
            return thash;
        }
        case ALGO_X25X:
        {
            return HashX25X(buf.data(), buf.data() + buf.size());
        }
        case ALGO_ARGON2D:
        {
            uint256 salt, pepper, finalhash;
            salt = GlobalHash(buf.data(), buf.data() + buf.size());
            pepper = HashX16R(buf.data(), buf.data() + buf.size(), salt);
            Argon2dHash(buf.data(), buf.size(), finalhash.begin(), 32, salt.begin(), 32, pepper.begin(), 32);
            return finalhash;
        }
        case ALGO_ARGON2I:
        {
            uint256 salt, pepper, finalhash;
            salt = GlobalHash(buf.data(), buf.data() + buf.size());
            pepper = HashCPU23R(buf.data(), buf.data() + buf.size(), salt);
            Argon2iHash(buf.data(), buf.size(), finalhash.begin(), 32, salt.begin(), 32, pepper.begin(), 32);
            return finalhash;
        }
        case ALGO_CPU23R:
        {
            assert(buf.size() == 80);
            uint256 hashPrevBlock;
            memcpy(&hashPrevBlock, buf.data() + 4, 32);
            return HashCPU23R(buf.data(), buf.data() + buf.size(), hashPrevBlock);
        }
        case ALGO_YESPOWER:
        {
            assert(buf.size() == 80);
            uint256 thash;
            yespower_hash((const char*)buf.data(), (char*)&thash);
            return thash;
        }
        case ALGO_X21S:
        {
            assert(buf.size() == 80);
            uint256 hashPrevBlock;
            memcpy(&hashPrevBlock, buf.data() + 4, 32);
            return HashX21S(buf.data(), buf.data() + buf.size(), hashPrevBlock);
        }
        case ALGO_X16S:
        {
            assert(buf.size() == 80);
            uint256 hashPrevBlock;
            memcpy(&hashPrevBlock, buf.data() + 4, 32);
            return HashX16s(buf.data(), buf.data() + buf.size(), hashPrevBlock);
        }
        case ALGO_X22I:
        {
            return HashX22I(buf.data(), buf.data() + buf.size());
        }
        case ALGO_LYRA2Z:
        {
            assert(buf.size() == 80);
            uint256 thash;
            lyra2z_hash((const char*)buf.data(), (char*)&thash);
            return thash;
        }
        case ALGO_HONEYCOMB:
        {
            return HashHoneyComb(buf.data(), buf.data() + buf.size());
        }
        case ALGO_EH192:
        {
            return this->GetSHA256Hash();
        }
        case ALGO_MARS:
        {
            return this->GetSHA256Hash();
        }
        case ALGO_X12:
        {
            return HashX12(buf.data(), buf.data() + buf.size());
        }
        case ALGO_HEX:
        {
            return HashHEX(buf.data(), buf.data() + buf.size());
        }
        case ALGO_DEDAL:
        {
            return HashDedal(buf.data(), buf.data() + buf.size());
        }
        case ALGO_C11:
        {
            return HashC11(buf.data(), buf.data() + buf.size());
        }
        case ALGO_PHI1612:
        {
            return Phi1612(buf.data(), buf.data() + buf.size());
        }
        case ALGO_PHI2:
        {
            return PHI2(buf.data(), buf.data() + buf.size());
        }
        case ALGO_X16RT:
        {
            assert(buf.size() == 80);
            uint32_t nTime;
            memcpy(&nTime, buf.data() + 68, 4);
            int32_t nTimeX16r = nTime & 0xffffff80;
            uint256 hashTime = Hash(static_cast<char*>(static_cast<void*>(&nTimeX16r)), static_cast<char*>(static_cast<void*>(&nTimeX16r))+4);
            return HashX16R(buf.data(), buf.data() + buf.size(), hashTime);
        }
        case ALGO_TRIBUS:
        {
            return Tribus(buf.data(), buf.data() + buf.size());
        }
        case ALGO_ALLIUM:
        {
            assert(buf.size() == 80);
            uint256 thash;
            allium_hash((const char*)buf.data(), (char*)&thash);
            return thash;
        }
        case ALGO_ARCTICHASH:
        {
            return ArcticHash(buf.data(), buf.data() + buf.size());
        }
        case ALGO_DESERTHASH:
        {
            return DesertHash(buf.data(), buf.data() + buf.size());
        }
        case ALGO_CRYPTOANDCOFFEE:
        {
            return cryptoandcoffee_hash(buf.data(), buf.data() + buf.size());
        }
        case ALGO_RICKHASH:
        {
            return RickHash(buf.data(), buf.data() + buf.size());
        }
    }
    return this->GetSHA256Hash();
}

int LoadMultiHasherVersionFlags(bool fHardfork3Activated)
{
    return fHardfork3Activated ? PROTOCOL_VERSION | MULTIHASHER_YESCRYPT_R8_NEW : PROTOCOL_VERSION;
}