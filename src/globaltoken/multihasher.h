// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2019 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBALTOKEN_MULTIHASHER_H
#define GLOBALTOKEN_MULTIHASHER_H

#include <globaltoken/powalgorithm.h>
#include <serialize.h>
#include <version.h>
#include <uint256.h>

#include <vector>

static const int MULTIHASHER_YESCRYPT_R8_NEW = 0x40000000;

/** A writer stream (for serialization) that computes a 256-bit hash, with selected algorithm. */
class CMultihasher
{
private:
    std::vector<unsigned char> buf;

    const int nType;
    const int nVersion;
    uint8_t nAlgo;
    uint256 GetSHA256Hash() const;
public:

    CMultihasher(int nTypeIn, int nVersionIn, uint8_t nAlgoIn) : nType(nTypeIn), nVersion(nVersionIn), nAlgo(nAlgoIn) {}

    int GetType() const { return nType; }
    int GetVersion() const { return nVersion; }

    void write(const char *pch, size_t size) {
        buf.insert(buf.end(), pch, pch + size);
    }

    uint256 GetHash() const;

    template<typename T>
    CMultihasher& operator<<(const T& obj) {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }
};

/** Compute the 256-bit hash of an object's serialization, with an selected algorithm. */
template<typename T>
uint256 SerializeMultiAlgoHash(const T& obj, uint8_t nAlgo, int nType=SER_GETHASH, int nVersion=PROTOCOL_VERSION)
{
    CMultihasher ss(nType, nVersion, nAlgo);
    ss << obj;
    return ss.GetHash();
}

int LoadMultiHasherVersionFlags(bool fHardfork3Activated);

#endif // GLOBALTOKEN_MULTIHASHER_H
