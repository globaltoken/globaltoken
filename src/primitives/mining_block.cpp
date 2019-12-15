// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/mining_block.h>
#include <globaltoken/multihasher.h>

#include <hash.h>
#include <tinyformat.h>
#include <utilstrencodings.h>
#include <chainparams.h>
#include <crypto/common.h>

uint256 CDefaultBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CEquihashBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CDefaultBlockHeader::GetPoWHash(uint8_t algo, int nType, int nVersion) const
{
    return SerializeMultiAlgoHash(*this, algo, nType, nVersion);
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