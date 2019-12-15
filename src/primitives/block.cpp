// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2018-2019 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>
#include <globaltoken/powalgorithm.h>
#include <hash.h>
#include <tinyformat.h>
#include <utilstrencodings.h>

void CBlockHeader::SetAuxpow (CAuxPow* apow)
{
    if (apow)
    {
        auxpow.reset(apow);
        SetAuxpowVersion(true);
    } else
    {
        auxpow.reset();
        SetAuxpowVersion(false);
    }
}

std::string CBlock::ToString(bool fHardfork3) const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, powalgo=%u, powalgoname=%s, powhash=%s, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, nBigNonce=%s, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        GetAlgo(),
        GetAlgoName(GetAlgo()),
        GetPoWHash(SER_GETHASH, LoadMultiHasherVersionFlags(fHardfork3)).ToString(),
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce, nBigNonce.GetHex(),
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}