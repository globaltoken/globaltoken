// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2018 The GlobalToken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBALTOKEN_MINING_BLOCK_H
#define GLOBALTOKEN_MINING_BLOCK_H

#include <primitives/block_dependencies.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

/** 2 Different Block classes for Equihash & normal blocks.
 *  + 2 classes for auxpow pos parent blocks.
 */
class CDefaultBlockHeader : public CPureBlockVersion
{
public:
    // header
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    CDefaultBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CPureBlockVersion*)this);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    }

    void SetNull()
    {
        CPureBlockVersion::SetNull();
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }
    
    uint256 GetHash() const;
	
    uint256 GetPoWHash(uint8_t algo, int nType, int nVersion) const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};


class CDefaultBlock : public CDefaultBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CDefaultBlock()
    {
        SetNull();
    }

    CDefaultBlock(const CDefaultBlockHeader &header)
    {
        SetNull();
        *(static_cast<CDefaultBlockHeader*>(this)) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*static_cast<CDefaultBlockHeader*>(this));
        READWRITE(vtx);
    }

    void SetNull()
    {
        CDefaultBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CDefaultBlockHeader GetDefaultBlockHeader() const
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
    
    std::string ToString() const;
};

class CEquihashBlockHeader : public CPureBlockVersion
{
public:
    // header
    static const size_t HEADER_SIZE=4+32+32+32+4+4+32; // excluding Equihash solution
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint256 hashReserved;
    uint32_t nTime;
    uint32_t nBits;
    uint256 nNonce;
    std::vector<unsigned char> nSolution; // Equihash solution.

    CEquihashBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CPureBlockVersion*)this);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(hashReserved);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
        READWRITE(nSolution);
    }

    void SetNull()
    {
        CPureBlockVersion::SetNull();
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        hashReserved.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce.SetNull();
        nSolution.clear();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};


class CEquihashBlock : public CEquihashBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CEquihashBlock()
    {
        SetNull();
    }

    CEquihashBlock(const CEquihashBlockHeader &header)
    {
        SetNull();
        *(static_cast<CEquihashBlockHeader*>(this)) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*static_cast<CEquihashBlockHeader*>(this));
        READWRITE(vtx);
    }

    void SetNull()
    {
        CEquihashBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CEquihashBlockHeader GetEquihashBlockHeader() const
    {
        CEquihashBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.hashReserved   = hashReserved;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.nSolution      = nSolution;
        return block;
    }

    std::string ToString() const;
};

class CPOSDefaultBlockHeader : public CPureBlockVersion
{
public:
    // header
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    CPOSDefaultBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CPureBlockVersion*)this);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    }

    void SetNull()
    {
        CPureBlockVersion::SetNull();
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};


class CPOSDefaultBlock : public CPOSDefaultBlockHeader
{
public:
    // network and disk
    std::vector<CPOSTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CPOSDefaultBlock()
    {
        SetNull();
    }

    CPOSDefaultBlock(const CPOSDefaultBlockHeader &header)
    {
        SetNull();
        *(static_cast<CPOSDefaultBlockHeader*>(this)) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*static_cast<CPOSDefaultBlockHeader*>(this));
        READWRITE(vtx);
    }

    void SetNull()
    {
        CPOSDefaultBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CPOSDefaultBlockHeader GetDefaultBlockHeader() const
    {
        CPOSDefaultBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        return block;
    }
    
    std::string ToString() const;
};

class CPOSEquihashBlockHeader : public CPureBlockVersion
{
public:
    // header
    static const size_t HEADER_SIZE=4+32+32+32+4+4+32; // excluding Equihash solution
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint256 hashReserved;
    uint32_t nTime;
    uint32_t nBits;
    uint256 nNonce;
    std::vector<unsigned char> nSolution; // Equihash solution.

    CPOSEquihashBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CPureBlockVersion*)this);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(hashReserved);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
        READWRITE(nSolution);
    }

    void SetNull()
    {
        CPureBlockVersion::SetNull();
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        hashReserved.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce.SetNull();
        nSolution.clear();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};


class CPOSEquihashBlock : public CPOSEquihashBlockHeader
{
public:
    // network and disk
    std::vector<CPOSTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CPOSEquihashBlock()
    {
        SetNull();
    }

    CPOSEquihashBlock(const CPOSEquihashBlockHeader &header)
    {
        SetNull();
        *(static_cast<CPOSEquihashBlockHeader*>(this)) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*static_cast<CPOSEquihashBlockHeader*>(this));
        READWRITE(vtx);
    }

    void SetNull()
    {
        CPOSEquihashBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CPOSEquihashBlockHeader GetEquihashBlockHeader() const
    {
        CPOSEquihashBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.hashReserved   = hashReserved;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.nSolution      = nSolution;
        return block;
    }

    std::string ToString() const;
};

/**
 * Custom serializer for CBlockHeader that omits the bignonce and solution, for use
 * as input to Equihash.
 */
class CEquihashInput : private CEquihashBlockHeader
{
public:
    CEquihashInput(const CEquihashBlockHeader &header)
    {
        CEquihashBlockHeader::SetNull();
        *((CEquihashBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(hashReserved);
        READWRITE(nTime);
        READWRITE(nBits);
    }
};

#endif // GLOBALTOKEN_MINING_BLOCK_H