// Copyright (c) 2020 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBALTOKEN_TREASURY_H
#define GLOBALTOKEN_TREASURY_H

#include <uint256.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

#include <string>
#include <vector>

class CTreasuryProposal
{
    
public:

    // the version of this proposal
    uint32_t nVersion;

    // the ID of this proposal
    uint256 hashID;
    
    // creation time
    uint32_t nCreationTime;
    
    // last edited
    uint32_t nLastEdited;
    
    // the expiration time
    uint32_t nExpireTime;
    
    // headline of this propsal
    std::string strHeadline;
    
    // text description of this proposal
    std::string strDescription;
    
    // the related treasury transaction
    CMutableTransaction mtx;

    CTreasuryProposal()
    {
        SetNull();
    }
    
    void SetNull()
    {
        nVersion = 0;
        hashID.SetNull();
        nCreationTime = 0;
        nLastEdited = 0;
        nExpireTime = 0;
        strHeadline.clear();
        strDescription.clear();
        mtx = CMutableTransaction();
    }
    
    bool IsNull() const;
    uint256 GetHash() const;
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashID);
        READWRITE(nCreationTime);
        READWRITE(nLastEdited);
        READWRITE(nExpireTime);
        READWRITE(strHeadline);
        READWRITE(strDescription);
        READWRITE(mtx);
    }
};

class CTreasuryMempool {

private:

    /* the Version of this Treasury Mempool */
    uint32_t nVersion;
    
    /* The last unix timestamp when the file was saved to disk. */
    uint32_t nLastSaved;

    /* Directory of the current treasury file */
    std::string strTreasuryDir;
    
    /* File of the current treasury file */
    std::string strTreasuryFile;
    
    void BasicInit()
    {
        SetNull();
        nVersion = 1; // Current Version
    }
    
public:

    /* All treasury proposals */
    std::vector<CTreasuryProposal> vTreasuryProposals;

    CTreasuryMempool()
    {
        SetNull();
    }
    
    CTreasuryMempool(const std::string &dir, const std::string &filename)
    {
        BasicInit();
        strTreasuryDir = dir;
        strTreasuryFile = filename;
    }
    
    void SetNull()
    {
        nVersion = 0;
        nLastSaved = 0;
        strTreasuryDir.clear();
        strTreasuryFile.clear();
        vTreasuryProposals.clear();
    }
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(nLastSaved);
        READWRITE(vTreasuryProposals);
    }
    
    void SetTreasuryDir (const std::string &dir);
    void SetTreasuryFile (const std::string &file);
    std::string GetTreasuryDir () const;
    std::string GetTreasuryFile () const;
    bool IsCached() const;
    void SetVersion (const uint32_t nNewVersion);
    void SetLastSaved (const uint32_t nNewLastSaved);
    uint32_t GetVersion() const;
    uint32_t GetLastSaved() const;
};

/** Treasury Stuff */
const std::string CONST_TREASURY_FILE_MARKER = "GlobalTokenTreasuryProposalFileMagic";
extern CTreasuryMempool activeTreasury;

#endif // GLOBALTOKEN_TREASURY_H
