// Copyright (c) 2020 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GLOBALTOKEN_TREASURY_H
#define GLOBALTOKEN_TREASURY_H

#include <boost/filesystem.hpp>

#include <script/script.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

#include <string>
#include <vector>

class CTreasuryProposal
{
    
private:
    static const int MAX_HEADLINE_LENGTH     = 512;
    static const int MAX_DESCRIPTION_LENGTH  = 32768;
    
    // if this proposal is checked and the signer agreed with it.
    // (memory-only)
    bool fAgreed;
    
public:

    static const int MAX_TX_INPUTS = 1200;

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
        fAgreed = false;
        nVersion = 0;
        hashID.SetNull();
        nCreationTime = 0;
        nLastEdited = 0;
        nExpireTime = 0;
        strHeadline.clear();
        strDescription.clear();
        mtx = CMutableTransaction();
    }
    
    friend bool operator==(const CTreasuryProposal& a, const CTreasuryProposal& b)
    {
        return (a.fAgreed == b.fAgreed && a.nVersion == b.nVersion
                && a.hashID == b.hashID && a.nCreationTime == b.nCreationTime
                && a.nLastEdited == b.nLastEdited && a.nExpireTime == b.nExpireTime
                && a.strHeadline == b.strHeadline && a.strDescription == b.strDescription
                && a.mtx == b.mtx);
    }
    
    bool IsNull() const;
    bool IsHeadlineValid() const;
    bool IsDescriptionValid() const;
    bool IsExpired(const uint32_t nSystemTime) const;
    bool IsAgreed() const;
    bool SetAgreed();
    bool UnsetAgreed();
    void UpdateTimeData(const uint32_t nSystemTime);
    void RemoveOverflowedProposalTxInputs();
    void ClearProposalTxInputScriptSigs();
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
    boost::filesystem::path filePath;
    
    void BasicInit()
    {
        SetNull();
        nVersion = 1; // Current Version
    }
    
public:

    /* All treasury proposals */
    std::vector<CTreasuryProposal> vTreasuryProposals;
    
    /* All treasury redeemscripts and other scripts */
    std::vector<CScript> vRedeemScripts;
    
    /* The current treasury change address script */
    CScript scriptChangeAddress;

    CTreasuryMempool()
    {
        SetNull();
    }
    
    CTreasuryMempool(const std::string &path)
    {
        BasicInit();
        SetTreasuryFilePath(path);
    }
    
    void SetNull()
    {
        nVersion = 0;
        nLastSaved = 0;
        filePath.clear();
        vTreasuryProposals.clear();
        vRedeemScripts.clear();
        scriptChangeAddress.clear();
    }
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(nLastSaved);
        READWRITE(vTreasuryProposals);
        READWRITE(vRedeemScripts);
        READWRITE(scriptChangeAddress);
    }
    
    void SetTreasuryFilePath (const std::string &path);
    boost::filesystem::path GetTreasuryFilePath () const;
    bool IsCached() const;
    void SetVersion (const uint32_t nNewVersion);
    void SetLastSaved (const uint32_t nNewLastSaved);
    uint32_t GetVersion() const;
    uint32_t GetLastSaved() const;
    uint256 GetHash() const;
    void DeleteExpiredProposals(const uint32_t nSystemTime);
    bool SearchScriptByScript(const CScript &script, size_t &nIndex) const;
    bool RemoveScriptByID(const size_t nIndex);
    bool GetProposalvID(const uint256& hash, size_t& nIndex) const;
};

/** Treasury Stuff */
const std::string CONST_TREASURY_FILE_MARKER = "GlobalTokenTreasuryProposalFileMagic";
extern CTreasuryMempool activeTreasury;

#endif // GLOBALTOKEN_TREASURY_H
