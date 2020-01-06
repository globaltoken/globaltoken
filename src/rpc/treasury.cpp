// Copyright (c) 2020 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/treasury.h>
#include <core_io.h>
#include <rpc/server.h>
#include <globaltoken/treasury.h>
#include <protocol.h>
#include <serialize.h>
#include <validation.h>
#include <utilstrencodings.h>
#include <utiltime.h>
#include <random.h>

#include <stdint.h>
#include <sstream>

#include <univalue.h>

#include <mutex>
#include <condition_variable>

UniValue treasurymempoolInfoToJSON()
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("proposals", (int64_t) activeTreasury.vTreasuryProposals.size());
    ret.pushKV("bytes", (int64_t) ::GetSerializeSize(activeTreasury, SER_NETWORK, PROTOCOL_VERSION));
    ret.pushKV("version", (int64_t) activeTreasury.GetVersion());
    ret.pushKV("lastsaved", (int64_t) activeTreasury.GetLastSaved());
    ret.pushKV("datadir", activeTreasury.GetTreasuryDir());
    ret.pushKV("filename", activeTreasury.GetTreasuryFile());
    return ret;
}

UniValue proposaltoJSON(const CTreasuryProposal* proposal, int decodeProposalTX)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("id", proposal->hashID.GetHex());
    result.pushKV("bytes", (int)::GetSerializeSize(*proposal, SER_NETWORK, PROTOCOL_VERSION));
    result.pushKV("version", (int64_t)proposal->nVersion);
    result.pushKV("creationtime", (int64_t)proposal->nCreationTime);
    result.pushKV("lasteditedtime", (int64_t)proposal->nLastEdited);
    result.pushKV("expiretime", (int64_t)proposal->nExpireTime);
    result.pushKV("headline", proposal->strHeadline);
    result.pushKV("description", proposal->strDescription);
    if(decodeProposalTX)
    {
        CTransaction tx(proposal->mtx);
        UniValue objTx(UniValue::VOBJ);
        TxToUniv(tx, uint256(), objTx, decodeProposalTX == 2, RPCSerializationFlags());
        result.pushKV("tx", objTx);
    }
    return result;
}

UniValue gettreasuryproposal(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1 && request.params.size() != 2)
        throw std::runtime_error(
            "gettreasuryproposal\n"
            "\nReturns details of the treasury proposals.\n"
            "\nArguments:\n"
            "1. \"id\"         (required, string) The proposal ID to get details for.\n"
            "2. \"txdecode\"   (optional, int, default=0) How to decode the treasury transaction (0 = don't decode, 1 = decode without hex, 2 = decode and show hex tx)\n"
            "\nResult:\n"
            "{\n"
            "  \"id\": xxxxx,                (hash) The ID of this proposal\n"
            "  \"bytes\": xxxxx,             (int) Size in bytes of this proposal.\n"
            "  \"version\": xxxxx,           (int) The version of this proposal.\n"
            "  \"creationtime\": xxxxx,      (int) The unix timestamp, when the proposal was created.\n"
            "  \"lasteditedtime\": xxxxx,    (int) The unix timestamp, when the proposal was edited last time.\n"
            "  \"expiretime\": xxxxx,        (int) The unix timestamp, when the proposal will expire.\n"
            "  \"headline\": xxxxx,          (string) The headline of this proposal.\n"
            "  \"description\": xxxxx,       (string) The proposal description.\n"
            "  \"tx\": {\n,                  (object) The decoded transation to json.\n"
            "      ....,                     \n"
            "  }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("gettreasuryproposal", "")
            + HelpExampleRpc("gettreasuryproposal", "")
        );
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    const CTreasuryProposal *currentProposal = nullptr;
    uint256 proposalHash = uint256S(request.params[0].get_str());
    int nSettings = (!request.params[1].isNull()) ? request.params[1].get_int() : 0;
    
    if(nSettings < 0 || nSettings > 2)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid txdecode param value.");
    
    for(size_t i = 0; i < activeTreasury.vTreasuryProposals.size(); i++)
    {
        if(activeTreasury.vTreasuryProposals[i].hashID == proposalHash)
        {
            currentProposal = &activeTreasury.vTreasuryProposals[i];
            break;
        }
    }
    
    if(currentProposal == nullptr)
        throw JSONRPCError(RPC_MISC_ERROR, "Treasury proposal not found.");

    return proposaltoJSON(currentProposal, nSettings);
}

UniValue gettreasuryproposalinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0 && request.params.size() != 1)
        throw std::runtime_error(
            "gettreasuryproposalinfo\n"
            "\nReturns details of the treasury proposals.\n"
            "\nArguments:\n"
            "1. \"decodeproposal\"   (optional, int, default=0) How to decode the treasury proposal (0 = don't decode proposal, 1 = decode proposal, 2 = decode proposal with tx, 3 = decode proposal with tx and hex tx)\n"
            "\nResult:\n"
            "{\n"
            "  \"count\": xxxxx,              (numeric) Current proposal objects\n"
            "  \"proposals\": xxxxx,          (array) Array of all proposal IDs.\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("gettreasuryproposalinfo", "")
            + HelpExampleRpc("gettreasuryproposalinfo", "")
        );
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    int nSettings = (!request.params[0].isNull()) ? request.params[0].get_int() : 0;
    
    if(nSettings < 0 || nSettings > 3)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid decodeproposal param value.");

    UniValue ret(UniValue::VOBJ), proposals(UniValue::VARR);
    ret.pushKV("count", (int64_t) activeTreasury.vTreasuryProposals.size());
    
    if(nSettings == 0)
    {
        for(size_t i = 0; i < activeTreasury.vTreasuryProposals.size(); i++)
        {
            proposals.push_back(activeTreasury.vTreasuryProposals[i].hashID.GetHex());
        }
    }
    else if(nSettings == 1)
    {
        proposals.setObject();
        for(size_t i = 0; i < activeTreasury.vTreasuryProposals.size(); i++)
        {
            proposals.push_back(proposaltoJSON(&activeTreasury.vTreasuryProposals[i], 0));
        }
    }
    else if(nSettings == 2)
    {
        proposals.setObject();
        for(size_t i = 0; i < activeTreasury.vTreasuryProposals.size(); i++)
        {
            proposals.push_back(proposaltoJSON(&activeTreasury.vTreasuryProposals[i], 1));
        }
    }
    else
    {
        proposals.setObject();
        for(size_t i = 0; i < activeTreasury.vTreasuryProposals.size(); i++)
        {
            proposals.push_back(proposaltoJSON(&activeTreasury.vTreasuryProposals[i], 2));
        }
    }
    ret.pushKV("proposals", proposals);
    return ret;
}

UniValue gettreasurymempoolinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "gettreasurymempoolinfo\n"
            "\nReturns details on the active state of the treasury memory pool.\n"
            "\nResult:\n"
            "{\n"
            "  \"proposals\": xxxxx,          (numeric) Current proposal objects\n"
            "  \"bytes\": xxxxx,              (numeric) Size in bytes of this treasury memory pool\n"
            "  \"version\": xxxxx,            (numeric) The version of this treasury mempool\n"
            "  \"lastsaved\": xxxxx,          (numeric) Unix timestamp, when the mempool was last saved\n"
            "  \"datadir\": xxxxx             (numeric) The current datadir of the loaded treasury memory pool\n"
            "  \"filename\": xxxxx            (numeric) The current file of the loaded treasury memory pool\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("gettreasurymempoolinfo", "")
            + HelpExampleRpc("gettreasurymempoolinfo", "")
        );
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");

    return treasurymempoolInfoToJSON();
}

UniValue opentreasurymempool(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "opentreasurymempool\n"
            "\nReads the treasury mempool from disk.\n"
            "\nArguments:\n"
            "1. \"directory\"   (required, string) The directory, where the treasury mempool is saved into.\n"
            "2. \"filename\"    (required, string) The name of the file, to open.\n"
            "\nExamples:\n"
            + HelpExampleCli("opentreasurymempool", "")
            + HelpExampleRpc("opentreasurymempool", "")
        );
    }
    
    if (activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "You have already a cached treasury mempool. Close, Abort or save it in order to open a new one.");
    
    CTreasuryMempool cachedTreasury = CTreasuryMempool(request.params[0].get_str(), request.params[1].get_str());

    std::string error;
    if (!LoadTreasuryMempool(cachedTreasury, error)) {
        throw JSONRPCError(RPC_MISC_ERROR, std::string("Unable to load treasury mempool from disk. Reason: ") + error);
    }
    
    activeTreasury = cachedTreasury;

    return NullUniValue;
}

UniValue createtreasurymempool(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "createtreasurymempool\n"
            "\nCreates the treasury mempool file on disk.\n"
            "\nArguments:\n"
            "1. \"directory\"   (required, string) The directory, where the treasury mempool will be saved into.\n"
            "2. \"filename\"    (required, string) The name of the file, to create.\n"
            "\nExamples:\n"
            + HelpExampleCli("createtreasurymempool", "")
            + HelpExampleRpc("createtreasurymempool", "")
        );
    }
    
    if (activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "You have already a cached treasury mempool. Close, Abort or save it in order to create a new one.");
    
    CTreasuryMempool cachedTreasury = CTreasuryMempool(request.params[0].get_str(), request.params[1].get_str());
    
    std::string error;
    if (!TreasuryMempoolSanityChecks(cachedTreasury, error, true, nullptr)) {
        throw JSONRPCError(RPC_MISC_ERROR, std::string("Treasury Mempool Sanity checks failed: ") + error);
    }

    if (!DumpTreasuryMempool(cachedTreasury, error)) {
        throw JSONRPCError(RPC_MISC_ERROR, std::string("Unable to create new treasury mempool to disk. Reason: ") + error);
    }
    
    activeTreasury = cachedTreasury;

    return NullUniValue;
}

UniValue createtreasuryproposal(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "createtreasuryproposal\n"
            "\nCreates a new treasury proposal and adds it to the treasury memory pool.\n"
            "\nArguments:\n"
            "1. \"headline\"    (required, string) The headline of this proposal\n"
            "2. \"description\" (required, string) The description of this proposal\n"
            "\nExamples:\n"
            + HelpExampleCli("createtreasuryproposal", "")
            + HelpExampleRpc("createtreasuryproposal", "")
        );
    }
    
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    // Create the proposal and give it a random hash.
    uint32_t nCurrentTime = GetTime();
    CTreasuryProposal proposal;
    uint256 hashRandom;
    std::stringstream strStream;
    GetStrongRandBytes((unsigned char*)&hashRandom, sizeof(hashRandom));
    
    proposal.nVersion = 1;
    proposal.hashID = hashRandom;
    proposal.nCreationTime = nCurrentTime;
    proposal.nLastEdited = nCurrentTime;
    proposal.nExpireTime = nCurrentTime + (60 * 60 * 24 * 31); // ~ One month until this proposal will expire.
    proposal.strHeadline = request.params[0].get_str();
    proposal.strDescription = request.params[1].get_str();
    
    if(!proposal.IsHeadlineValid())
    {
        strStream << "Headline exceeds max length with " << proposal.strHeadline.length() << "chars!";
        throw JSONRPCError(RPC_INVALID_PARAMETER, strStream.str());
    }
    
    if(!proposal.IsDescriptionValid())
    {
        strStream << "Description exceeds max length with " << proposal.strDescription.length() << "chars!";
        throw JSONRPCError(RPC_INVALID_PARAMETER, strStream.str());
    }
    
    hashRandom = proposal.GetHash(); // now we get the final ID (from all data)
    proposal.hashID = hashRandom;
    
    // Now add the proposal to cachedTreasury
    activeTreasury.vTreasuryProposals.push_back(proposal);

    return proposal.hashID.GetHex();
}

UniValue savetreasurymempooltonewfile(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "savetreasurymempooltonewfile\n"
            "\nSaves the treasury mempool to a new file.\n"
            "\nArguments:\n"
            "1. \"directory\"   (required, string) The directory, where the treasury mempool will be saved into.\n"
            "2. \"filename\"    (required, string) The name of the file, to create.\n"
            "\nExamples:\n"
            + HelpExampleCli("savetreasurymempooltonewfile", "")
            + HelpExampleRpc("savetreasurymempooltonewfile", "")
        );
    }
    
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    std::string error;
    CTreasuryMempool cachedTreasury = activeTreasury;
    cachedTreasury.SetTreasuryDir(request.params[0].get_str());
    cachedTreasury.SetTreasuryFile(request.params[1].get_str());
    
    if (!TreasuryMempoolSanityChecks(cachedTreasury, error, true, nullptr)) {
        throw JSONRPCError(RPC_MISC_ERROR, std::string("Treasury Mempool Sanity checks failed: ") + error);
    }

    if (!DumpTreasuryMempool(cachedTreasury, error)) {
        throw JSONRPCError(RPC_MISC_ERROR, std::string("Unable to create new treasury mempool to disk. Reason: ") + error);
    }

    return NullUniValue;
}

UniValue savetreasurymempool(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "savetreasurymempool\n"
            "\nSaves the treasury mempool to disk.\n"
            "\nExamples:\n"
            + HelpExampleCli("savetreasurymempool", "")
            + HelpExampleRpc("savetreasurymempool", "")
        );
    }
    
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");

    std::string error;
    if (!DumpTreasuryMempool(activeTreasury, error)) {
        throw JSONRPCError(RPC_MISC_ERROR, std::string("Unable to dump treasury mempool to disk. Reason: ") + error);
    }

    return NullUniValue;
}

UniValue closetreasurymempool(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "closetreasurymempool\n"
            "\nSaves and closes the treasury mempool stream.\n"
            "\nExamples:\n"
            + HelpExampleCli("closetreasurymempool", "")
            + HelpExampleRpc("closetreasurymempool", "")
        );
    }
    
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");

    std::string error;
    if (!DumpTreasuryMempool(activeTreasury, error)) {
        throw JSONRPCError(RPC_MISC_ERROR, std::string("Unable to dump treasury mempool to disk. Reason: ") + error);
    }
    
    activeTreasury.SetNull();

    return NullUniValue;
}

UniValue aborttreasurymempool(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "aborttreasurymempool\n"
            "\nCloses the treasury mempool without saving changes.\n"
            "\nExamples:\n"
            + HelpExampleCli("aborttreasurymempool", "")
            + HelpExampleRpc("aborttreasurymempool", "")
        );
    }
    
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    activeTreasury.SetNull();

    return NullUniValue;
}

static const CRPCCommand commands[] =
{ //  category              name                            actor (function)               argNames
  //  --------------------- ------------------------------  -----------------------------  ----------
    { "treasury",           "savetreasurymempool",          &savetreasurymempool,          {} },
    { "treasury",           "gettreasurymempoolinfo",       &gettreasurymempoolinfo,       {} },
    { "treasury",           "closetreasurymempool",         &closetreasurymempool,         {} },
    { "treasury",           "aborttreasurymempool",         &aborttreasurymempool,         {} },
    { "treasury",           "gettreasuryproposalinfo",      &gettreasuryproposalinfo,      {"decodeproposal"} },
    { "treasury",           "gettreasuryproposal",          &gettreasuryproposal,          {"id", "txdecode"} },
    { "treasury",           "createtreasurymempool",        &createtreasurymempool,        {"directory","filename"}   },
    { "treasury",           "opentreasurymempool",          &opentreasurymempool,          {"directory","filename"}   },
    { "treasury",           "savetreasurymempooltonewfile", &savetreasurymempooltonewfile, {"directory","filename"}   },
    { "treasury",           "createtreasuryproposal",       &createtreasuryproposal,       {"headline","description"} }
};

void RegisterTreasuryRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
