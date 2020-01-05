// Copyright (c) 2020 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/treasury.h>
#include <rpc/server.h>
#include <globaltoken/treasury.h>
#include <protocol.h>
#include <serialize.h>
#include <validation.h>
#include <utilstrencodings.h>

#include <stdint.h>

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
        throw JSONRPCError(RPC_MISC_ERROR, "You have already an cached treasury mempool. Close, Abort or save it in order to open a new one.");
    
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
        throw JSONRPCError(RPC_MISC_ERROR, "You have already an cached treasury mempool. Close, Abort or save it in order to create a new one.");
    
    CTreasuryMempool cachedTreasury = CTreasuryMempool(request.params[0].get_str(), request.params[1].get_str());

    std::string error;
    if (!DumpTreasuryMempool(cachedTreasury, error)) {
        throw JSONRPCError(RPC_MISC_ERROR, std::string("Unable to create new treasury mempool to disk. Reason: ") + error);
    }
    
    activeTreasury = cachedTreasury;

    return NullUniValue;
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
    
    CTreasuryMempool cachedTreasury = activeTreasury;
    cachedTreasury.SetTreasuryDir(request.params[0].get_str());
    cachedTreasury.SetTreasuryFile(request.params[1].get_str());

    std::string error;
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
    { "treasury",           "createtreasurymempool",        &createtreasurymempool,        {"directory","filename"} },
    { "treasury",           "opentreasurymempool",          &opentreasurymempool,          {"directory","filename"} },
    { "treasury",           "savetreasurymempooltonewfile", &savetreasurymempooltonewfile, {"directory","filename"}}
};

void RegisterTreasuryRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
