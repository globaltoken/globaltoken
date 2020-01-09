// Copyright (c) 2020 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <core_io.h>
#include <coins.h>
#include <consensus/validation.h>
#include <globaltoken/treasury.h>
#include <protocol.h>
#include <serialize.h>
#include <init.h>
#include <net.h>
#include <net_processing.h>
#include <policy/policy.h>
#include <validation.h>
#include <validationinterface.h>
#include <rpc/safemode.h>
#include <rpc/server.h>
#include <rpc/treasury.h>
#include <utilstrencodings.h>
#include <utiltime.h>
#include <random.h>
#include <sync.h>
#include <txmempool.h>
#include <script/script.h>
#include <script/standard.h>

#include <stdint.h>
#include <sstream>

#include <univalue.h>

#include <mutex>
#include <future>
#include <condition_variable>

UniValue treasurymempoolInfoToJSON()
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("proposals", (int64_t) activeTreasury.vTreasuryProposals.size());
    ret.pushKV("scripts", (int64_t) activeTreasury.vRedeemScripts.size());
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
    result.pushKV("expired", proposal->IsExpired(GetTime()));
    result.pushKV("agreed", proposal->IsAgreed());
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

UniValue broadcastallsignedproposals(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0 && request.params.size() != 1)
        throw std::runtime_error(
            "broadcastsignedproposal ( allowhighfees )\n"
            "\nSubmits signed treasury proposal transaction (serialized, hex-encoded) to local node and network.\n"
            "\nAlso see createrawtransaction, updateproposaltxfromhex and signtreasuryproposalswithwallet calls.\n"
            "\nArguments:\n"
            "1. allowhighfees    (boolean, optional, default=false) Allow high fees\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "      \"proposal\"           (hash) The proposal ID hash of this entry.\n"
            "      \"txid\"               (hash) The TXID of this proposal.\n"
            "      \"sent\"               (bool) Returns true, if this transaction has been broadcasted successfully, otherwise false.\n"
            "      \"error\"              (string) If this transaction was not successfully broadcasted, it will tell you the error with this argument.\n"
            "  }\n"
            "]\n"
            "\nCreate a transaction\n"
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\" : \\\"mytxid\\\",\\\"vout\\\":0}]\" \"{\\\"myaddress\\\":0.01}\"") +
            "Sign the transaction, and get back the hex\n"
            + HelpExampleCli("updateproposaltxfromhex", "\"proposalsid\" \"myhex\"") +
            "\nSend the transaction (signed hex)\n"
            + HelpExampleCli("broadcastsignedproposal", "\"proposalid\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("broadcastsignedproposal", "\"proposalid\"")
        );
        
    RPCTypeCheck(request.params, {UniValue::VBOOL});
    UniValue ret(UniValue::VARR);
        
    LOCK(cs_treasury);

    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    if(activeTreasury.vTreasuryProposals.size() == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No treasury proposals in mempool.");
    
    ObserveSafeMode();

    CAmount nMaxRawTxFee = maxTxFee;
    if (!request.params[0].isNull() && request.params[0].get_bool())
        nMaxRawTxFee = 0;
    
    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    
    std::vector<CTreasuryProposal> vPps;

    { // cs_main scope
    LOCK(cs_main);
    CCoinsViewCache &view = *pcoinsTip;
    
    for(size_t i = 0; i < activeTreasury.vTreasuryProposals.size(); i++)
    {
        const CTransaction txConst(activeTreasury.vTreasuryProposals[i].mtx);
        bool fFailed = true;
        for (unsigned int input = 0; input < activeTreasury.vTreasuryProposals[i].mtx.vin.size(); input++) 
        {
            CTxIn& txin = activeTreasury.vTreasuryProposals[i].mtx.vin[input];
            const Coin& coin = view.AccessCoin(txin.prevout);
            if (coin.IsSpent())
            {
                break;
            }
            
            const CScript& prevPubKey = coin.out.scriptPubKey;
            const CAmount& amount = coin.out.nValue;

            // The Script should return no error, that means it's complete.
            ScriptError serror = SCRIPT_ERR_OK;
            if (!VerifyScript(txin.scriptSig, prevPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, input, amount), &serror)) 
            {
                break;
            }
            fFailed = false;
        }
        
        if(!fFailed)
            vPps.push_back(activeTreasury.vTreasuryProposals[i]);
    }
    
    if(vPps.size() == 0)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No signed transactions found!");
    
    for(size_t i = 0; i < vPps.size(); i++)
    {
        std::promise<void> promise;
        UniValue obj(UniValue::VOBJ);
        CMutableTransaction mtx = vPps[i].mtx;
        CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
        const uint256& hashTx = tx->GetHash();
        std::string strErrMsg;
        bool fSent = false, fHaveChain = false;
        
        obj.pushKV("proposal", vPps[i].hashID.GetHex());
        obj.pushKV("txid", hashTx.GetHex());
        
        for (size_t o = 0; !fHaveChain && o < tx->vout.size(); o++) {
            const Coin& existingCoin = view.AccessCoin(COutPoint(hashTx, o));
            fHaveChain = !existingCoin.IsSpent();
        }
        bool fHaveMempool = mempool.exists(hashTx);
        if (!fHaveMempool && !fHaveChain) {
            // push to local node and sync with wallets
            CValidationState state;
            bool fMissingInputs;
            if (!AcceptToMemoryPool(mempool, state, std::move(tx), &fMissingInputs,
                                    nullptr /* plTxnReplaced */, false /* bypass_limits */, nMaxRawTxFee)) {
                if (state.IsInvalid()) {
                    strErrMsg = FormatStateMessage(state);
                } else {
                    if (fMissingInputs) {
                        strErrMsg = "Missing inputs";
                    }
                    strErrMsg = FormatStateMessage(state);
                }
            } else {
                // If wallet is enabled, ensure that the wallet has been made aware
                // of the new transaction prior to returning. This prevents a race
                // where a user might call sendrawtransaction with a transaction
                // to/from their wallet, immediately call some wallet RPC, and get
                // a stale result because callbacks have not yet been processed.
                CallFunctionInValidationInterfaceQueue([&promise] {
                    promise.set_value();
                });
                
                fSent = true;
            }
        } else if (fHaveChain) {
            strErrMsg = "transaction already in block chain";
        } else {
            // Make sure we don't block forever if re-sending
            // a transaction already in mempool.
            promise.set_value();
        }
        
        obj.pushKV("sent", fSent);
        if(strErrMsg.length() > 0)
            obj.pushKV("error", strErrMsg);
        
        if(!fSent)
            vPps[i].SetNull();
        
        ret.push_back(obj);
        promise.get_future().wait();
    }

    } // cs_main
    
    for(size_t i = 0; i < vPps.size(); i++)
    {
        if(vPps[i].IsNull())
            vPps.erase(vPps.begin() + i);
    }

    for(size_t i = 0; i < vPps.size(); i++)
    {
        const CTransaction ctx(vPps[i].mtx);
        size_t nIndex = 0;
        RelayTransactionFromExtern(ctx, g_connman.get());
        
        if(!activeTreasury.GetProposalvID(vPps[i].hashID, nIndex))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Could not find treasury proposal while broadcasting the transaction");
        
        activeTreasury.vTreasuryProposals[nIndex].nExpireTime = GetTime() + (60 * 60 * 15); // This proposal has been successful completed, let it expire now in 15 minutes, so last checks can be done and then it will be deleted.
    }

    return ret;
}

UniValue broadcastsignedproposal(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "broadcastsignedproposal \"id\" ( allowhighfees )\n"
            "\nSubmits signed treasury proposal transaction (serialized, hex-encoded) to local node and network.\n"
            "\nAlso see createrawtransaction, updateproposaltxfromhex and signtreasuryproposalswithwallet calls.\n"
            "\nArguments:\n"
            "1. \"id\"           (string, required) The proposal ID, that has a signed transaction and now should be broadcasted via network.\n"
            "2. allowhighfees    (boolean, optional, default=false) Allow high fees\n"
            "\nResult:\n"
            "\nThe transaction ID, if successful, otherwise it returns an error.\n"
            "\nCreate a transaction\n"
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\" : \\\"mytxid\\\",\\\"vout\\\":0}]\" \"{\\\"myaddress\\\":0.01}\"") +
            "Sign the transaction, and get back the hex\n"
            + HelpExampleCli("updateproposaltxfromhex", "\"proposalsid\" \"myhex\"") +
            "\nSend the transaction (signed hex)\n"
            + HelpExampleCli("broadcastsignedproposal", "\"proposalid\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("broadcastsignedproposal", "\"proposalid\"")
        );
        
    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VBOOL});
        
    LOCK(cs_treasury);

    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    uint256 proposalHash = uint256S(request.params[0].get_str());
    size_t nIndex = 0;
    
    if(!activeTreasury.GetProposalvID(proposalHash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");
    
    ObserveSafeMode();

    std::promise<void> promise;
    
    CTreasuryProposal* pProposal = &activeTreasury.vTreasuryProposals[nIndex];

    CMutableTransaction mtx = pProposal->mtx;
    CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
    const uint256& hashTx = tx->GetHash();

    CAmount nMaxRawTxFee = maxTxFee;
    if (!request.params[1].isNull() && request.params[1].get_bool())
        nMaxRawTxFee = 0;

    { // cs_main scope
    LOCK(cs_main);
    CCoinsViewCache &view = *pcoinsTip;
    bool fHaveChain = false;
    for (size_t o = 0; !fHaveChain && o < tx->vout.size(); o++) {
        const Coin& existingCoin = view.AccessCoin(COutPoint(hashTx, o));
        fHaveChain = !existingCoin.IsSpent();
    }
    bool fHaveMempool = mempool.exists(hashTx);
    if (!fHaveMempool && !fHaveChain) {
        // push to local node and sync with wallets
        CValidationState state;
        bool fMissingInputs;
        if (!AcceptToMemoryPool(mempool, state, std::move(tx), &fMissingInputs,
                                nullptr /* plTxnReplaced */, false /* bypass_limits */, nMaxRawTxFee)) {
            if (state.IsInvalid()) {
                throw JSONRPCError(RPC_TRANSACTION_REJECTED, FormatStateMessage(state));
            } else {
                if (fMissingInputs) {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
                }
                throw JSONRPCError(RPC_TRANSACTION_ERROR, FormatStateMessage(state));
            }
        } else {
            // If wallet is enabled, ensure that the wallet has been made aware
            // of the new transaction prior to returning. This prevents a race
            // where a user might call sendrawtransaction with a transaction
            // to/from their wallet, immediately call some wallet RPC, and get
            // a stale result because callbacks have not yet been processed.
            CallFunctionInValidationInterfaceQueue([&promise] {
                promise.set_value();
            });
        }
    } else if (fHaveChain) {
        throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain");
    } else {
        // Make sure we don't block forever if re-sending
        // a transaction already in mempool.
        promise.set_value();
    }

    } // cs_main

    promise.get_future().wait();

    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    RelayTransactionFromExtern(*tx, g_connman.get());
    pProposal->nExpireTime = GetTime() + (60 * 60 * 15); // This proposal has been successful completed, let it expire now in 15 minutes, so last checks can be done and then it will be deleted.

    return hashTx.GetHex();
}

UniValue updateproposaltxfromhex(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "updateproposaltxfromhex\n"
            "\nUpdates a treasury proposal transaction from given hex.\n"
            "\nArguments:\n"
            "1. \"id\"            (required, string) The proposal ID to update the transaction for.\n"
            "2. \"hextx\"         (required, string) The raw tx hex encoded, that should be inserted into the proposal.\n"
            "\nResult:\n"
            "{\nNull, if successfully updated, otherwise it will return an error.\n"
            "\nExamples:\n"
            + HelpExampleCli("updateproposaltxfromhex", "")
            + HelpExampleRpc("updateproposaltxfromhex", "")
        );
        
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    uint256 proposalHash = uint256S(request.params[0].get_str());
    size_t nIndex = 0;
    CMutableTransaction mtx;
    
    if(!activeTreasury.GetProposalvID(proposalHash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");
    
    if (!DecodeHexTx(mtx, request.params[1].get_str(), true)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }
    
    if(activeTreasury.vTreasuryProposals[nIndex].mtx.GetHash() == mtx.GetHash())
        throw JSONRPCError(RPC_MISC_ERROR, "The transaction is already up to date.");

    activeTreasury.vTreasuryProposals[nIndex].mtx = mtx;
    return NullUniValue;
}

UniValue getproposaltxashex(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getproposaltxashex\n"
            "\nUpdates a treasury proposal transaction from given hex.\n"
            "\nArguments:\n"
            "1. \"id\"            (required, string) The proposal ID to get the hex tx for.\n"
            "\nResult:\n"
            "{\nThe hex encoded transaction, if successful, otherwise it will return an error.\n"
            "\nExamples:\n"
            + HelpExampleCli("getproposaltxashex", "")
            + HelpExampleRpc("getproposaltxashex", "")
        );
        
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    uint256 proposalHash = uint256S(request.params[0].get_str());
    size_t nIndex = 0;
    
    if(!activeTreasury.GetProposalvID(proposalHash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");

    const CTransaction ctx(activeTreasury.vTreasuryProposals[nIndex].mtx);
    return EncodeHexTx(ctx, RPCSerializationFlags());
}

UniValue votetreasuryproposal(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "votetreasuryproposal\n"
            "\nVotes for a treasury proposal.\n"
            "\nArguments:\n"
            "1. \"id\"         (required, string) The proposal ID to vote for.\n"
            "\nResult:\n"
            "{\nNull, if voted otherwise it will return an error.\n"
            "\nExamples:\n"
            + HelpExampleCli("votetreasuryproposal", "")
            + HelpExampleRpc("votetreasuryproposal", "")
        );
        
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    uint256 proposalHash = uint256S(request.params[0].get_str());
    size_t nIndex = 0;
    
    if(!activeTreasury.GetProposalvID(proposalHash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");
    
    if(!activeTreasury.vTreasuryProposals[nIndex].SetAgreed())
        throw JSONRPCError(RPC_MISC_ERROR, "You already agreed with this proposal, use \"deltreasuryproposalvote\" to delete your vote.");

    return NullUniValue;
}

UniValue deltreasuryproposalvote(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "deltreasuryproposalvote\n"
            "\nRemoves your vote from a treasury proposal.\n"
            "\nArguments:\n"
            "1. \"id\"         (required, string) The proposal ID to vote for.\n"
            "\nResult:\n"
            "{\nNull, if the vote has been deleted, otherwise it returns an error.\n"
            "\nExamples:\n"
            + HelpExampleCli("deltreasuryproposalvote", "")
            + HelpExampleRpc("deltreasuryproposalvote", "")
        );
        
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    uint256 proposalHash = uint256S(request.params[0].get_str());
    size_t nIndex = 0;
    
    if(!activeTreasury.GetProposalvID(proposalHash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");
    
    if(!activeTreasury.vTreasuryProposals[nIndex].UnsetAgreed())
        throw JSONRPCError(RPC_MISC_ERROR, "This proposal is unvoted, use \"votetreasuryproposal\" to add your vote.");

    return NullUniValue;
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
            "  \"expired\": xxxxx,           (bool) Returns true if this proposal is expired, otherwise false.\n"
            "  \"agreed\": xxxxx,            (bool) Returns true if a vote has been saved for this proposal, otherwise false.\n"
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
        
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    const CTreasuryProposal *currentProposal = nullptr;
    uint256 proposalHash = uint256S(request.params[0].get_str());
    int nSettings = (!request.params[1].isNull()) ? request.params[1].get_int() : 0;
    size_t nIndex = 0;
    
    if(nSettings < 0 || nSettings > 2)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid txdecode param value.");
    
    if(!activeTreasury.GetProposalvID(proposalHash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");

    return proposaltoJSON(&activeTreasury.vTreasuryProposals[nIndex], nSettings);
}

UniValue cleartreasuryscripts(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "cleartreasuryscripts\n"
            "\nRemoves all treasury scripts from treasury mempool.\n"
            "\nResult:\n"
            "\n(string) Returns null.\n"
            "\nExamples:\n"
            + HelpExampleCli("cleartreasuryscripts", "")
            + HelpExampleRpc("cleartreasuryscripts", "")
        );
        
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    activeTreasury.vRedeemScripts.clear();
    return NullUniValue;
}

UniValue cleartreasuryproposals(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "cleartreasuryproposals\n"
            "\nRemoves all treasury proposals from treasury mempool.\n"
            "\nResult:\n"
            "\n(string) Returns null.\n"
            "\nExamples:\n"
            + HelpExampleCli("cleartreasuryproposals", "")
            + HelpExampleRpc("cleartreasuryproposals", "")
        );
        
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    activeTreasury.vTreasuryProposals.clear();
    return NullUniValue;
}

UniValue extendtreasuryproposal(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "extendtreasuryproposal\n"
            "\nExtends the expiration time, so this proposal keeps longer valid.\n"
            "\nArguments:\n"
            "1. ID          (required, hash) The hash (ID) of the proposal to delete.\n"
            "\nResult:\n"
            "\n(string) Returns null, if this proposal has been extended, otherwise it returns an error.\n"
            "\nExamples:\n"
            + HelpExampleCli("extendtreasuryproposal", "")
            + HelpExampleRpc("extendtreasuryproposal", "")
        );
        
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    uint256 hash = uint256S(request.params[0].get_str());
    size_t nIndex = 0;
    int64_t nSystemTime = GetTime();
    
    if(!activeTreasury.GetProposalvID(hash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");

    int64_t nDifference = (int64_t)activeTreasury.vTreasuryProposals[nIndex].nExpireTime - nSystemTime;
    
    if(nDifference >= (60 * 60 * 24 * 7))
        throw JSONRPCError(RPC_MISC_ERROR, "Proposal is not about to expire, so you cannot extend it!");
    
    activeTreasury.vTreasuryProposals[nIndex].nExpireTime = nSystemTime + (60 * 60 * 24 * 21); // Extend it for 3 weeks / 21 days.
    activeTreasury.vTreasuryProposals[nIndex].nLastEdited = nSystemTime; // Modify last edited timestamp.
    return NullUniValue;
}

UniValue deletetreasuryproposal(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "deletetreasuryproposal\n"
            "\nRemoves a Treasury Redeem Script by ID. The ID can be found with gettreasuryscriptinfo.\n"
            "\nArguments:\n"
            "1. ID          (required, hash) The hash (ID) of the proposal to delete.\n"
            "\nResult:\n"
            "\n(string) Returns null, if this proposal has been deleted, otherwise it returns an error.\n"
            "\nExamples:\n"
            + HelpExampleCli("deletetreasuryproposal", "")
            + HelpExampleRpc("deletetreasuryproposal", "")
        );
        
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    uint256 hash = uint256S(request.params[0].get_str());
    size_t nIndex = 0;
    uint32_t nSystemTime = GetTime();
    
    if(!activeTreasury.GetProposalvID(hash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");

    activeTreasury.vTreasuryProposals[nIndex].nExpireTime = nSystemTime - 1; // mark as expired.
    activeTreasury.DeleteExpiredProposals(nSystemTime);
    return NullUniValue;
}

UniValue removetreasuryscript(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "removetreasuryscript\n"
            "\nRemoves a Treasury Redeem Script by ID. The ID can be found with gettreasuryscriptinfo.\n"
            "\nArguments:\n"
            "1. ID          (required, integer) The ID of the script, that should be removed.\n"
            "\nResult:\n"
            "\n(string) If successful: A string with the message, that it was successfully added and what the Script ID is.\n"
            "\nExamples:\n"
            + HelpExampleCli("removetreasuryscript", "")
            + HelpExampleRpc("removetreasuryscript", "")
        );
        
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    int nIndex = request.params[0].get_int();
    
    if (nIndex < 0 || nIndex >= activeTreasury.vRedeemScripts.size())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ID not found. (Out of range)");

    if(activeTreasury.RemoveScriptByID(nIndex))
        return std::string("Removed Redeemscript successfully!");
    else
        throw JSONRPCError(RPC_MISC_ERROR, "Could not delete Treasury Redeem Script.");
}

UniValue addtreasuryscript(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "addtreasuryscript\n"
            "\nReturns details of the treasury saved script, given by the ID. The ID can be found with gettreasuryscriptinfo.\n"
            "\nArguments:\n"
            "1. \"hexscript\"       (required, string) The hex encoded treasury redeem script, that you want to add.\n"
            "\nResult:\n"
            "\n(string) If successful: A string with the message, that it was successfully added and what the Script ID is.\n"
            "\nExamples:\n"
            + HelpExampleCli("addtreasuryscript", "")
            + HelpExampleRpc("addtreasuryscript", "")
        );
        
    LOCK(cs_treasury);
    RPCTypeCheck(request.params, {UniValue::VSTR});
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    CScript script;
    std::stringstream strStream;
    size_t nIndex = 0;
    if (request.params[0].get_str().size() > 1)
    {
        std::vector<unsigned char> scriptData(ParseHexV(request.params[0], "argument"));
        script = CScript(scriptData.begin(), scriptData.end());
    } 
    else 
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Empty scripts cannot be added!");
    }
    
    if(!script.HasValidOps())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Redeem script includes unknown OP Codes!");
    
    if(script.IsUnspendable())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "The treasury script is unspendable!");
    
    if(activeTreasury.SearchScriptByScript(script, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury redeemscript already exists in treasury mempool!");
    
    // Now all checks are done, and we can add this script.
    activeTreasury.vRedeemScripts.push_back(script);
    activeTreasury.SearchScriptByScript(script, nIndex);
    
    strStream << "The treasury script has been added successfully with ID: " << nIndex;
    return strStream.str();
}

UniValue gettreasuryscriptbyid(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1 && request.params.size() != 2)
        throw std::runtime_error(
            "gettreasuryscriptbyid\n"
            "\nReturns details of the treasury saved script, given by the ID. The ID can be found with gettreasuryscriptinfo.\n"
            "\nArguments:\n"
            "1. \"id\"             (required, int) The ID of the treasury script, that you want to see.\n"
            "2. \"decodescript\"   (optional, int, default=0) How to decode the treasury script (0 = describe the treasury script, 1 = show hex and describe the script)\n"
            "\nResult:\n"
            "{\n"
            "   (object) The object of the treasury script\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("gettreasuryscriptbyid", "")
            + HelpExampleRpc("gettreasuryscriptbyid", "")
        );
        
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    int nIndex = request.params[0].get_int();
    
    if (nIndex < 0 || nIndex >= activeTreasury.vRedeemScripts.size())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ID not found. (Out of range)");
    
    int nSettings = (!request.params[1].isNull()) ? request.params[1].get_int() : 0;
    
    if(nSettings < 0 || nSettings > 1)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid decodescript param value.");

    UniValue ret(UniValue::VOBJ);
    ScriptPubKeyToUniv(activeTreasury.vRedeemScripts[nIndex], ret, nSettings);
    UniValue type;
    type = find_value(ret, "type");

    if (type.isStr() && type.get_str() != "scripthash") {
        // P2SH cannot be wrapped in a P2SH. If this script is already a P2SH,
        // don't return the address for a P2SH of the P2SH.
        ret.pushKV("p2sh", EncodeDestination(CScriptID(activeTreasury.vRedeemScripts[nIndex])));
    }
    return ret;
}

UniValue gettreasuryscriptinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0 && request.params.size() != 1)
        throw std::runtime_error(
            "gettreasuryscriptinfo\n"
            "\nReturns details of the treasury saved scripts.\n"
            "\nArguments:\n"
            "1. \"decodescript\"   (optional, int, default=0) How to decode the treasury scripts (0 = describe the treasury script, 1 = show hex and describe the script)\n"
            "\nResult:\n"
            "{\n"
            "  \"count\": xxxxx,              (numeric) Current treasury scripts\n"
            "  \"scripts\": xxxxx,            (array) Array of all saved treasury scripts.\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("gettreasuryscriptinfo", "")
            + HelpExampleRpc("gettreasuryscriptinfo", "")
        );
        
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    int nSettings = (!request.params[0].isNull()) ? request.params[0].get_int() : 0;
    
    if(nSettings < 0 || nSettings > 1)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid decodescript param value.");

    UniValue ret(UniValue::VOBJ), scripts(UniValue::VARR);
    ret.pushKV("count", (int64_t) activeTreasury.vRedeemScripts.size());
    
    for(size_t i = 0; i < activeTreasury.vRedeemScripts.size(); i++)
    {
        UniValue script(UniValue::VOBJ);
        script.pushKV("id", (int)i);
        ScriptPubKeyToUniv(activeTreasury.vRedeemScripts[i], script, nSettings);
        UniValue type;
        type = find_value(script, "type");

        if (type.isStr() && type.get_str() != "scripthash") {
            // P2SH cannot be wrapped in a P2SH. If this script is already a P2SH,
            // don't return the address for a P2SH of the P2SH.
            script.pushKV("p2sh", EncodeDestination(CScriptID(activeTreasury.vRedeemScripts[i])));
        }
        scripts.push_back(script);
    }
    ret.pushKV("scripts", scripts);
    return ret;
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
      
    LOCK(cs_treasury);
      
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
        for(size_t i = 0; i < activeTreasury.vTreasuryProposals.size(); i++)
        {
            proposals.push_back(proposaltoJSON(&activeTreasury.vTreasuryProposals[i], 0));
        }
    }
    else if(nSettings == 2)
    {
        for(size_t i = 0; i < activeTreasury.vTreasuryProposals.size(); i++)
        {
            proposals.push_back(proposaltoJSON(&activeTreasury.vTreasuryProposals[i], 1));
        }
    }
    else
    {
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
     
    LOCK(cs_treasury);
     
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
    
    LOCK(cs_treasury);
    
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
    
    LOCK(cs_treasury);
    
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
    
    LOCK(cs_treasury);
    
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
        strStream << "Headline exceeds max length with " << proposal.strHeadline.length() << " chars!";
        throw JSONRPCError(RPC_INVALID_PARAMETER, strStream.str());
    }
    
    if(!proposal.IsDescriptionValid())
    {
        strStream << "Description exceeds max length with " << proposal.strDescription.length() << " chars!";
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
    
    LOCK(cs_treasury);
    
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
    
    LOCK(cs_treasury);
    
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
    
    LOCK(cs_treasury);
    
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
    
    LOCK(cs_treasury);
    
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    activeTreasury.SetNull();

    return NullUniValue;
}

static const CRPCCommand commands[] =
{ //  category              name                            actor (function)               argNames
  //  --------------------- ------------------------------  -----------------------------  ----------
    /** All treasury mempool functions */
    { "treasury",           "createtreasurymempool",        &createtreasurymempool,        {"directory","filename"}   },
    { "treasury",           "opentreasurymempool",          &opentreasurymempool,          {"directory","filename"}   },
    { "treasury",           "savetreasurymempooltonewfile", &savetreasurymempooltonewfile, {"directory","filename"}   },
    { "treasury",           "savetreasurymempool",          &savetreasurymempool,          {} },
    { "treasury",           "gettreasurymempoolinfo",       &gettreasurymempoolinfo,       {} },
    { "treasury",           "closetreasurymempool",         &closetreasurymempool,         {} },
    { "treasury",           "aborttreasurymempool",         &aborttreasurymempool,         {} },
    
    /** All treasury script functions */
    { "treasury",           "addtreasuryscript",            &addtreasuryscript,            {"hexscript"} },
    { "treasury",           "removetreasuryscript",         &removetreasuryscript,         {"id"} },
    { "treasury",           "cleartreasuryscripts",         &cleartreasuryscripts,         {} },
    { "treasury",           "gettreasuryscriptinfo",        &gettreasuryscriptinfo,        {"decodescript"} },
    { "treasury",           "gettreasuryscriptbyid",        &gettreasuryscriptbyid,        {"id","decodescript"} },
    
    /** All treasury proposal functions */
    { "treasury",           "gettreasuryproposalinfo",      &gettreasuryproposalinfo,      {"decodeproposal"} },
    { "treasury",           "gettreasuryproposal",          &gettreasuryproposal,          {"id", "txdecode"} },
    { "treasury",           "createtreasuryproposal",       &createtreasuryproposal,       {"headline","description"} },
    { "treasury",           "deletetreasuryproposal",       &deletetreasuryproposal,       {"id"} },
    { "treasury",           "extendtreasuryproposal",       &extendtreasuryproposal,       {"id"} },
    { "treasury",           "votetreasuryproposal",         &votetreasuryproposal,         {"id"} },
    { "treasury",           "deltreasuryproposalvote",      &deltreasuryproposalvote,      {"id"} },
    { "treasury",           "cleartreasuryproposals",       &cleartreasuryproposals,       {} },
    
    /** All treasury proposal transaction functions */
    { "treasury",           "updateproposaltxfromhex",      &updateproposaltxfromhex,      {"id","hextx"} },
    { "treasury",           "getproposaltxashex",           &getproposaltxashex,           {"id"} },
    { "treasury",           "broadcastallsignedproposals",  &broadcastallsignedproposals,  {"allowhighfees"} },
    { "treasury",           "broadcastsignedproposal",      &broadcastsignedproposal,      {"id","allowhighfees"} },
};

void RegisterTreasuryRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
