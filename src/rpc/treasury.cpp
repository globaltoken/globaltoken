// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2020 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <core_io.h>
#include <coins.h>
#include <consensus/validation.h>
#include <globaltoken/treasury.h>
#include <globaltoken/hardfork.h>
#include <keystore.h>
#include <protocol.h>
#include <serialize.h>
#include <init.h>
#include <net.h>
#include <net_processing.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <validation.h>
#include <validationinterface.h>
#include <rpc/safemode.h>
#include <rpc/server.h>
#include <rpc/treasury.h>
#include <rpc/rawtransaction.h>
#include <utilstrencodings.h>
#include <utiltime.h>
#include <random.h>
#include <sync.h>
#include <txmempool.h>
#include <script/script.h>
#include <script/standard.h>

#include <algorithm>
#include <stdint.h>
#include <sstream>

#include <univalue.h>

#include <mutex>
#include <future>
#include <condition_variable>

bool IsTreasuryChangeAddrValid(const CScript& scriptTreasuryChange, CTxDestination &txDestination)
{
    AssertLockHeld(cs_treasury);
    
    if(scriptTreasuryChange == CScript())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No treasury changeaddress configured.");
    
    txnouttype type;
    std::vector<std::vector<unsigned char> > vSolutionsRet;

    if (!Solver(scriptTreasuryChange, type, vSolutionsRet))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Could not verify Treasury Change Script!");
    
    if(!ExtractDestination(scriptTreasuryChange, txDestination))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Could not decode Treasury Change address!");
    
    return (type == TX_SCRIPTHASH);
}

UniValue treasurymempoolInfoToJSON()
{
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("proposals", (int64_t) activeTreasury.vTreasuryProposals.size());
    ret.pushKV("scripts", (int64_t) activeTreasury.vRedeemScripts.size());
    ret.pushKV("bytes", (int64_t) ::GetSerializeSize(activeTreasury, SER_NETWORK, PROTOCOL_VERSION));
    ret.pushKV("version", (int64_t) activeTreasury.GetVersion());
    ret.pushKV("lastsaved", (int64_t) activeTreasury.GetLastSaved());
    ret.pushKV("filepath", activeTreasury.GetTreasuryFilePath().string());
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

UniValue GetProposalTxInfo(const CTreasuryProposal* pProposal)
{
    AssertLockHeld(cs_treasury);
    UniValue ret(UniValue::VOBJ);
    bool fCheckSignature = true, fCompletelySigned = true;
    
    const CMutableTransaction* pMtx = &pProposal->mtx;
    const CTransaction txConst(*pMtx);
    size_t nLoopInternal = 0;
    
    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0)
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Globaltoken is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Globaltoken is downloading blocks...");
    
    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK2(cs_main, mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        for (const CTxIn& txin : pMtx->vin) {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }
    
    CAmount amountInputs = view.GetValueIn(txConst), amountOutputs = txConst.GetValueOut();
    
    for (const CTxIn& txin : pMtx->vin) {
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Input not found or already spent for input: " + txin.prevout.ToString());
        }
        
        if(fCheckSignature)
        {
            ScriptError serror = SCRIPT_ERR_OK;
            if (!VerifyScript(txin.scriptSig, coin.out.scriptPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, nLoopInternal, coin.out.nValue), &serror)) 
            {
                // Cancel fCheckSignature, because this transaction is already unsigned.
                fCheckSignature = false;
                fCompletelySigned = false;
            }
        }
        nLoopInternal++;
            
    }
    
    ret.pushKV("inputs", (int)pMtx->vin.size());
    ret.pushKV("inputamount", ValueFromAmount(amountInputs));
    ret.pushKV("outputs", (int)pMtx->vout.size());
    ret.pushKV("outputamount", ValueFromAmount(amountOutputs));
    ret.pushKV("signed", fCompletelySigned);
    if(amountInputs >= amountOutputs)
        ret.pushKV("fee", ValueFromAmount(amountInputs - amountOutputs));
    
    return ret;
}

bool BroadcastSignedTreasuryProposalTransaction(CTreasuryProposal* pProposal, UniValue& result, const CAmount& nMaxRawTxFee)
{    
    AssertLockHeld(cs_treasury);
    
    ObserveSafeMode();

    std::promise<void> promise;
    UniValue ret(UniValue::VOBJ);
    CMutableTransaction mtx = pProposal->mtx;
    CTransactionRef tx(MakeTransactionRef(std::move(mtx)));
    const uint256& hashTx = tx->GetHash();
    bool fSent = false;

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
                ret.pushKV("txid", hashTx.GetHex());
                ret.pushKV("sent", fSent);
                ret.pushKV("error", JSONRPCError(RPC_TRANSACTION_REJECTED, FormatStateMessage(state)));
                result.pushKVs(ret);
                return fSent;
            } else {
                if (fMissingInputs) {
                    ret.pushKV("txid", hashTx.GetHex());
                    ret.pushKV("sent", fSent);
                    ret.pushKV("error", JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs"));
                    result.pushKVs(ret);
                    return fSent;
                }
                ret.pushKV("txid", hashTx.GetHex());
                ret.pushKV("sent", fSent);
                ret.pushKV("error", JSONRPCError(RPC_TRANSACTION_ERROR, FormatStateMessage(state)));
                result.pushKVs(ret);
                return fSent;
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
        ret.pushKV("txid", hashTx.GetHex());
        ret.pushKV("sent", fSent);
        ret.pushKV("error", JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain"));
        result.pushKVs(ret);
        return fSent;
    } else {
        // Make sure we don't block forever if re-sending
        // a transaction already in mempool.
        promise.set_value();
    }

    } // cs_main

    promise.get_future().wait();

    fSent = true;

    RelayTransactionFromExtern(*tx, g_connman.get());
    pProposal->nExpireTime = GetTime() + (60 * 30); // This proposal has been successful completed, let it expire now in 30 minutes, so last checks can be done and then it will be deleted.
    
    ret.pushKV("txid", hashTx.GetHex());
    ret.pushKV("sent", fSent);
    result.pushKVs(ret);
    return fSent;
}

UniValue broadcastallsignedproposals(const JSONRPCRequest& request)
{
    if (request.fHelp || (request.params.size() != 0 && request.params.size() != 1))
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
    
    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0)
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Globaltoken is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Globaltoken is downloading blocks...");

    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    if(activeTreasury.vTreasuryProposals.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No treasury proposals in mempool.");

    CAmount nMaxRawTxFee = maxTxFee;
    if (!request.params[0].isNull() && request.params[0].get_bool())
        nMaxRawTxFee = 0;
    
    std::vector<CTreasuryProposal*> vPps;

    { // cs_main scope
    LOCK(cs_main);
    CCoinsViewCache &view = *pcoinsTip;
    
    for(size_t i = 0; i < activeTreasury.vTreasuryProposals.size(); i++)
    {
        const CTransaction txConst(activeTreasury.vTreasuryProposals[i].mtx);
        bool fFailed = true;
        for (unsigned int input = 0; input < activeTreasury.vTreasuryProposals[i].mtx.vin.size(); input++) 
        {
            const CTxIn& txin = activeTreasury.vTreasuryProposals[i].mtx.vin[input];
            const Coin& coin = view.AccessCoin(txin.prevout);
            if (coin.IsSpent())
                break;
            
            const CScript& prevPubKey = coin.out.scriptPubKey;
            const CAmount& amount = coin.out.nValue;

            // The Script should return no error, that means it's complete.
            ScriptError serror = SCRIPT_ERR_OK;
            if (!VerifyScript(txin.scriptSig, prevPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, input, amount), &serror)) 
                break;
            
            fFailed = false;
        }
        
        if(!fFailed)
            vPps.push_back(&activeTreasury.vTreasuryProposals[i]);
    }
    } // cs_main
    
    if(vPps.size() == 0)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No signed transactions found!");
    
    for(size_t i = 0; i < vPps.size(); i++)
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("proposal", vPps[i]->hashID.GetHex());
        BroadcastSignedTreasuryProposalTransaction(vPps[i], obj, nMaxRawTxFee);
        ret.push_back(obj);
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
    UniValue obj(UniValue::VOBJ);
    
    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0)
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Globaltoken is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Globaltoken is downloading blocks...");

    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    uint256 proposalHash = uint256S(request.params[0].get_str());
    size_t nIndex = 0;
    bool fSigned = false;
    
    CAmount nMaxRawTxFee = maxTxFee;
    if (!request.params[1].isNull() && request.params[1].get_bool())
        nMaxRawTxFee = 0;
    
    if(!activeTreasury.GetProposalvID(proposalHash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");
    
    CTreasuryProposal* pProposal = &activeTreasury.vTreasuryProposals[nIndex];
    
    { // cs_main scope
    LOCK(cs_main);
    CCoinsViewCache &view = *pcoinsTip;
    const CTransaction txConst(pProposal->mtx);
    for (unsigned int input = 0; input < pProposal->mtx.vin.size(); input++) 
    {
        const CTxIn& txin = pProposal->mtx.vin[input];
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent())
            break;
        
        const CScript& prevPubKey = coin.out.scriptPubKey;
        const CAmount& amount = coin.out.nValue;

        // The Script should return no error, that means it's complete.
        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(txin.scriptSig, prevPubKey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, input, amount), &serror)) 
            break;
        
        fSigned = true;
    }
    } // cs_main
    
    if(fSigned)
        BroadcastSignedTreasuryProposalTransaction(pProposal, obj, nMaxRawTxFee);
    else
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Treasury proposal transaction not signed yet!");

    return obj;
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
    
    activeTreasury.vTreasuryProposals[nIndex].UpdateTimeData(GetTime());
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
    
    activeTreasury.vTreasuryProposals[nIndex].UpdateTimeData(GetTime());

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
    
    activeTreasury.vTreasuryProposals[nIndex].UpdateTimeData(GetTime());

    return NullUniValue;
}

UniValue gettreasuryproposal(const JSONRPCRequest& request)
{
    if (request.fHelp || (request.params.size() != 1 && request.params.size() != 2))
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
            "  \"tx\": {\n,                  (object) The decoded transaction to json.\n"
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
    
    activeTreasury.vTreasuryProposals[nIndex].UpdateTimeData(nSystemTime);
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

UniValue deltreasurychangeaddr(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "deltreasurychangeaddr\n"
            "\nDeletes the current treasury change address from mempool\n"
            "\nResult:\n"
            "\n(null) If successful: Null otherwise it displays an error.\n"
            "\nExamples:\n"
            + HelpExampleCli("deltreasurychangeaddr", "")
            + HelpExampleRpc("deltreasurychangeaddr", "")
        );
        
    LOCK(cs_treasury);
    RPCTypeCheck(request.params, {UniValue::VSTR});
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    if(activeTreasury.scriptChangeAddress == CScript())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "There is no treasury change address saved in mempool currently.");
       
    activeTreasury.scriptChangeAddress.clear();
    return NullUniValue;
}

UniValue gettreasurychangeaddr(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "gettreasurychangeaddr\n"
            "\nReturns details of the current treasury proposal change address.\n"
            "\nResult:\n"
            "{\n"
            "  \"address\" : \"address\",        (string) The treasury change address validated\n"
            "  \"scriptPubKey\" : \"hex\",       (string) The hex encoded scriptPubKey generated by the treasury change address\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("gettreasurychangeaddr", "")
            + HelpExampleRpc("gettreasurychangeaddr", "")
        );
        
    LOCK(cs_treasury);
    RPCTypeCheck(request.params, {UniValue::VSTR});
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    if(activeTreasury.scriptChangeAddress == CScript())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No treasury changeaddress configured.");
    
    CTxDestination destination;

    if (!IsTreasuryChangeAddrValid(activeTreasury.scriptChangeAddress, destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Treasury mempool change address is not a script address!");
    }
    
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("address", EncodeDestination(destination));
    UniValue o(UniValue::VOBJ);
    ScriptPubKeyToUniv(activeTreasury.scriptChangeAddress, o, true);
    obj.pushKV("scriptPubKey", o);
    return obj;
}

UniValue settreasurychangeaddr(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "settreasurychangeaddr\n"
            "\nSets a new treasury change address and saves it into treasury mempool.\n"
            "\nArguments:\n"
            "1. \"address\"       (required, string) The address, that you want to set as treasury proposal transaction change address.\n"
            "\nResult:\n"
            "{\n"
            "  \"address\" : \"address\",        (string) The treasury change address validated\n"
            "  \"scriptPubKey\" : \"hex\",       (string) The hex encoded scriptPubKey generated by the treasury change address\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("settreasurychangeaddr", "\"yx3SsiKBoNoULoTa3TJx5MSnoA6KNBXdwB\"")
            + HelpExampleRpc("settreasurychangeaddr", "\"yx3SsiKBoNoULoTa3TJx5MSnoA6KNBXdwB\"")
        );
        
    LOCK(cs_treasury);
    RPCTypeCheck(request.params, {UniValue::VSTR});
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    if(activeTreasury.scriptChangeAddress != CScript())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "There is already a change address configured, use deltreasurychangeaddr to delete the current change address and then set a new one.");
    
    CTxDestination dest = DecodeDestination(request.params[0].get_str()), destination;
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }
    
    if (IsDestinationStringOldScriptFormat(request.params[0].get_str())) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, GetOldScriptAddressWarning(request.params[0].get_str()));
    }
    
    CScript tempScript = GetScriptForDestination(dest);

    if (!IsTreasuryChangeAddrValid(tempScript, destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Given treasury mempool change address is not a script address!");
    }
    
    activeTreasury.scriptChangeAddress = tempScript;
    
    JSONRPCRequest changeaddressinfo;
    changeaddressinfo.id = request.id;
    changeaddressinfo.params.setArray();
    return gettreasurychangeaddr(changeaddressinfo);
}

UniValue addtreasuryscript(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "addtreasuryscript\n"
            "\nAdds a new treasury redeem script to treasury mempool.\n"
            "\nArguments:\n"
            "1. \"hexscript\"       (required, string) The hex encoded treasury redeem script, that you want to add.\n"
            "\nResult:\n"
            "\n(string) If successful: A string with the message, that it was successfully added and what the Script ID is.\n"
            "\nExamples:\n"
            + HelpExampleCli("addtreasuryscript", "\"myhexscript\"")
            + HelpExampleRpc("addtreasuryscript", "\"myhexscript\"")
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
    if (request.fHelp || (request.params.size() != 1 && request.params.size() != 2))
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
    if (request.fHelp || (request.params.size() != 0 && request.params.size() != 1))
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
    if (request.fHelp || (request.params.size() != 0 && request.params.size() != 1))
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
            "  \"filepath\": xxxxx            (numeric) The current path to the file of the loaded treasury memory pool\n"
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
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "opentreasurymempool\n"
            "\nReads the treasury mempool from disk.\n"
            "\nArguments:\n"
            "1. \"pathtofile\"   (required, string) The directory, where the treasury mempool is saved into.\n"
            "\nExamples:\n"
            + HelpExampleCli("opentreasurymempool", "\"/usr/share/glttreasury/proposalmempool.dat\"")
            + HelpExampleCli("opentreasurymempool", "\"C:\\Users\\Example\\Desktop\\proposalmempool.dat\"")
            + HelpExampleRpc("opentreasurymempool", "\"C:\\Users\\Example\\Desktop\\proposalmempool.dat\"")
        );
    }
    
    LOCK(cs_treasury);
    
    if (activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "You have already a cached treasury mempool. Close, Abort or save it in order to open a new one.");
    
    CTreasuryMempool cachedTreasury(request.params[0].get_str());

    std::string error;
    if (!LoadTreasuryMempool(cachedTreasury, error)) {
        throw JSONRPCError(RPC_MISC_ERROR, std::string("Unable to load treasury mempool from disk. Reason: ") + error);
    }
    
    activeTreasury = cachedTreasury;

    return NullUniValue;
}

UniValue createtreasurymempool(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "createtreasurymempool\n"
            "\nCreates the treasury mempool file on disk.\n"
            "\nArguments:\n"
            "1. \"pathtofile\"   (required, string) The directory, where the treasury mempool will be saved into.\n"
            "\nExamples:\n"
            + HelpExampleCli("createtreasurymempool", "\"/usr/share/glttreasury/proposalmempool.dat\"")
            + HelpExampleCli("createtreasurymempool", "\"C:\\Users\\Example\\Desktop\\proposalmempool.dat\"")
            + HelpExampleRpc("createtreasurymempool", "\"C:\\Users\\Example\\Desktop\\proposalmempool.dat\"")
        );
    }
    
    LOCK(cs_treasury);
    
    if (activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "You have already a cached treasury mempool. Close, Abort or save it in order to create a new one.");
    
    CTreasuryMempool cachedTreasury(request.params[0].get_str());
    
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

UniValue createproposaltx(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 5)
        throw std::runtime_error(
            "createproposaltx [{\"txid\":\"id\",\"vout\":n},...] {\"address\":amount,...} ( locktime ) ( replaceable )\n"
            "\nCreate a transaction spending the given inputs and creating new outputs.\n"
            "Outputs can be addresses only.\n"
            "Saves the transaction directly to treasury mempool, if succeeded.\n"
            "Note that the transaction's inputs are not signed, and\n"
            "it is not transmitted to the network.\n"

            "\nArguments:\n"
            "1. \"id\"                    (hash, required) The proposal ID you want to add this tx to.\n"
            "2. \"inputs\"                (array, required) A json array of json objects\n"
            "     [\n"
            "       {\n"
            "         \"txid\":\"id\",    (string, required) The transaction id\n"
            "         \"vout\":n,         (numeric, required) The output number\n"
            "         \"sequence\":n      (numeric, optional) The sequence number\n"
            "       } \n"
            "       ,...\n"
            "     ]\n"
            "3. \"outputs\"               (object, required) a json object with outputs\n"
            "    {\n"
            "      \"address\": x.xxx,    (numeric or string, required) The key is the globaltoken address, the numeric value (can be string) is the " + CURRENCY_UNIT + " amount\n"
            "      ,...\n"
            "    }\n"
            "4. locktime                  (numeric, optional, default=0) Raw locktime. Non-0 value also locktime-activates inputs\n"
            "5. replaceable               (boolean, optional, default=false) Marks this transaction as BIP125 replaceable.\n"
            "                             Allows this transaction to be replaced by a transaction with higher fees. If provided, it is an error if explicit sequence numbers are incompatible.\n"
            "\nResult:\n"
            "\"null\"                     (null) If succeeded, it returns null, if there is an error, you get the error message.\n"

            "\nExamples:\n"
            + HelpExampleCli("createproposaltx", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"{\\\"address\\\":0.01}\"")
            + HelpExampleRpc("createproposaltx", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"{\\\"address\\\":0.01}\"")
        );

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VARR, UniValue::VOBJ, UniValue::VNUM, UniValue::VBOOL}, true);
    if (request.params[0].isNull() || request.params[1].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments 1 and 2 must be non-null");
    
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    uint256 proposalHash = uint256S(request.params[0].get_str());
    size_t nIndex = 0;
    
    if(!activeTreasury.GetProposalvID(proposalHash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");

    UniValue inputs = request.params[1].get_array();
    UniValue sendTo = request.params[2].get_obj();

    CMutableTransaction rawTx;

    if (!request.params[3].isNull()) {
        int64_t nLockTime = request.params[3].get_int64();
        if (nLockTime < 0 || nLockTime > std::numeric_limits<uint32_t>::max())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, locktime out of range");
        rawTx.nLockTime = nLockTime;
    }

    bool rbfOptIn = request.params[4].isTrue();

    for (unsigned int idx = 0; idx < inputs.size(); idx++) {
        const UniValue& input = inputs[idx];
        const UniValue& o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");

        const UniValue& vout_v = find_value(o, "vout");
        if (!vout_v.isNum())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        uint32_t nSequence;
        if (rbfOptIn) {
            nSequence = MAX_BIP125_RBF_SEQUENCE;
        } else if (rawTx.nLockTime) {
            nSequence = std::numeric_limits<uint32_t>::max() - 1;
        } else {
            nSequence = std::numeric_limits<uint32_t>::max();
        }

        // set the sequence number if passed in the parameters object
        const UniValue& sequenceObj = find_value(o, "sequence");
        if (sequenceObj.isNum()) {
            int64_t seqNr64 = sequenceObj.get_int64();
            if (seqNr64 < 0 || seqNr64 > std::numeric_limits<uint32_t>::max()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, sequence number is out of range");
            } else {
                nSequence = (uint32_t)seqNr64;
            }
        }

        CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);

        rawTx.vin.push_back(in);
    }

    std::set<CTxDestination> destinations;
    std::vector<std::string> addrList = sendTo.getKeys();
    for (const std::string& name_ : addrList) {
        CTxDestination destination = DecodeDestination(name_);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Globaltoken address: ") + name_);
        }
        
        if (IsDestinationStringOldScriptFormat(name_)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, GetOldScriptAddressWarning(name_));
        }

        if (!destinations.insert(destination).second) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + name_);
        }

        CScript scriptPubKey = GetScriptForDestination(destination);
        CAmount nAmount = AmountFromValue(sendTo[name_]);

        CTxOut out(nAmount, scriptPubKey);
        rawTx.vout.push_back(out);
    }

    if (!request.params[4].isNull() && rbfOptIn != SignalsOptInRBF(rawTx)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter combination: Sequence number(s) contradict replaceable option");
    }
    
    if(activeTreasury.vTreasuryProposals[nIndex].mtx == rawTx)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Transaction is already up to date!");
    else
        activeTreasury.vTreasuryProposals[nIndex].mtx = rawTx;
    
    activeTreasury.vTreasuryProposals[nIndex].UpdateTimeData(GetTime());

    return NullUniValue;
}

UniValue moveunusableproposaltxinputs(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "handleproposaltxinputs\n"
            "\nRemoves invalid transaction inputs, removes overflowed (1 MB tx size) inputs and funds the other proposal tx transaction with the overflowed inputs until it reachs 1 MB\nand adds them as change money and clears the scriptSig to sign the transaction.\n"

            "\nArguments:\n"
            "1. \"fromid\"                    (hash, required) The proposal ID you want to move proposal tx inputs from.\n"
            "2. \"toid\"                      (hash, required) The proposal ID you want to move proposal tx inputs to.\n"

            "\nResult:\n\n"
            "(array) Returns the transaction details from the both changed proposal transactions.\n\n"
            "[{\n"
            "  \"id\": xxxxx,              (string) The ID of the proposal\n"
            "  \"inputs\": xxxxx,          (numeric) Current transaction inputs of this proposal\n"
            "  \"inputamount\": xxxxx,     (numeric) Total transaction input amount in " + CURRENCY_UNIT + "\n"
            "  \"outputs\": xxxxx,         (numeric) Current transaction outputs of this proposal\n"
            "  \"outputamount\": xxxxx,    (numeric) Total transaction output amount in " + CURRENCY_UNIT + "\n"
            "  \"signed\": xxxxx,          (bool) Outputs true if this transaction is fully signed and ready for sending, otherwise false.\n"
            "  \"fee\": xxxxx              (numeric) The fee of this transaction, can be missing, if this transaction is not final.\n"
            "}, \n{\n....\n}\n]\n"

            "\nExamples:\n"
            + HelpExampleCli("moveunusableproposaltxinputs", "\"fromid\" \"toid\"")
            + HelpExampleRpc("moveunusableproposaltxinputs", "\"fromid\",\"toid\"")
        );
    
    LOCK(cs_treasury);
    
    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0)
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Globaltoken is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Globaltoken is downloading blocks...");
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    if(activeTreasury.vTreasuryProposals.empty())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No treasury proposals found.");
    
    if(activeTreasury.scriptChangeAddress == CScript())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No treasury change address set.");
    
    uint256 fromProposal = uint256S(request.params[0].get_str()), toProposal = uint256S(request.params[1].get_str());
    size_t nFromProposal = 0, nToProposal = 0;
    
    if(!activeTreasury.GetProposalvID(fromProposal, nFromProposal))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury (fromid) proposal not found.");
    
    if(!activeTreasury.GetProposalvID(toProposal, nToProposal))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury (toid) proposal not found.");
    
    if(fromProposal == toProposal)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Treasury proposals must be different!");
    
    std::vector<CTxIn> vTxIn;
    UniValue ret(UniValue::VARR);
    
    if(activeTreasury.vTreasuryProposals[nFromProposal].mtx.vin.size() < CTreasuryProposal::MAX_TX_INPUTS)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Treasury proposal (from) Transaction is not a overflowed transaction!");
    
    if(activeTreasury.vTreasuryProposals[nToProposal].mtx.vin.size() > CTreasuryProposal::MAX_TX_INPUTS)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Treasury proposal (to) Transaction is already overflowed and cannot be filled with more inputs!");
    
    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK2(cs_main, mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view
        for (const CTxIn& txin : activeTreasury.vTreasuryProposals[nFromProposal].mtx.vin) 
        {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }
        
        for (const CTxIn& txin : activeTreasury.vTreasuryProposals[nToProposal].mtx.vin) 
        {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }
        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }
    
    // Remove unspendable transaction inputs and overflow inputs
    for (size_t input = activeTreasury.vTreasuryProposals[nFromProposal].mtx.vin.size(); input > 0; input--) 
    {
        size_t inputIndex = input - 1;
        if (view.AccessCoin(activeTreasury.vTreasuryProposals[nFromProposal].mtx.vin[inputIndex].prevout).IsSpent())
        {
            activeTreasury.vTreasuryProposals[nFromProposal].mtx.vin.erase(activeTreasury.vTreasuryProposals[nFromProposal].mtx.vin.begin() + inputIndex);
        }
    }
    
    for (size_t input = activeTreasury.vTreasuryProposals[nFromProposal].mtx.vin.size(); input > CTreasuryProposal::MAX_TX_INPUTS; input--) 
    {
        size_t inputIndex = input - 1;
        activeTreasury.vTreasuryProposals[nFromProposal].mtx.vin[inputIndex].scriptSig.clear();
        vTxIn.push_back(activeTreasury.vTreasuryProposals[nFromProposal].mtx.vin[inputIndex]);
        activeTreasury.vTreasuryProposals[nFromProposal].mtx.vin.erase(activeTreasury.vTreasuryProposals[nFromProposal].mtx.vin.begin() + inputIndex);
    }
    
    // Remove double unspent entries.
    std::vector<CTxIn>::iterator itend = vTxIn.end();
	for (std::vector<CTxIn>::iterator it = vTxIn.begin(); it != itend; it++) 
    {
		itend = std::remove(it + 1, itend, *it);
	}
    
    vTxIn.erase(itend, vTxIn.end());
    
    // Remove double inputs
    for (size_t input = 0; input < activeTreasury.vTreasuryProposals[nFromProposal].mtx.vin.size(); input++) 
    {
        for (size_t icheck = activeTreasury.vTreasuryProposals[nToProposal].mtx.vin.size(); icheck > 0; icheck--) 
        {
            size_t nTmpIndex = icheck - 1;
            if (activeTreasury.vTreasuryProposals[nFromProposal].mtx.vin[input] == activeTreasury.vTreasuryProposals[nToProposal].mtx.vin[nTmpIndex])
            {
                activeTreasury.vTreasuryProposals[nToProposal].mtx.vin.erase(activeTreasury.vTreasuryProposals[nToProposal].mtx.vin.begin() + nTmpIndex);
            }
        }
    }
    
    // Remove unspendable transaction inputs and overflow inputs from pToMtx
    for (size_t input = activeTreasury.vTreasuryProposals[nToProposal].mtx.vin.size(); input > 0; input--) 
    {
        size_t nTmpIndex = input - 1;
        if (view.AccessCoin(activeTreasury.vTreasuryProposals[nToProposal].mtx.vin[nTmpIndex].prevout).IsSpent())
        {
            activeTreasury.vTreasuryProposals[nToProposal].mtx.vin.erase(activeTreasury.vTreasuryProposals[nToProposal].mtx.vin.begin() + nTmpIndex);
        }
    }
    
    CAmount currentAmount = 0;
    
    for (size_t input = activeTreasury.vTreasuryProposals[nToProposal].mtx.vin.size(); input < CTreasuryProposal::MAX_TX_INPUTS; input++) 
    {
        if(!vTxIn.empty())
        {
            activeTreasury.vTreasuryProposals[nToProposal].mtx.vin.push_back(vTxIn[0]);
            currentAmount += view.AccessCoin(vTxIn[0].prevout).out.nValue;
            vTxIn.erase(vTxIn.begin());
        }
        else
        {
            break;
        }
    }
    
    if(currentAmount > 0)
        activeTreasury.vTreasuryProposals[nToProposal].mtx.vout.push_back(CTxOut(currentAmount, activeTreasury.scriptChangeAddress));
    
    // Now we return the edited vTreasuryProposals
    
    activeTreasury.vTreasuryProposals[nFromProposal].UpdateTimeData(GetTime());
    activeTreasury.vTreasuryProposals[nToProposal].UpdateTimeData(GetTime());
    
    UniValue from(UniValue::VOBJ), to(UniValue::VOBJ);
    from.pushKV("id", activeTreasury.vTreasuryProposals[nFromProposal].hashID.GetHex());
    from.pushKVs(GetProposalTxInfo(&activeTreasury.vTreasuryProposals[nFromProposal]));
    ret.push_back(from);
    
    to.pushKV("id", activeTreasury.vTreasuryProposals[nToProposal].hashID.GetHex());
    to.pushKVs(GetProposalTxInfo(&activeTreasury.vTreasuryProposals[nToProposal]));
    ret.push_back(to);

    return ret;
}

UniValue handleproposaltxinputs(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "handleproposaltxinputs\n"
            "\nRemoves invalid transaction inputs, removes overflowed (1 MB tx size) inputs and funds other proposal tx transactions with the overflowed inputs until they reach 1 MB\nand adds them as change money and clears the scriptSig to sign the transaction.\n"

            "\nResult:\n\n"
            "(array) Returns the transaction details from all changed proposal transactions.\n\n"
            "[{\n"
            "  \"id\": xxxxx,              (string) The ID of the proposal\n"
            "  \"inputs\": xxxxx,          (numeric) Current transaction inputs of this proposal\n"
            "  \"inputamount\": xxxxx,     (numeric) Total transaction input amount in " + CURRENCY_UNIT + "\n"
            "  \"outputs\": xxxxx,         (numeric) Current transaction outputs of this proposal\n"
            "  \"outputamount\": xxxxx,    (numeric) Total transaction output amount in " + CURRENCY_UNIT + "\n"
            "  \"signed\": xxxxx,          (bool) Outputs true if this transaction is fully signed and ready for sending, otherwise false.\n"
            "  \"fee\": xxxxx              (numeric) The fee of this transaction, can be missing, if this transaction is not final.\n"
            "}, \n{\n....\n}\n]\n"

            "\nExamples:\n"
            + HelpExampleCli("handleproposaltxinputs", "")
            + HelpExampleRpc("handleproposaltxinputs", "")
        );
    
    LOCK(cs_treasury);
    
    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0)
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Globaltoken is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Globaltoken is downloading blocks...");
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    if(activeTreasury.vTreasuryProposals.empty())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No treasury proposals found.");
    
    if(activeTreasury.scriptChangeAddress == CScript())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No treasury change address set.");
    
    std::vector<CTxIn> vTxIn;
    UniValue ret(UniValue::VARR);
    
    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK2(cs_main, mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view
        for(const CTreasuryProposal& proposal : activeTreasury.vTreasuryProposals)
        {
            for (const CTxIn& txin : proposal.mtx.vin) 
            {
                view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
            }
        }
        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }
    
    // Remove unspendable transaction inputs and overflow inputs
    for (unsigned int i = 0; i < activeTreasury.vTreasuryProposals.size(); i++) 
    {
        activeTreasury.vTreasuryProposals[i].UpdateTimeData(GetTime());
        for (size_t input = activeTreasury.vTreasuryProposals[i].mtx.vin.size(); input > 0; input--) 
        {
            size_t nTmpIndex = input - 1;
            if (view.AccessCoin(activeTreasury.vTreasuryProposals[i].mtx.vin[nTmpIndex].prevout).IsSpent())
            {
                activeTreasury.vTreasuryProposals[i].mtx.vin.erase(activeTreasury.vTreasuryProposals[i].mtx.vin.begin() + nTmpIndex);
            }
        }
        
        for (size_t input = activeTreasury.vTreasuryProposals[i].mtx.vin.size(); input > CTreasuryProposal::MAX_TX_INPUTS; input--) 
        {
            size_t nTmpIndex = input - 1;
            activeTreasury.vTreasuryProposals[i].mtx.vin[nTmpIndex].scriptSig.clear();
            vTxIn.push_back(activeTreasury.vTreasuryProposals[i].mtx.vin[nTmpIndex]);
            activeTreasury.vTreasuryProposals[i].mtx.vin.erase(activeTreasury.vTreasuryProposals[i].mtx.vin.begin() + nTmpIndex);
        }
    }
    
    // Remove double unspent entries.
    std::vector<CTxIn>::iterator itend = vTxIn.end();
	for (std::vector<CTxIn>::iterator it = vTxIn.begin(); it != itend; it++) 
    {
		itend = std::remove(it + 1, itend, *it);
	}
    
    vTxIn.erase(itend, vTxIn.end());
    
    // Remove double inputs
    for (unsigned int i = 0; i < activeTreasury.vTreasuryProposals.size(); i++) 
    {
        for (unsigned int p = 0; p < activeTreasury.vTreasuryProposals.size(); p++) 
        {
            if(activeTreasury.vTreasuryProposals[i] == activeTreasury.vTreasuryProposals[p])
                continue;
            
            for (int input = 0; input < activeTreasury.vTreasuryProposals[i].mtx.vin.size(); input++) 
            {
                for (size_t icheck = activeTreasury.vTreasuryProposals[p].mtx.vin.size(); icheck > 0; icheck--) 
                {
                    size_t nTmpIndex = icheck - 1;
                    if (activeTreasury.vTreasuryProposals[i].mtx.vin[input] == activeTreasury.vTreasuryProposals[p].mtx.vin[nTmpIndex])
                    {
                        activeTreasury.vTreasuryProposals[p].mtx.vin.erase(activeTreasury.vTreasuryProposals[p].mtx.vin.begin() + nTmpIndex);
                    }
                }
            }
        }
    }
    
    // Add unused inputs to existing proposal transactions and spent them as change money.
    for (unsigned int i = 0; i < activeTreasury.vTreasuryProposals.size(); i++) 
    {
        CAmount currentAmount = 0;
        
        for (size_t input = activeTreasury.vTreasuryProposals[i].mtx.vin.size(); input < CTreasuryProposal::MAX_TX_INPUTS; input++) 
        {
            if(vTxIn.size() != 0)
            {
                activeTreasury.vTreasuryProposals[i].mtx.vin.push_back(vTxIn[0]);
                currentAmount += view.AccessCoin(vTxIn[0].prevout).out.nValue;
                vTxIn.erase(vTxIn.begin());
            }
            else
            {
                break;
            }
        }
        
        if(currentAmount > 0)
            activeTreasury.vTreasuryProposals[i].mtx.vout.push_back(CTxOut(currentAmount, activeTreasury.scriptChangeAddress));
    }
    
    // Now we return the edited vTreasuryProposals
    for (size_t i = 0; i < activeTreasury.vTreasuryProposals.size(); i++) 
    {
        const CTreasuryProposal* pProposal = &activeTreasury.vTreasuryProposals[i]; 
        UniValue preobj(UniValue::VOBJ);
        preobj.pushKV("id", pProposal->hashID.GetHex());
        preobj.pushKVs(GetProposalTxInfo(pProposal));
        ret.push_back(preobj);
    }

    return ret;
}

UniValue prepareproposaltx(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "prepareproposaltx \"id\"\n"
            "\nRemoves invalid transaction inputs, removes overflowed (1 MB tx size) inputs, clears the scriptSig to sign the transaction again and resets all recipients outputs to zero to configure the proposal tx again.\n"

            "\nArguments:\n"
            "1. \"id\"                     (hash, required) The proposal ID where you want to prepare the proposal tx.\n"
            "\nResult:\n"
            "{\n"
            "  \"inputs\": xxxxx,          (numeric) Current transaction inputs of this proposal\n"
            "  \"inputamount\": xxxxx,     (numeric) Total transaction input amount in " + CURRENCY_UNIT + "\n"
            "  \"outputs\": xxxxx,         (numeric) Current transaction outputs of this proposal\n"
            "  \"outputamount\": xxxxx,    (numeric) Total transaction output amount in " + CURRENCY_UNIT + "\n"
            "  \"signed\": xxxxx,          (bool) Outputs true if this transaction is fully signed and ready for sending, otherwise false.\n"
            "  \"fee\": xxxxx              (numeric) The fee of this transaction, can be missing, if this transaction is not final.\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("prepareproposaltx", "\"id\"")
            + HelpExampleRpc("prepareproposaltx", "\"id\"")
        );
    
    LOCK(cs_treasury);
    
    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0)
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Globaltoken is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Globaltoken is downloading blocks...");
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    if(activeTreasury.scriptChangeAddress == CScript())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No treasury change address set.");
    
    uint256 proposalHash = uint256S(request.params[0].get_str());
    size_t nIndex = 0;
    
    if(!activeTreasury.GetProposalvID(proposalHash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");
    
    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        LOCK2(cs_main, mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        for (const CTxIn& txin : activeTreasury.vTreasuryProposals[nIndex].mtx.vin) {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }
    
    for (size_t input = activeTreasury.vTreasuryProposals[nIndex].mtx.vin.size(); input > 0; input--) 
    {
        size_t nTmpIndex = input - 1;
        if (view.AccessCoin(activeTreasury.vTreasuryProposals[nIndex].mtx.vin[nTmpIndex].prevout).IsSpent())
        {
            activeTreasury.vTreasuryProposals[nIndex].mtx.vin.erase(activeTreasury.vTreasuryProposals[nIndex].mtx.vin.begin() + nTmpIndex);
        }
    }
    
    activeTreasury.vTreasuryProposals[nIndex].RemoveOverflowedProposalTxInputs();
    activeTreasury.vTreasuryProposals[nIndex].ClearProposalTxInputScriptSigs();
    
    for (int output = 0; output < activeTreasury.vTreasuryProposals[nIndex].mtx.vout.size(); output++) 
    {
        activeTreasury.vTreasuryProposals[nIndex].mtx.vout[output].nValue = 0;
    }
    
    activeTreasury.vTreasuryProposals[nIndex].mtx.vout.push_back(CTxOut(view.GetValueIn(CTransaction(activeTreasury.vTreasuryProposals[nIndex].mtx)), activeTreasury.scriptChangeAddress));
    activeTreasury.vTreasuryProposals[nIndex].UpdateTimeData(GetTime());

    return GetProposalTxInfo(&activeTreasury.vTreasuryProposals[nIndex]);
}

UniValue editproposaltxrecamount(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "editproposaltxrecamount \"id\"\n"
            "\nEdits the output amount of one treasury proposal recipient and returns the new output information for this transaction.\nIf this transaction output is successfully edited, it returns equivalent data like getproposaltxamountinfo, otherwise it displays an error.\n"

            "\nArguments:\n"
            "1. \"id\"                     (hash, required) The proposal ID where you want to get the recipients from.\n"
            "2. vout                       (int, required) The transaction vout number / recipient ID.\n"
            "3. newamount                  (int or string, required) The new transaction output value for this recipient.\n"
            "\nResult:\n"
            "{\n"
            "  \"inputs\": xxxxx,          (numeric) Current transaction inputs of this proposal\n"
            "  \"inputamount\": xxxxx,     (numeric) Total transaction input amount in " + CURRENCY_UNIT + "\n"
            "  \"outputs\": xxxxx,         (numeric) Current transaction outputs of this proposal\n"
            "  \"outputamount\": xxxxx,    (numeric) Total transaction output amount in " + CURRENCY_UNIT + "\n"
            "  \"signed\": xxxxx,          (bool) Outputs true if this transaction is fully signed and ready for sending, otherwise false.\n"
            "  \"fee\": xxxxx              (numeric) The fee of this transaction, can be missing, if this transaction is not final.\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("editproposaltxrecamount", "\"id\" 0 1.23456789")
            + HelpExampleRpc("editproposaltxrecamount", "\"id\", 0, \"1.23456789\"")
        );
    
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    uint256 proposalHash = uint256S(request.params[0].get_str());
    size_t nIndex = 0;
    int nOut = request.params[1].get_int();
    
    if(!activeTreasury.GetProposalvID(proposalHash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");
    
    if(nOut < 0 || nOut >= activeTreasury.vTreasuryProposals[nIndex].mtx.vout.size())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal recipient ID out of range.");
    
    CAmount nAmount = AmountFromValue(request.params[2]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    
    activeTreasury.vTreasuryProposals[nIndex].mtx.vout[nOut].nValue = nAmount;
    activeTreasury.vTreasuryProposals[nIndex].UpdateTimeData(GetTime());

    return GetProposalTxInfo(&activeTreasury.vTreasuryProposals[nIndex]);
}

UniValue getproposaltxinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getproposaltxinfo \"id\"\n"
            "\nReturns detailed information about the treasury proposal transaction.\n"

            "\nArguments:\n"
            "1. \"id\"                     (hash, required) The proposal ID where you want to get the recipients from.\n"
            "\nResult:\n"
            "{\n"
            "  \"inputs\": xxxxx,          (numeric) Current transaction inputs of this proposal\n"
            "  \"outputs\": xxxxx,         (numeric) Current transaction outputs of this proposal\n"
            "  \"bytes\": xxxxx,           (numeric) Total transaction output amount in " + CURRENCY_UNIT + "\n"
            "  \"signed\": xxxxx           (boolean) Returns true if this transaction is signed and ready to be sent, otherwise false.\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getproposaltxinfo", "\"id\"")
            + HelpExampleRpc("getproposaltxinfo", "\"id\"")
        );

    RPCTypeCheck(request.params, {UniValue::VSTR}, false);
    if (request.params[0].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, argument 1 must be non-null");
    
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    uint256 proposalHash = uint256S(request.params[0].get_str());
    size_t nIndex = 0;
    
    if(!activeTreasury.GetProposalvID(proposalHash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");
    
    UniValue propslInf(UniValue::VOBJ), ret(UniValue::VOBJ);
    propslInf = GetProposalTxInfo(&activeTreasury.vTreasuryProposals[nIndex]);
    
    ret.pushKV("inputs", propslInf["inputs"].get_int());
    ret.pushKV("outputs", propslInf["outputs"].get_int());
    ret.pushKV("bytes", (int64_t) ::GetSerializeSize(activeTreasury.vTreasuryProposals[nIndex].mtx, SER_NETWORK, PROTOCOL_VERSION));
    ret.pushKV("signed", propslInf["signed"].get_bool());

    return ret;
}

UniValue getproposaltxrecipients(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getproposaltxrecipients \"id\"\n"
            "\nOutputs all transaction recipients in this treasury proposal transaction.\n"

            "\nArguments:\n"
            "1. \"id\"                     (hash, required) The proposal ID where you want to get the recipients from.\n"
            "\nResult:\n"
            "{\n"
            "  \"recipients\": xxxxx,      (numeric) The total transaction recipients\n"
            "  \"outputs\": xxxxx,         (array) All transaction recipients\n"
            "   [{\n"
            "       \"value\" : x.xxx,            (numeric) The value in " + CURRENCY_UNIT + "\n"
            "       \"n\" : n,                    (numeric) index\n"
            "       \"scriptPubKey\" : {          (json object)\n"
            "         \"asm\" : \"asm\",          (string) the asm\n"
            "         \"hex\" : \"hex\",          (string) the hex\n"
            "         \"reqSigs\" : n,            (numeric) The required sigs\n"
            "         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
            "         \"addresses\" : [           (json array of string)\n"
            "           \"address\"               (string) globaltoken address\n"
            "           ,...\n"
            "         ]\n"
            "       }\n"
            "   },...]\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getproposaltxrecipients", "\"id\"")
            + HelpExampleRpc("getproposaltxrecipients", "\"id\"")
        );

    RPCTypeCheck(request.params, {UniValue::VSTR}, false);
    if (request.params[0].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, argument 1 must be non-null");
    
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    uint256 proposalHash = uint256S(request.params[0].get_str());
    size_t nIndex = 0;
    
    if(!activeTreasury.GetProposalvID(proposalHash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");
    
    UniValue ret(UniValue::VOBJ), vout(UniValue::VARR);
    const CMutableTransaction* pMtx = &activeTreasury.vTreasuryProposals[nIndex].mtx;
    
    for (unsigned int i = 0; i < pMtx->vout.size(); i++) {
        const CTxOut& txout = pMtx->vout[i];

        UniValue out(UniValue::VOBJ);

        out.pushKV("value", ValueFromAmount(txout.nValue));
        out.pushKV("n", (int64_t)i);

        UniValue o(UniValue::VOBJ);
        ScriptPubKeyToUniv(txout.scriptPubKey, o, true);
        out.pushKV("scriptPubKey", o);
        vout.push_back(out);
    }
    
    ret.pushKV("recipients", (int)pMtx->vout.size());
    ret.pushKV("outputs", vout);

    return ret;
}

UniValue getproposaltxamountinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getproposaltxamountinfo \"id\"\n"
            "\nOutputs the current proposal's tx input and output amounts.\n"

            "\nArguments:\n"
            "1. \"id\"                     (hash, required) The proposal ID where you want to delete a recipient from\n"
            "\nResult:\n"
            "{\n"
            "  \"inputs\": xxxxx,          (numeric) Current transaction inputs of this proposal\n"
            "  \"inputamount\": xxxxx,     (numeric) Total transaction input amount in " + CURRENCY_UNIT + "\n"
            "  \"outputs\": xxxxx,         (numeric) Current transaction outputs of this proposal\n"
            "  \"outputamount\": xxxxx,    (numeric) Total transaction output amount in " + CURRENCY_UNIT + "\n"
            "  \"signed\": xxxxx,          (bool) Outputs true if this transaction is fully signed and ready for sending, otherwise false.\n"
            "  \"fee\": xxxxx              (numeric) The fee of this transaction, can be missing, if this transaction is not final.\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getproposaltxamountinfo", "\"id\"")
            + HelpExampleRpc("getproposaltxamountinfo", "\"id\"")
        );

    RPCTypeCheck(request.params, {UniValue::VSTR}, false);
    if (request.params[0].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, argument 1 must be non-null");
    
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    uint256 proposalHash = uint256S(request.params[0].get_str());
    size_t nIndex = 0;
    
    if(!activeTreasury.GetProposalvID(proposalHash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");

    return GetProposalTxInfo(&activeTreasury.vTreasuryProposals[nIndex]);
}

UniValue delproposaltxrecipient(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "delproposaltxrecipient \"id\" recipient\n"
            "\nRemoves a tx recipient from proposal tx.\n"
            "Updates the transaction directly in treasury mempool, if succeeded.\n"
            "Note that the transaction's inputs are not signed, and\n"
            "it is not transmitted to the network.\n"

            "\nArguments:\n"
            "1. \"id\"                    (hash, required) The proposal ID where you want to delete a recipient from\n"
            "2. recipient                 (int, required) The output recipient number (vout number). Can be found with getproposaltxrecipients\n"
            "\nResult:\n"
            "\"null\"                     (null) If succeeded, it returns null, if there is an error, you get the error message.\n"

            "\nExamples:\n"
            + HelpExampleCli("delproposaltxrecipient", "\"id\" 1")
            + HelpExampleRpc("delproposaltxrecipient", "\"id\", 1")
        );

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VNUM}, false);
    if (request.params[0].isNull() || request.params[1].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments 1 and 2 must be non-null");
    
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    uint256 proposalHash = uint256S(request.params[0].get_str());
    size_t nIndex = 0, nVOut = 0;
    
    if(!activeTreasury.GetProposalvID(proposalHash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");
    
    if(request.params[1].get_int() < 0 || request.params[1].get_int() >= activeTreasury.vTreasuryProposals[nIndex].mtx.vout.size())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Recipient out of range.");
    
    nVOut = request.params[1].get_int();
    
    activeTreasury.vTreasuryProposals[nIndex].mtx.vout.erase(activeTreasury.vTreasuryProposals[nIndex].mtx.vout.begin() + nVOut);
    activeTreasury.vTreasuryProposals[nIndex].UpdateTimeData(GetTime());

    return NullUniValue;
}

UniValue addproposaltxrecipients(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "addproposaltxrecipients \"id\" {\"address\":amount,...}\n"
            "\nAdds more recipients to this proposal tx.\n"
            "Outputs can be addresses only.\n"
            "Updates the transaction directly in treasury mempool, if succeeded.\n"
            "Note that the transaction's inputs are not signed, and\n"
            "it is not transmitted to the network.\n"

            "\nArguments:\n"
            "1. \"id\"                    (hash, required) The proposal ID you want to add this recipients to.\n"
            "2. \"recipients\"            (object, required) a json object with tx outputs\n"
            "    {\n"
            "      \"address\": x.xxx,    (numeric or string, required) The key is the globaltoken address, the numeric value (can be string) is the " + CURRENCY_UNIT + " amount\n"
            "      ,...\n"
            "    }\n"
            "\nResult:\n"
            "\"null\"                     (null) If succeeded, it returns null, if there is an error, you get the error message.\n"

            "\nExamples:\n"
            + HelpExampleCli("addproposaltxrecipients", "\"id\" \"{\\\"address\\\":0.01}\"")
            + HelpExampleRpc("addproposaltxrecipients", "\"id\", \"{\\\"address\\\":0.01}\"")
        );

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VOBJ}, false);
    if (request.params[0].isNull() || request.params[1].isNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, arguments 1 and 2 must be non-null");
    
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    uint256 proposalHash = uint256S(request.params[0].get_str());
    size_t nIndex = 0;
    
    if(!activeTreasury.GetProposalvID(proposalHash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");

    UniValue sendTo = request.params[1].get_obj();

    std::vector<CTxOut> vOuts;

    std::set<CTxDestination> destinations;
    std::vector<std::string> addrList = sendTo.getKeys();
    for (const std::string& name_ : addrList) {
        CTxDestination destination = DecodeDestination(name_);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Globaltoken address: ") + name_);
        }
        
        if (IsDestinationStringOldScriptFormat(name_)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, GetOldScriptAddressWarning(name_));
        }

        if (!destinations.insert(destination).second) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + name_);
        }

        CScript scriptPubKey = GetScriptForDestination(destination);
        CAmount nAmount = AmountFromValue(sendTo[name_]);

        CTxOut out(nAmount, scriptPubKey);
        vOuts.push_back(out);
    }
    
    activeTreasury.vTreasuryProposals[nIndex].mtx.vout.reserve(activeTreasury.vTreasuryProposals[nIndex].mtx.vout.size() + vOuts.size());
    activeTreasury.vTreasuryProposals[nIndex].mtx.vout.insert(activeTreasury.vTreasuryProposals[nIndex].mtx.vout.end(), vOuts.begin(), vOuts.end());
    activeTreasury.vTreasuryProposals[nIndex].UpdateTimeData(GetTime());

    return NullUniValue;
}

UniValue signtreasuryproposalswithkey(const JSONRPCRequest& request)
{
    if (request.fHelp || (request.params.size() != 1 && request.params.size() != 2))
        throw std::runtime_error(
            "signtreasuryproposalswithkey [\"privatekey1\",...] ( sighashtype )\n"
            "\nSign all agreed treasury proposals with given private keys.\n"
            "The first argument is an array of base58-encoded private\n"
            "keys that will be the only keys used to sign the transaction.\n"

            "\nArguments:\n"
            "1. \"privkeys\"                       (string, required) A json array of base58-encoded private keys for signing\n"
            "    [                               (json array of strings)\n"
            "      \"privatekey\"                  (string) private key in base58-encoding\n"
            "      ,...\n"
            "    ]\n"
            "2. \"sighashtype\"                    (string, optional, default=ALL) The signature hash type. Must be one of\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\"\n"

            "\nResult:\n"
            "{\n"
            "  \"hex\" : \"value\",                  (string) The hex-encoded raw transaction with signature(s)\n"
            "  \"complete\" : true|false,          (boolean) If the transaction has a complete set of signatures\n"
            "  \"errors\" : [                      (json array of objects) Script verification errors (if there are any)\n"
            "    {\n"
            "      \"txid\" : \"hash\",              (string) The hash of the referenced, previous transaction\n"
            "      \"vout\" : n,                   (numeric) The index of the output to spent and used as input\n"
            "      \"scriptSig\" : \"hex\",          (string) The hex-encoded signature script\n"
            "      \"sequence\" : n,               (numeric) Script sequence number\n"
            "      \"error\" : \"text\"              (string) Verification or signing error related to the input\n"
            "    }\n"
            "    ,...\n"
            "  ]\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("signrawtransactionwithkey", "'[\"privatekey1\",\"privatekey2\"]'")
            + HelpExampleRpc("signrawtransactionwithkey", "'[\"privatekey1\",\"privatekey2\"]'")
        );

    RPCTypeCheck(request.params, {UniValue::VARR, UniValue::VSTR}, true);
    UniValue result(UniValue::VARR);
    
    LOCK(cs_treasury);
    
    CBasicKeyStore keystore;
    txnouttype type;
    std::vector<CTxDestination> addresses;
    int nRequired, nFoundSigningAddresses=0;
    
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    if (activeTreasury.vRedeemScripts.size() == 0)
        throw JSONRPCError(RPC_MISC_ERROR, "No redeem scripts saved in treasury mempool.");
    
    const UniValue& keys = request.params[0].get_array();
    for (unsigned int idx = 0; idx < keys.size(); ++idx) {
        UniValue k = keys[idx];
        CBitcoinSecret vchSecret;
        if (!vchSecret.SetString(k.get_str())) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
        }
        CKey key = vchSecret.GetKey();
        if (!key.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");
        }
        keystore.AddKey(key);
    }
    
    for(size_t r = 0; r < activeTreasury.vRedeemScripts.size(); r++)
    {
    
        if (!ExtractDestinations(activeTreasury.vRedeemScripts[r], type, addresses, nRequired))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Could not decode Redeemscript.");
        
        for (unsigned int i = 0; i < addresses.size(); i++) 
        {
            auto keyid = GetKeyForDestination(keystore, addresses[i]);
            if (!keyid.IsNull()) {
                nFoundSigningAddresses++;
            }
        }
        
        // Add redeem scripts to the temp wallet.
        keystore.AddCScript(activeTreasury.vRedeemScripts[r]);
        // Automatically also add the P2WSH wrapped version of the script (to deal with P2SH-P2WSH).
        keystore.AddCScript(GetScriptForWitness(activeTreasury.vRedeemScripts[r]));
        addresses.clear();
    }
    
    if(nFoundSigningAddresses == 0)
    {
        throw JSONRPCError(RPC_WALLET_ERROR, "None of the signers addresses are yours, the transaction cannot be signed.");
    }
    
    for(size_t i = 0; i < activeTreasury.vTreasuryProposals.size(); i++)
    {
        if(activeTreasury.vTreasuryProposals[i].IsAgreed())
        {
            // Sign the agreed transactions
            result.push_back(SignTreasuryTransactionPartially(activeTreasury.vTreasuryProposals[i], &keystore, request.params[1]));
        }
    }
    return result;
}

UniValue clearproposaltxrecipients(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "clearproposaltxrecipients \"id\"\n"
            "\nClears all outputs from the treasury proposal transaction\n"

            "\nArguments:\n"
            "1. \"id\"                    (hash, required) The proposal ID where you want to reset the transaction.\n"
            "\nResult:\n"
            "\"null\"                     (null) If succeeded, it returns null, if there is an error, you get the error message.\n"

            "\nExamples:\n"
            + HelpExampleCli("clearproposaltxrecipients", "\"proposalhash\"")
            + HelpExampleRpc("clearproposaltxrecipients", "\"proposalhash\"")
        );

    RPCTypeCheck(request.params, {UniValue::VSTR}, false);
    
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    uint256 proposalHash = uint256S(request.params[0].get_str());
    size_t nIndex = 0;
    
    if(!activeTreasury.GetProposalvID(proposalHash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");
    
    activeTreasury.vTreasuryProposals[nIndex].mtx.vout.clear();
    activeTreasury.vTreasuryProposals[nIndex].UpdateTimeData(GetTime());

    return NullUniValue;
}

UniValue clearproposaltx(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "clearproposaltx \"id\"\n"
            "\nResets the transaction of the given proposal.\n"

            "\nArguments:\n"
            "1. \"id\"                    (hash, required) The proposal ID where you want to reset the transaction.\n"
            "\nResult:\n"
            "\"null\"                     (null) If succeeded, it returns null, if there is an error, you get the error message.\n"

            "\nExamples:\n"
            + HelpExampleCli("clearproposaltx", "\"proposalhash\"")
            + HelpExampleRpc("clearproposaltx", "\"proposalhash\"")
        );

    RPCTypeCheck(request.params, {UniValue::VSTR}, false);
    
    LOCK(cs_treasury);
        
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    uint256 proposalHash = uint256S(request.params[0].get_str());
    size_t nIndex = 0;
    
    if(!activeTreasury.GetProposalvID(proposalHash, nIndex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Treasury proposal not found.");
    
    activeTreasury.vTreasuryProposals[nIndex].mtx = CMutableTransaction();
    activeTreasury.vTreasuryProposals[nIndex].UpdateTimeData(GetTime());

    return NullUniValue;
}

UniValue savetreasurymempooltonewfile(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "savetreasurymempooltonewfile\n"
            "\nSaves the treasury mempool to a new file.\n"
            "\nArguments:\n"
            "1. \"pathtofile\"   (required, string) The directory, where the treasury mempool will be saved into.\n"
            "\nExamples:\n"
            + HelpExampleCli("savetreasurymempooltonewfile", "\"/usr/share/glttreasury/proposalmempool.dat\"")
            + HelpExampleCli("savetreasurymempooltonewfile", "\"C:\\Users\\Example\\Desktop\\proposalmempool.dat\"")
            + HelpExampleRpc("savetreasurymempooltonewfile", "\"C:\\Users\\Example\\Desktop\\proposalmempool.dat\"")
        );
    }
    
    LOCK(cs_treasury);
    
    if (!activeTreasury.IsCached())
        throw JSONRPCError(RPC_MISC_ERROR, "No treasury mempool loaded.");
    
    std::string error;
    CTreasuryMempool cachedTreasury = activeTreasury;
    cachedTreasury.SetTreasuryFilePath(request.params[0].get_str());
    
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
    { "treasury",           "createtreasurymempool",        &createtreasurymempool,        {"pathtofile"}   },
    { "treasury",           "opentreasurymempool",          &opentreasurymempool,          {"pathtofile"}   },
    { "treasury",           "savetreasurymempooltonewfile", &savetreasurymempooltonewfile, {"pathtofile"}   },
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
    { "treasury",           "createproposaltx",             &createproposaltx,             {"id","inputs","outputs","locktime","replaceable"} },
    { "treasury",           "clearproposaltx",              &clearproposaltx,              {"id"} },
    { "treasury",           "clearproposaltxrecipients",    &clearproposaltxrecipients,    {"id"} },
    { "treasury",           "addproposaltxrecipients",      &addproposaltxrecipients,      {"id","recipients"} },
    { "treasury",           "delproposaltxrecipient",       &delproposaltxrecipient,       {"id","recipient"} },
    { "treasury",           "getproposaltxamountinfo",      &getproposaltxamountinfo,      {"id"} },
    { "treasury",           "getproposaltxrecipients",      &getproposaltxrecipients,      {"id"} },
    { "treasury",           "getproposaltxinfo",            &getproposaltxinfo,            {"id"} },
    { "treasury",           "editproposaltxrecamount",      &editproposaltxrecamount,      {"id","vout","newamount"} },
    { "treasury",           "prepareproposaltx",            &prepareproposaltx,            {"id"} },
    { "treasury",           "handleproposaltxinputs",       &handleproposaltxinputs,       {} },
    { "treasury",           "moveunusableproposaltxinputs", &moveunusableproposaltxinputs, {"fromid","toid"} },
    { "treasury",           "settreasurychangeaddr",        &settreasurychangeaddr,        {"address"} },
    { "treasury",           "gettreasurychangeaddr",        &gettreasurychangeaddr,        {} },
    { "treasury",           "deltreasurychangeaddr",        &deltreasurychangeaddr,        {} },
    { "treasury",           "signtreasuryproposalswithkey", &signtreasuryproposalswithkey, {"privkeys","sighashtype"}}
};

void RegisterTreasuryRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
