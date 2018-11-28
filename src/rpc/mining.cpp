// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2009-2017 The DigiByte Core developers
// Copyright (c) 2016-2017 The Zcash developers
// Copyright (c) 2018 The Bitcoin Private developers
// Copyright (c) 2017-2018 The Bitcoin Gold developers
// Copyright (c) 2017-2018 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <crypto/algos/equihash/equihash.h>
#include <globaltoken/hardfork.h>
#include <init.h>
#include <validation.h>
#include <miner.h>
#include <net.h>
#include <policy/fees.h>
#include <pow.h>
#include <primitives/mining_block.h>
#include <rpc/blockchain.h>
#include <rpc/mining.h>
#include <rpc/server.h>
#include <spork.h>
#include <txmempool.h>
#include <util.h>
#include <utilstrencodings.h>
#include <validationinterface.h>
#include <warnings.h>

#include <masternode-payments.h>
#include <masternode-sync.h>

#include <memory>
#include <stdint.h>

unsigned int ParseConfirmTarget(const UniValue& value)
{
    int target = value.get_int();
    unsigned int max_target = ::feeEstimator.HighestTargetTracked(FeeEstimateHorizon::LONG_HALFLIFE);
    if (target < 1 || (unsigned int)target > max_target) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid conf_target, must be between %u - %u", 1, max_target));
    }
    return (unsigned int)target;
}

/**
 * Return average network hashes per second based on the last 'lookup' blocks,
 * or from the last difficulty change if 'lookup' is nonpositive.
 * If 'height' is nonnegative, compute the estimate at the time when a given block was found.
 */
UniValue GetNetworkHashPS(int lookup, int height) {
    CBlockIndex *pb = chainActive.Tip();

    if (height >= 0 && height < chainActive.Height())
        pb = chainActive[height];

    if (pb == nullptr || !pb->nHeight)
        return 0;

    // If lookup is -1, then use blocks since last difficulty change.
    if (lookup <= 0)
        lookup = pb->nHeight % Params().GetConsensus().DifficultyAdjustmentInterval() + 1;

    // If lookup is larger than chain, then set it to chain length.
    if (lookup > pb->nHeight)
        lookup = pb->nHeight;

    CBlockIndex *pb0 = pb;
    int64_t minTime = pb0->GetBlockTime();
    int64_t maxTime = minTime;
    for (int i = 0; i < lookup; i++) {
        pb0 = pb0->pprev;
        int64_t time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime);
    }

    // In case there's a situation where minTime == maxTime, we don't want a divide by zero exception.
    if (minTime == maxTime)
        return 0;

    arith_uint256 workDiff = pb->nChainWork - pb0->nChainWork;
    int64_t timeDiff = maxTime - minTime;

    return workDiff.getdouble() / timeDiff;
}

UniValue GetTreasuryOutput(const CBlock &block, int nHeight, bool skipActivationCheck)
{
    if(IsHardForkActivated(block.nTime) || skipActivationCheck)
    {
        const CChainParams& params = Params();
        CAmount treasuryamount = params.GetTreasuryAmount(block.vtx[0]->GetValueOut());
        CTxOut out = CTxOut(treasuryamount, params.GetFoundersRewardScriptAtHeight(nHeight));
        CScript scriptPubKey = params.GetFoundersRewardScriptAtHeight(nHeight);
        
        CDataStream sshextxstream(SER_NETWORK, PROTOCOL_VERSION);
        
        sshextxstream << out;
        
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("height",        nHeight);
        obj.pushKV("address",       params.GetFoundersRewardAddressAtHeight(nHeight).c_str());
        obj.pushKV("scriptPubKey",  HexStr(scriptPubKey.begin(), scriptPubKey.end()));
        obj.pushKV("amount",        (int64_t)treasuryamount);
        obj.pushKV("hex",           HexStr(sshextxstream.begin(), sshextxstream.end()));
        return obj;
    }
    return NullUniValue;
}

UniValue GetTreasuryOutput(uint32_t nTime, int nHeight, bool skipActivationCheck)
{
    LOCK(cs_main);
    
    if(IsHardForkActivated(nTime) || skipActivationCheck)
    {
        if(nHeight < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
        
        if(nHeight > chainActive.Tip()->nHeight)
        {
            const CChainParams& params = Params();
            CAmount treasuryamount = params.GetTreasuryAmount(GetBlockSubsidy(nHeight, params.GetConsensus()));
            CTxOut out = CTxOut(treasuryamount, params.GetFoundersRewardScriptAtHeight(nHeight));
            CScript scriptPubKey = params.GetFoundersRewardScriptAtHeight(nHeight);
            
            CDataStream sshextxstream(SER_NETWORK, PROTOCOL_VERSION);
            
            sshextxstream << out;
            
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("height",        nHeight);
            obj.pushKV("address",       params.GetFoundersRewardAddressAtHeight(nHeight).c_str());
            obj.pushKV("scriptPubKey",  HexStr(scriptPubKey.begin(), scriptPubKey.end()));
            obj.pushKV("amount",        (int64_t)treasuryamount);
            obj.pushKV("hex",           HexStr(sshextxstream.begin(), sshextxstream.end()));
            return obj;
        }
        else
        {
            CBlock block;
            CBlockIndex* pblockindex = chainActive[nHeight];

            if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0)
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Block not available (pruned data)");

            if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
            
            return GetTreasuryOutput(block, nHeight, skipActivationCheck);
        }
    }
    return NullUniValue;
}

UniValue getblocktreasury(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getblocktreasury ( nheight )\n"
            "\nReturns a json object containing treasury-related information, that must be included in Hardfork blocks.\n"
            "\nArguments:\n"
            "1. nHeight     (numeric, optional, default=currentHeight) Calculate treasury for a given height.\n"
            "\nResult:\n"
            "{\n"
            "  \"height\":       xxxxx,     (numeric) The height of this treasury details\n"
            "  \"address\":      xxxxx,     (string)  The GlobalToken treasury address of this height\n"
            "  \"scriptPubKey\": xxxxx,     (string)  The scriptpubkey of the treasury address\n"
            "  \"amount\":       xxxxx,     (numeric) The treasury amount for this height in Satoshis\n"
            "  \"hex\":          xxxxx      (string)  The hex TXOutput, that can be added to the coinbase transaction, to include treasury easily\n"
            "}\n"
            + HelpExampleCli("getblocktreasury", "")
            + HelpExampleRpc("getblocktreasury", "")
       );

    uint32_t nTime = 0;
    int nHeight = 0;
    {
        LOCK(cs_main);
        nTime = chainActive.Tip()->nTime;
        nHeight = (request.params[0].isNull()) ? chainActive.Tip()->nHeight : request.params[0].get_int();
    }
    return GetTreasuryOutput(nTime, nHeight, true);
}

UniValue getnetworkhashps(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
            "getnetworkhashps ( nblocks height )\n"
            "\nReturns the estimated network hashes per second based on the last n blocks.\n"
            "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.\n"
            "Pass in [height] to estimate the network speed at the time when a certain block was found.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric, optional, default=120) The number of blocks, or -1 for blocks since last difficulty change.\n"
            "2. height      (numeric, optional, default=-1) To estimate at the time of the given height.\n"
            "\nResult:\n"
            "x             (numeric) Hashes per second estimated\n"
            "\nExamples:\n"
            + HelpExampleCli("getnetworkhashps", "")
            + HelpExampleRpc("getnetworkhashps", "")
       );

    LOCK(cs_main);
    return GetNetworkHashPS(!request.params[0].isNull() ? request.params[0].get_int() : 120, !request.params[1].isNull() ? request.params[1].get_int() : -1);
}

UniValue generateBlocks(std::shared_ptr<CReserveScript> coinbaseScript, int nGenerate, uint64_t nMaxTries, bool keepScript)
{
	static const int nInnerLoopGlobalTokenMask = 0x1FFFF;
    static const int nInnerLoopGlobalTokenCount = 0x10000;
    static const int nInnerLoopEquihashMask = 0xFFFF;
	static const int nInnerLoopEquihashCount = 0xFFFF;
    int nHeightEnd = 0;
    int nHeight = 0;
	int nInnerLoopCount;
	int nInnerLoopMask;

    {   // Don't keep cs_main locked
        LOCK(cs_main);
        nHeight = chainActive.Height();
        nHeightEnd = nHeight+nGenerate;
    }
    unsigned int nExtraNonce = 0;
    UniValue blockHashes(UniValue::VARR);
	const CChainParams& params = Params();
	unsigned int n;
    unsigned int k;
    while (nHeight < nHeightEnd)
    {
        std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(Params()).CreateNewBlock(coinbaseScript->reserveScript, currentAlgo));
        if (!pblocktemplate.get())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
        CBlock *pblock = &pblocktemplate->block;
        
        // Check if the user accepted to pay the block treasury / founders reward (dev tax) / blockchain self-funding fee & masternode reward
        if(IsHardForkActivated(pblock->nTime))
        {
            if(!gArgs.GetBoolArg("-acceptdividedcoinbase", false))
            {
                throw std::runtime_error(GetCoinbaseFeeString(DIVIDEDPAYMENTS_GENERATE_WARNING));
            }
            
            if(currentAlgo == ALGO_EQUIHASH && !gArgs.GetBoolArg("-enableequihash", false))
            {
                std::stringstream strStream;
                strStream << "You cannot mine " << GetAlgoName(currentAlgo) << " right now.\n"
                << "Because of very slow solutions on CPUs " << GetAlgoName(currentAlgo) << " is disabled.\n"
                << "You can enable it the following way:\n\n"
                << "Add -enable" << GetAlgoName(currentAlgo) << "=1 to your globaltoken.conf or\n"
                << "start the daemon with the -enable" << GetAlgoName(currentAlgo) << " argument.\n\n"
                << "To activate Equihash, follow the described steps and restart your wallet.";
                throw std::runtime_error(strStream.str());
            }
            
            if(currentAlgo == ALGO_ZHASH && !gArgs.GetBoolArg("-enablezhash", false))
            {
                std::stringstream strStream;
                strStream << "You cannot mine " << GetAlgoName(currentAlgo) << " right now.\n"
                << "Because of very slow solutions on CPUs " << GetAlgoName(currentAlgo) << " is disabled.\n"
                << "You can enable it the following way:\n\n"
                << "Add -enable" << GetAlgoName(currentAlgo) << "=1 to your globaltoken.conf or\n"
                << "start the daemon with the -enable" << GetAlgoName(currentAlgo) << " argument.\n\n"
                << "To activate Zhash, follow the described steps and restart your wallet.";
                throw std::runtime_error(strStream.str());
            }
        }
        
        /*
        Best way to test auxpow (needs some code change for Equihash and normal block format!)
        
        CAuxPow::initAuxPow(*pblock);
        CPureBlockHeader& miningHeader = pblock->auxpow->parentBlock;
        while (nMaxTries > 0 && miningHeader.nNonce < nInnerLoopCount && !CheckProofOfWork(miningHeader.GetPoWHash(currentAlgo), pblock->nBits, Params().GetConsensus())) {
            ++miningHeader.nNonce;
            --nMaxTries;
        }
        if (nMaxTries == 0) {
            break;
        }
        if (miningHeader.nNonce == nInnerLoopCount) {
            continue;
        }
        
        */
        {
            LOCK(cs_main);
            IncrementExtraNonce(pblock, chainActive.Tip(), nExtraNonce);
        }
		if(IsHardForkActivated(pblock->nTime))
		{
			if(currentAlgo == ALGO_EQUIHASH || currentAlgo == ALGO_ZHASH)
			{
                CEquihashBlockHeader equihashblock = pblock->GetEquihashBlockHeader();
				nInnerLoopMask = nInnerLoopEquihashMask;
				nInnerLoopCount = nInnerLoopEquihashCount;
                n = (currentAlgo == ALGO_EQUIHASH) ? params.EquihashN() : params.ZhashN();
                k = (currentAlgo == ALGO_EQUIHASH) ? params.EquihashK() : params.ZhashK();
				// Solve Equihash.
				crypto_generichash_blake2b_state eh_state;
                EhInitialiseState(n, k, eh_state, currentAlgo == ALGO_ZHASH ? DEFAULT_ZHASH_PERSONALIZE : DEFAULT_EQUIHASH_PERSONALIZE);

				// I = the block header minus nonce and solution.
				CEquihashInput I{equihashblock};
				CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
				ss << I;

				// H(I||...
				crypto_generichash_blake2b_update(&eh_state, (unsigned char*)&ss[0], ss.size());

				while (nMaxTries > 0 &&
					   ((int)equihashblock.nNonce.GetUint64(0) & nInnerLoopEquihashMask) < nInnerLoopCount) {
					// Yes, there is a chance every nonce could fail to satisfy the -regtest
					// target -- 1 in 2^(2^256). That ain't gonna happen
					equihashblock.nNonce = ArithToUint256(UintToArith256(equihashblock.nNonce) + 1);

					// H(I||V||...
					crypto_generichash_blake2b_state curr_state;
					curr_state = eh_state;
					crypto_generichash_blake2b_update(&curr_state,
													  equihashblock.nNonce.begin(),
													  equihashblock.nNonce.size());

					// (x_1, x_2, ...) = A(I, V, n, k)
					std::function<bool(std::vector<unsigned char>)> validBlock =
							[&equihashblock](std::vector<unsigned char> soln) {
						equihashblock.nSolution = soln;
						return CheckProofOfWork(equihashblock.GetHash(), equihashblock.nBits, Params().GetConsensus(), currentAlgo);
					};
					bool found = EhBasicSolveUncancellable(n, k, curr_state, validBlock);
                    --nMaxTries;
					if (found) {
						break;
					}
				}
                
                // If Block is found convert CEquihashBlockHeader calculated stuff to pblock
                
                pblock->nBigNonce = equihashblock.nNonce;
                pblock->nSolution = equihashblock.nSolution;
			}
			else
			{
                CDefaultBlockHeader defaultblockheader = pblock->GetDefaultBlockHeader();
				nInnerLoopMask = nInnerLoopGlobalTokenMask;
				nInnerLoopCount = nInnerLoopGlobalTokenCount;
				while (nMaxTries > 0 && defaultblockheader.nNonce < nInnerLoopCount && !CheckProofOfWork(defaultblockheader.GetPoWHash(currentAlgo), defaultblockheader.nBits, Params().GetConsensus(), currentAlgo)) {
					++defaultblockheader.nNonce;
					--nMaxTries;
				}
                
                // If Block is found convert CDefaultBlockHeader calculated stuff to pblock
                
                pblock->nNonce = defaultblockheader.nNonce;
			}
		}
		else
		{
            CDefaultBlockHeader defaultblockheader = pblock->GetDefaultBlockHeader();
			nInnerLoopMask = nInnerLoopGlobalTokenMask;
			nInnerLoopCount = nInnerLoopGlobalTokenCount;
			while (nMaxTries > 0 && defaultblockheader.nNonce < nInnerLoopCount && !CheckProofOfWork(defaultblockheader.GetPoWHash(ALGO_SHA256D), defaultblockheader.nBits, Params().GetConsensus(), ALGO_SHA256D)) {
				++defaultblockheader.nNonce;
				--nMaxTries;
			}
            
            // If Block is found convert CDefaultBlockHeader calculated stuff to pblock
                
            pblock->nNonce = defaultblockheader.nNonce;
		}
        if (nMaxTries == 0) {
            break;
        }
        if ((pblock->GetAlgo() == ALGO_EQUIHASH || pblock->GetAlgo() == ALGO_ZHASH) && ((int)pblock->nBigNonce.GetUint64(0) & nInnerLoopMask) == nInnerLoopCount) {
            continue;
        }
        if (!(pblock->GetAlgo() == ALGO_EQUIHASH || pblock->GetAlgo() == ALGO_ZHASH) && (pblock->nNonce & nInnerLoopMask) == nInnerLoopCount) {
            continue;
        }
        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
        if (!ProcessNewBlock(Params(), shared_pblock, true, nullptr))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewBlock, block not accepted");
        ++nHeight;
        blockHashes.push_back(pblock->GetHash().GetHex());

        //mark script as important because it was used at least for one coinbase output if the script came from the wallet
        if (keepScript)
        {
            coinbaseScript->KeepScript();
        }
    }
    return blockHashes;
}

UniValue generatetoaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
            "generatetoaddress nblocks address (maxtries)\n"
            "\nMine blocks immediately to a specified address (before the RPC call returns)\n"
            "\nArguments:\n"
            "1. nblocks      (numeric, required) How many blocks are generated immediately.\n"
            "2. address      (string, required) The address to send the newly generated globaltoken to.\n"
            "3. maxtries     (numeric, optional) How many iterations to try (default = 1000000 or 50000 for scrypt, neoscrypt and yescrypt).\n"
            "\nResult:\n"
            "[ blockhashes ]     (array) hashes of blocks generated\n"
            "\nExamples:\n"
            "\nGenerate 11 blocks to myaddress\n"
            + HelpExampleCli("generatetoaddress", "11 \"myaddress\"")
        );

    int nGenerate = request.params[0].get_int();
    uint64_t nMaxTries;
    if(currentAlgo == ALGO_NEOSCRYPT || ALGO_YESCRYPT || ALGO_SCRYPT)
        nMaxTries = 50000;
    else
        nMaxTries = 1000000;
    if (!request.params[2].isNull()) {
        nMaxTries = request.params[2].get_int();
    }

    CTxDestination destination = DecodeDestination(request.params[1].get_str());
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    }

    std::shared_ptr<CReserveScript> coinbaseScript = std::make_shared<CReserveScript>();
    coinbaseScript->reserveScript = GetScriptForDestination(destination);

    return generateBlocks(coinbaseScript, nGenerate, nMaxTries, false);
}

UniValue getmininginfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getmininginfo\n"
            "\nReturns a json object containing mining-related information."
            "\nResult:\n"
            "{\n"
            "  \"blocks\": nnn,             (numeric) The current block\n"
            "  \"currentblockweight\": nnn, (numeric) The last block weight\n"
            "  \"currentblocktx\": nnn,     (numeric) The last block transaction\n"
            "  \"difficulty\": xxx.xxxxx    (numeric) The current difficulty\n"
            "  \"networkhashps\": nnn,      (numeric) The network hashes per second\n"
            "  \"pooledtx\": n              (numeric) The size of the mempool\n"
            "  \"chain\": \"xxxx\",           (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "  \"warnings\": \"...\"          (string) any network and blockchain warnings\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getmininginfo", "")
            + HelpExampleRpc("getmininginfo", "")
        );


    LOCK(cs_main);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("blocks",           (int)chainActive.Height());
    obj.pushKV("currentblockweight", (uint64_t)nLastBlockWeight);
    obj.pushKV("currentblocktx",   (uint64_t)nLastBlockTx);
	obj.pushKV("algoid",        currentAlgo);
	obj.pushKV("algo",           GetAlgoName(currentAlgo));
    obj.pushKV("difficulty",       (double)GetDifficulty(NULL, currentAlgo));
	obj.pushKV("difficulty_SHA256D",       (double)GetDifficulty(NULL, ALGO_SHA256D));
	obj.pushKV("difficulty_SCRYPT",       (double)GetDifficulty(NULL, ALGO_SCRYPT));
	obj.pushKV("difficulty_X11",       (double)GetDifficulty(NULL, ALGO_X11));
	obj.pushKV("difficulty_NEOSCRYPT",       (double)GetDifficulty(NULL, ALGO_NEOSCRYPT));
	obj.pushKV("difficulty_EQUIHASH",       (double)GetDifficulty(NULL, ALGO_EQUIHASH));
	obj.pushKV("difficulty_YESCRYPT",       (double)GetDifficulty(NULL, ALGO_YESCRYPT));
	obj.pushKV("difficulty_HMQ1725",       (double)GetDifficulty(NULL, ALGO_HMQ1725));
	obj.pushKV("difficulty_XEVAN",       (double)GetDifficulty(NULL, ALGO_XEVAN));
    obj.pushKV("difficulty_NIST5",       (double)GetDifficulty(NULL, ALGO_NIST5));
    obj.pushKV("difficulty_TIMETRAVEL10", (double)GetDifficulty(NULL, ALGO_TIMETRAVEL10));
    obj.pushKV("difficulty_PAWELHASH", (double)GetDifficulty(NULL, ALGO_PAWELHASH));
    obj.pushKV("difficulty_X13", (double)GetDifficulty(NULL, ALGO_X13));
    obj.pushKV("difficulty_X14", (double)GetDifficulty(NULL, ALGO_X14));
    obj.pushKV("difficulty_X15", (double)GetDifficulty(NULL, ALGO_X15));
    obj.pushKV("difficulty_X17", (double)GetDifficulty(NULL, ALGO_X17));
    obj.pushKV("difficulty_LYRA2RE", (double)GetDifficulty(NULL, ALGO_LYRA2RE));
    obj.pushKV("difficulty_BLAKE2S", (double)GetDifficulty(NULL, ALGO_BLAKE2S));
    obj.pushKV("difficulty_BLAKE2B", (double)GetDifficulty(NULL, ALGO_BLAKE2B));
    obj.pushKV("difficulty_ASTRALHASH", (double)GetDifficulty(NULL, ALGO_ASTRALHASH));
    obj.pushKV("difficulty_PADIHASH", (double)GetDifficulty(NULL, ALGO_PADIHASH));
    obj.pushKV("difficulty_JEONGHASH", (double)GetDifficulty(NULL, ALGO_JEONGHASH));
    obj.pushKV("difficulty_KECCAK", (double)GetDifficulty(NULL, ALGO_KECCAK));
    obj.pushKV("difficulty_ZHASH", (double)GetDifficulty(NULL, ALGO_ZHASH));
    obj.pushKV("difficulty_GLOBALHASH", (double)GetDifficulty(NULL, ALGO_GLOBALHASH));
    obj.pushKV("difficulty_SKEIN", (double)GetDifficulty(NULL, ALGO_SKEIN));
    obj.pushKV("difficulty_GROESTL", (double)GetDifficulty(NULL, ALGO_GROESTL));
    obj.pushKV("difficulty_QUBIT", (double)GetDifficulty(NULL, ALGO_QUBIT));
    obj.pushKV("difficulty_SKUNKHASH", (double)GetDifficulty(NULL, ALGO_SKUNKHASH));
    obj.pushKV("difficulty_QUARK", (double)GetDifficulty(NULL, ALGO_QUARK));
    obj.pushKV("difficulty_X16R", (double)GetDifficulty(NULL, ALGO_X16R));
    obj.pushKV("networkhashps",    getnetworkhashps(request));
    obj.pushKV("pooledtx",         (uint64_t)mempool.size());
    obj.pushKV("chain",            Params().NetworkIDString());
    obj.pushKV("warnings",         GetWarnings("statusbar"));
    return obj;
}

UniValue getalgoinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getalgoinfo\n"
            "Returns an object containing informations about all mining algorithms.\n"
            "\nResult:\n"
            "{\n"
			"  \"blocks\": xxxxxx,           (numeric) the current number of blocks processed in the server\n"
            "  \"headers\": xxxxxx,          (numeric) the current number of headers we have validated\n"
			"  \"bestblockhash\": \"...\",     (string) the hash of the currently best block\n"
			"  \"algos\": \"xx\",              (numeric) the number of total algos implemented\n"
			"  \"lastblockalgo\": \"xxxx\"     (string) the name of the algorithm from the last block that has been mined\n"
			"  \"lastblockalgoid\": \"xx\"     (numeric) the ID of the algorithm from the last block that has been mined\n"
			"  \"localalgo\": \"xxxx\"         (string) the name of the current algorithm that is activated to mine blocks\n"
			"  \"localalgoid\": \"xx\"         (numeric) the ID of the current algorithm that is activated to mine blocks\n"
            "  \"algo_details\": {             (object) details of the algo such like difficulty, last block and so on ..\n"
            "     \"xxxx\" : {                 (string) name of the algorithm\n"
			"        \"algoid\": xx,           (numeric) the ID of this algo\n"
            "        \"lastblock\": xx,        (numeric) the last block height mined by this algorithm. If it returns (-1) it means algo has not been seen yet.\n"
            "        \"difficulty\": xxxxxx,   (numeric) the current mining difficulty for this algo\n"
            "        \"nethashrate\": xx       (numeric) total nethashrate of this algo\n"
			"        \"lastdiffret\": xxxxxx,  (numeric) the last diff retargeting height from this algo\n"
			"        \"nextdiffret\": xxxxxx,  (numeric) the next diff retargeting height from this algo\n"
            "     }\n"
            "  }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getalgoinfo", "")
            + HelpExampleRpc("getalgoinfo", "")
        );

    LOCK(cs_main);
	
    CBlockIndex* tip = chainActive.Tip();

    UniValue obj(UniValue::VOBJ);
    UniValue algos(UniValue::VOBJ);
	
    obj.pushKV("blocks",                (int)chainActive.Height());
    obj.pushKV("headers",               pindexBestHeader ? pindexBestHeader->nHeight : -1);
    obj.pushKV("bestblockhash",         tip->GetBlockHash().GetHex());
    obj.pushKV("algos",                 NUM_ALGOS);
    obj.pushKV("lastblockalgo",         GetAlgoName(tip->GetAlgo()));
    obj.pushKV("lastblockalgoid",       tip->GetAlgo());
    obj.pushKV("localalgo",             GetAlgoName(currentAlgo));
    obj.pushKV("localalgoid",           currentAlgo);

    for(uint8_t i = 0; i < (uint8_t)NUM_ALGOS; i++)
    {
	    UniValue algo_description(UniValue::VOBJ);
        const CBlockIndex* pindexLastAlgo = GetLastBlockIndexForAlgo(tip, i);
        int lastblock = (pindexLastAlgo != nullptr) ? pindexLastAlgo->nHeight : -1;
	
        algo_description.pushKV("algoid",      i);
        algo_description.pushKV("lastblock",   lastblock);
        algo_description.pushKV("difficulty",  (double)GetDifficulty(NULL, i));
        algo_description.pushKV("nethashrate", getnetworkhashps(request));
        algo_description.pushKV("lastdiffret", CalculateDiffRetargetingBlock(tip, RETARGETING_LAST, i, Params().GetConsensus()));
        algo_description.pushKV("nextdiffret", CalculateDiffRetargetingBlock(tip, RETARGETING_NEXT, i, Params().GetConsensus()));
        algos.pushKV(GetAlgoName(i), algo_description);
    }
	
    obj.pushKV("algo_details", algos);
    return obj;
}


// NOTE: Unlike wallet RPC (which use BTC values), mining RPCs follow GBT (BIP 22) in using satoshi amounts
UniValue prioritisetransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "prioritisetransaction <txid> <dummy value> <fee delta>\n"
            "Accepts the transaction into mined blocks at a higher (or lower) priority\n"
            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id.\n"
            "2. dummy          (numeric, optional) API-Compatibility for previous API. Must be zero or null.\n"
            "                  DEPRECATED. For forward compatibility use named arguments and omit this parameter.\n"
            "3. fee_delta      (numeric, required) The fee value (in satoshis) to add (or subtract, if negative).\n"
            "                  The fee is not actually paid, only the algorithm for selecting transactions into a block\n"
            "                  considers the transaction as it would have paid a higher (or lower) fee.\n"
            "\nResult:\n"
            "true              (boolean) Returns true\n"
            "\nExamples:\n"
            + HelpExampleCli("prioritisetransaction", "\"txid\" 0.0 10000")
            + HelpExampleRpc("prioritisetransaction", "\"txid\", 0.0, 10000")
        );

    LOCK(cs_main);

    uint256 hash = ParseHashStr(request.params[0].get_str(), "txid");
    CAmount nAmount = request.params[2].get_int64();

    if (!(request.params[1].isNull() || request.params[1].get_real() == 0)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Priority is no longer supported, dummy argument to prioritisetransaction must be 0.");
    }

    mempool.PrioritiseTransaction(hash, nAmount);
    return true;
}


// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const CValidationState& state)
{
    if (state.IsValid())
        return NullUniValue;

    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, FormatStateMessage(state));
    if (state.IsInvalid())
    {
        std::string strRejectReason = state.GetRejectReason();
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

std::string gbt_vb_name(const Consensus::DeploymentPos pos) {
    const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
    std::string s = vbinfo.name;
    if (!vbinfo.gbt_force) {
        s.insert(s.begin(), '!');
    }
    return s;
}

UniValue getblocktemplate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getblocktemplate ( TemplateRequest )\n"
            "\nIf the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.\n"
            "It returns data needed to construct a block to work on.\n"
            "For full specification, see BIPs 22, 23, 9, and 145:\n"
            "    https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki\n"
            "    https://github.com/bitcoin/bips/blob/master/bip-0023.mediawiki\n"
            "    https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki#getblocktemplate_changes\n"
            "    https://github.com/bitcoin/bips/blob/master/bip-0145.mediawiki\n"

            "\nArguments:\n"
            "1. template_request         (json object, optional) A json object in the following spec\n"
            "     {\n"
            "       \"mode\":\"template\"    (string, optional) This must be set to \"template\", \"proposal\" (see BIP 23),or omitted\n"
            "       \"capabilities\":[     (array, optional) A list of strings\n"
            "           \"support\"          (string) client side supported feature, 'longpoll', 'coinbasetxn', 'coinbasevalue', 'proposal', 'serverlist', 'workid'\n"
            "           ,...\n"
            "       ],\n"
            "       \"rules\":[            (array, optional) A list of strings\n"
            "           \"support\"          (string) client side supported softfork deployment\n"
            "           ,...\n"
            "       ]\n"
            "     }\n"
            "\n"

            "\nResult:\n"
            "{\n"
            "  \"version\" : n,                    (numeric) The preferred block version\n"
            "  \"rules\" : [ \"rulename\", ... ],    (array of strings) specific block rules that are to be enforced\n"
            "  \"vbavailable\" : {                 (json object) set of pending, supported versionbit (BIP 9) softfork deployments\n"
            "      \"rulename\" : bitnumber          (numeric) identifies the bit number as indicating acceptance and readiness for the named softfork rule\n"
            "      ,...\n"
            "  },\n"
            "  \"vbrequired\" : n,                 (numeric) bit mask of versionbits the server requires set in submissions\n"
            "  \"previousblockhash\" : \"xxxx\",     (string) The hash of current highest block\n"
            "  \"transactions\" : [                (array) contents of non-coinbase transactions that should be included in the next block\n"
            "      {\n"
            "         \"data\" : \"xxxx\",             (string) transaction data encoded in hexadecimal (byte-for-byte)\n"
            "         \"txid\" : \"xxxx\",             (string) transaction id encoded in little-endian hexadecimal\n"
            "         \"hash\" : \"xxxx\",             (string) hash encoded in little-endian hexadecimal (including witness data)\n"
            "         \"depends\" : [                (array) array of numbers \n"
            "             n                          (numeric) transactions before this one (by 1-based index in 'transactions' list) that must be present in the final block if this one is\n"
            "             ,...\n"
            "         ],\n"
            "         \"fee\": n,                    (numeric) difference in value between transaction inputs and outputs (in satoshis); for coinbase transactions, this is a negative Number of the total collected block fees (ie, not including the block subsidy); if key is not present, fee is unknown and clients MUST NOT assume there isn't one\n"
            "         \"sigops\" : n,                (numeric) total SigOps cost, as counted for purposes of block limits; if key is not present, sigop cost is unknown and clients MUST NOT assume it is zero\n"
            "         \"weight\" : n,                (numeric) total transaction weight, as counted for purposes of block limits\n"
            "         \"required\" : true|false      (boolean) if provided and true, this transaction must be in the final block\n"
            "      }\n"
            "      ,...\n"
            "  ],\n"
            "  \"coinbaseaux\" : {                 (json object) data that should be included in the coinbase's scriptSig content\n"
            "      \"flags\" : \"xx\"                  (string) key name is to be ignored, and value included in scriptSig\n"
            "  },\n"
            "  \"coinbasevalue\" : n,              (numeric) maximum allowable input to coinbase transaction, including the generation award and transaction fees (in satoshis)\n"
            "  \"coinbasetxn\" : { ... },          (json object) information for coinbase transaction\n"
            "  \"treasury\" : {\n                  (json object) treasury transaction,that must be included in this block.\n"
            "       \"height\":       xxxxx,       (numeric) The height of this treasury details\n"
            "       \"address\":      xxxxx,       (string)  The GlobalToken treasury address of this height\n"
            "       \"scriptPubKey\": xxxxx,       (string)  The scriptpubkey of the treasury address\n"
            "       \"amount\":       xxxxx,       (numeric) The treasury amount for this height in Satoshis\n"
            "       \"hex\":          xxxxx        (string)  The hex TXOutput, that can be added to the coinbase transaction, to include treasury easily\n"
            "  },\n"
            "  \"target\" : \"xxxx\",                (string) The hash target\n"
            "  \"mintime\" : xxx,                  (numeric) The minimum timestamp appropriate for next block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mutable\" : [                     (array of string) list of ways the block template may be changed \n"
            "     \"value\"                          (string) A way the block template may be changed, e.g. 'time', 'transactions', 'prevblock'\n"
            "     ,...\n"
            "  ],\n"
            "  \"noncerange\" : \"00000000ffffffff\",(string) A range of valid nonces\n"
            "  \"sigoplimit\" : n,                 (numeric) limit of sigops in blocks\n"
            "  \"sizelimit\" : n,                  (numeric) limit of block size\n"
            "  \"weightlimit\" : n,                (numeric) limit of block weight\n"
            "  \"curtime\" : ttt,                  (numeric) current timestamp in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"bits\" : \"xxxxxxxx\",              (string) compressed target of next block\n"
            "  \"height\" : n                      (numeric) The height of the next block\n"
            "  \"masternode\" : {                  (json object) required masternode payee that must be included in the next block\n"
            "      \"payee\" : \"xxxx\",             (string) payee address\n"
            "      \"script\" : \"xxxx\",            (string) payee scriptPubKey\n"
            "      \"amount\": n                   (numeric) required amount to pay\n"
            "  },\n"
            "  \"masternode_payments_started\" :  true|false, (boolean) true, if masternode payments started\n"
            "  \"masternode_payments_enforced\" : true|false, (boolean) true, if masternode payments are enforced\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getblocktemplate", "")
            + HelpExampleRpc("getblocktemplate", "")
         );

    LOCK(cs_main);

    CScript coinbasetxnscript = CScript();
    std::string strMode = "template";
    UniValue lpval = NullUniValue;
    std::set<std::string> setClientRules;
    std::set<std::string> setCapabilitiesRules;
    int64_t nMaxVersionPreVB = -1;
    if (!request.params[0].isNull())
    {
        const UniValue& oparam = request.params[0].get_obj();
        const UniValue& modeval = find_value(oparam, "mode");
        if (modeval.isStr())
            strMode = modeval.get_str();
        else if (modeval.isNull())
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
        lpval = find_value(oparam, "longpollid");

        if (strMode == "proposal")
        {
            const UniValue& dataval = find_value(oparam, "data");
            if (!dataval.isStr())
                throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

            CBlock block;
            if (!DecodeHexBlk(block, dataval.get_str()))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

            uint256 hash = block.GetHash();
            BlockMap::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end()) {
                CBlockIndex *pindex = mi->second;
                if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                    return "duplicate";
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return "duplicate-invalid";
                return "duplicate-inconclusive";
            }

            CBlockIndex* const pindexPrev = chainActive.Tip();
            // TestBlockValidity only supports blocks built on the current Tip
            if (block.hashPrevBlock != pindexPrev->GetBlockHash())
                return "inconclusive-not-best-prevblk";
            CValidationState state;
            TestBlockValidity(state, Params(), block, pindexPrev, false, true);
            return BIP22ValidationResult(state);
        }

        const UniValue& aClientRules = find_value(oparam, "rules");
        if (aClientRules.isArray()) {
            for (unsigned int i = 0; i < aClientRules.size(); ++i) {
                const UniValue& v = aClientRules[i];
                setClientRules.insert(v.get_str());
            }
        } else {
            // NOTE: It is important that this NOT be read if versionbits is supported
            const UniValue& uvMaxVersion = find_value(oparam, "maxversion");
            if (uvMaxVersion.isNum()) {
                nMaxVersionPreVB = uvMaxVersion.get_int64();
            }
        }
        
        const UniValue& aCapabilities = find_value(oparam, "capabilities");
        if (aCapabilities.isArray()) {
            for (unsigned int i = 0; i < aCapabilities.size(); ++i) {
                const UniValue& v = aCapabilities[i];
                setCapabilitiesRules.insert(v.get_str());
            }
        }
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0)
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Globaltoken is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Globaltoken is downloading blocks...");
    
    // when enforcement is on we need information about a masternode payee or otherwise our block is going to be orphaned by the network
    CScript payee;
    if (sporkManager.IsSporkActive(SPORK_5_MASTERNODE_PAYMENT_ENFORCEMENT)
        && !masternodeSync.IsWinnersListSynced()
        && !mnpayments.GetBlockPayee(chainActive.Height() + 1, payee))
            throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Globaltoken is downloading masternode winners...");

    static unsigned int nTransactionsUpdatedLast;

    if (!lpval.isNull())
    {
        // Wait to respond until either the best block changes, OR a minute has passed and there are more transactions
        uint256 hashWatchedChain;
        std::chrono::steady_clock::time_point checktxtime;
        unsigned int nTransactionsUpdatedLastLP;

        if (lpval.isStr())
        {
            // Format: <hashBestChain><nTransactionsUpdatedLast>
            std::string lpstr = lpval.get_str();

            hashWatchedChain.SetHex(lpstr.substr(0, 64));
            nTransactionsUpdatedLastLP = atoi64(lpstr.substr(64));
        }
        else
        {
            // NOTE: Spec does not specify behaviour for non-string longpollid, but this makes testing easier
            hashWatchedChain = chainActive.Tip()->GetBlockHash();
            nTransactionsUpdatedLastLP = nTransactionsUpdatedLast;
        }

        // Release the wallet and main lock while waiting
        LEAVE_CRITICAL_SECTION(cs_main);
        {
            checktxtime = std::chrono::steady_clock::now() + std::chrono::minutes(1);

            WaitableLock lock(csBestBlock);
            while (chainActive.Tip()->GetBlockHash() == hashWatchedChain && IsRPCRunning())
            {
                if (cvBlockChange.wait_until(lock, checktxtime) == std::cv_status::timeout)
                {
                    // Timeout: Check transactions for update
                    if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP)
                        break;
                    checktxtime += std::chrono::seconds(10);
                }
            }
        }
        ENTER_CRITICAL_SECTION(cs_main);

        if (!IsRPCRunning())
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
        // TODO: Maybe recheck connections/IBD and (if something wrong) send an expires-immediately template to stop miners?
    }

    const struct VBDeploymentInfo& segwit_info = VersionBitsDeploymentInfo[Consensus::DEPLOYMENT_SEGWIT];
    // If the caller is indicating segwit support, then allow CreateNewBlock()
    // to select witness transactions, after segwit activates (otherwise
    // don't).
    bool fSupportsSegwit = setClientRules.find(segwit_info.name) != setClientRules.end();
    
    // Use coinbasetxn ?
    bool coinbasetxn = setCapabilitiesRules.find("coinbasetxn") != setCapabilitiesRules.end();
    
    if(coinbasetxn)
    {
        std::string strAddress = gArgs.GetArg("-coinbasetxnaddress", "NULL");
        CTxDestination destination = DecodeDestination(strAddress);
        if(strAddress != "NULL")
        {
            if (!IsValidDestination(destination)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid coinbase address. Check if your entered -coinbasetxnaddress is valid.");
            }
        }
        else
        {
            LogPrintf("%s: WARNING: Trying to use coinbasetxn, but no -coinbasetxnaddress is provided. coinbasetxn will be skipped.\n", __func__);
            coinbasetxn = false;
        }

        coinbasetxnscript = GetScriptForDestination(destination);
    }

    // Update block
    static CBlockIndex* pindexPrev;
    static int64_t nStart;
    static std::unique_ptr<CBlockTemplate> pblocktemplate;
    // Cache whether the last invocation was with segwit support, to avoid returning
    // a segwit-block to a non-segwit caller.
    static bool fLastTemplateSupportsSegwit = true;
    if (pindexPrev != chainActive.Tip() ||
        (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 5) ||
        fLastTemplateSupportsSegwit != fSupportsSegwit)
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = nullptr;

        // Store the pindexBest used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrevNew = chainActive.Tip();
        nStart = GetTime();
        fLastTemplateSupportsSegwit = fSupportsSegwit;

        // Create new block
        CScript scriptDummy = CScript() << OP_TRUE;
        CScript createscript = (coinbasetxn) ? coinbasetxnscript : scriptDummy;
        pblocktemplate = BlockAssembler(Params()).CreateNewBlock(createscript, currentAlgo, fSupportsSegwit);
        if (!pblocktemplate)
        {
            if(IsHardForkActivated(pindexPrevNew->nTime))
            {
                throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
            }
            else
            {
                if(currentAlgo == ALGO_SHA256D)
                {
                    throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
                }
                else
                {
                    std::stringstream strstream;
                    strstream << "You cannot mine with Algorithm " << GetAlgoName(currentAlgo) << ", because Hardfork is not activated yet.";
                    throw JSONRPCError(RPC_INVALID_PARAMS, strstream.str()); 
                }
            }
        }

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }
    CBlock* pblock = &pblocktemplate->block; // pointer for convenience
    const Consensus::Params& consensusParams = Params().GetConsensus();

    // Update nTime
    UpdateTime(pblock, consensusParams, pindexPrev, currentAlgo);
    pblock->nNonce = 0;
    pblock->nBigNonce = uint256();
	pblock->nSolution.clear();
    
    if(IsHardForkActivated(pblock->nTime) && !gArgs.GetBoolArg("-acceptdividedcoinbase", false))
    {
        throw std::runtime_error(GetCoinbaseFeeString(DIVIDEDPAYMENTS_BLOCKTEMPLATE_WARNING));
    }

    // NOTE: If at some point we support pre-segwit miners post-segwit-activation, this needs to take segwit support into consideration
    const bool fPreSegWit = (THRESHOLD_ACTIVE != VersionBitsState(pindexPrev, consensusParams, Consensus::DEPLOYMENT_SEGWIT, versionbitscache));

    UniValue aCaps(UniValue::VARR); aCaps.push_back("proposal");

    UniValue transactions(UniValue::VARR);
    UniValue txCoinbase = NullUniValue;
    UniValue masternodeObj(UniValue::VOBJ);
    UniValue treasuryObj(UniValue::VOBJ);
    treasuryObj = GetTreasuryOutput(*pblock, pindexPrev->nHeight + 1, false);
    
    if(pblock->txoutMasternode != CTxOut()) {
        CTxDestination address;
        ExtractDestination(pblock->txoutMasternode.scriptPubKey, address);
        masternodeObj.pushKV("payee", EncodeDestination(address).c_str());
        masternodeObj.pushKV("script", HexStr(pblock->txoutMasternode.scriptPubKey));
        masternodeObj.pushKV("amount", (int64_t)pblock->txoutMasternode.nValue);
    }
    
    std::map<uint256, int64_t> setTxIndex;
    int i = 0;
    for (const auto& it : pblock->vtx) {
        const CTransaction& tx = *it;
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase() && !coinbasetxn)
            continue;

        UniValue entry(UniValue::VOBJ);

        entry.pushKV("data", EncodeHexTx(tx));
        entry.pushKV("txid", txHash.GetHex());
        entry.pushKV("hash", tx.GetWitnessHash().GetHex());

        UniValue deps(UniValue::VARR);
        for (const CTxIn &in : tx.vin)
        {
            if (setTxIndex.count(in.prevout.hash))
                deps.push_back(setTxIndex[in.prevout.hash]);
        }
        entry.pushKV("depends", deps);

        int index_in_template = i - 1;
        entry.pushKV("fee", pblocktemplate->vTxFees[index_in_template]);
        int64_t nTxSigOps = pblocktemplate->vTxSigOpsCost[index_in_template];
        if (fPreSegWit) {
            assert(nTxSigOps % WITNESS_SCALE_FACTOR == 0);
            nTxSigOps /= WITNESS_SCALE_FACTOR;
        }
        entry.pushKV("sigops", nTxSigOps);
        entry.pushKV("weight", GetTransactionWeight(tx));

        if (tx.IsCoinBase()) 
        {
            // Show treasury reward if it is required and masternode payee
            if (IsHardForkActivated(pblock->nTime)) {
                // Correct this if GetBlockTemplate changes the order
                entry.pushKV("treasury", treasuryObj);
                entry.pushKV("masternode", masternodeObj);
            }
            entry.pushKV("required", true);
            txCoinbase = entry;
        } 
        else 
        {
            transactions.push_back(entry);
        }
    }

    UniValue aux(UniValue::VOBJ);
    aux.pushKV("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end()));

    arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);

    UniValue aMutable(UniValue::VARR);
    aMutable.push_back("time");
    aMutable.push_back("transactions");
    aMutable.push_back("prevblock");

    UniValue result(UniValue::VOBJ);
    result.pushKV("capabilities", aCaps);

    UniValue aRules(UniValue::VARR);
    UniValue vbavailable(UniValue::VOBJ);
    for (int j = 0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
        Consensus::DeploymentPos pos = Consensus::DeploymentPos(j);
        ThresholdState state = VersionBitsState(pindexPrev, consensusParams, pos, versionbitscache);
        switch (state) {
            case THRESHOLD_DEFINED:
            case THRESHOLD_FAILED:
                // Not exposed to GBT at all
                break;
            case THRESHOLD_LOCKED_IN:
            {
                // Ensure bit is set in block version
                pblock->nVersion |= VersionBitsMask(consensusParams, pos);
                // FALL THROUGH to get vbavailable set...
            }
            case THRESHOLD_STARTED:
            {
                const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
                vbavailable.pushKV(gbt_vb_name(pos), consensusParams.vDeployments[pos].bit);
                if (setClientRules.find(vbinfo.name) == setClientRules.end()) {
                    if (!vbinfo.gbt_force) {
                        // If the client doesn't support this, don't indicate it in the [default] version
                        pblock->nVersion &= ~VersionBitsMask(consensusParams, pos);
                    }
                }
                break;
            }
            case THRESHOLD_ACTIVE:
            {
                // Add to rules only
                const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
                aRules.push_back(gbt_vb_name(pos));
                if (setClientRules.find(vbinfo.name) == setClientRules.end()) {
                    // Not supported by the client; make sure it's safe to proceed
                    if (!vbinfo.gbt_force) {
                        // If we do anything other than throw an exception here, be sure version/force isn't sent to old clients
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Support for '%s' rule requires explicit client support", vbinfo.name));
                    }
                }
                break;
            }
        }
    }
    result.pushKV("version", pblock->nVersion);
    result.pushKV("rules", aRules);
    result.pushKV("vbavailable", vbavailable);
    result.pushKV("vbrequired", int(0));

    if (nMaxVersionPreVB >= 2) {
        // If VB is supported by the client, nMaxVersionPreVB is -1, so we won't get here
        // Because BIP 34 changed how the generation transaction is serialized, we can only use version/force back to v2 blocks
        // This is safe to do [otherwise-]unconditionally only because we are throwing an exception above if a non-force deployment gets activated
        // Note that this can probably also be removed entirely after the first BIP9 non-force deployment (ie, probably segwit) gets activated
        aMutable.push_back("version/force");
    }

    result.pushKV("previousblockhash", pblock->hashPrevBlock.GetHex());
    result.pushKV("transactions", transactions);
    if (coinbasetxn) 
    {
        assert(txCoinbase.isObject());
        result.pushKV("coinbasetxn", txCoinbase);
    } 
    else 
    {
        result.pushKV("coinbaseaux", aux);
        result.pushKV("coinbasevalue", (int64_t)pblock->vtx[0]->GetValueOut());
    }
    result.pushKV("treasury", treasuryObj);
    result.pushKV("longpollid", chainActive.Tip()->GetBlockHash().GetHex() + i64tostr(nTransactionsUpdatedLast));
    result.pushKV("target", hashTarget.GetHex());
    result.pushKV("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1);
    result.pushKV("mutable", aMutable);
    result.pushKV("noncerange", "00000000ffffffff");
    int64_t nSigOpLimit = MaxBlockSigOps(IsHardForkActivated(pblock->nTime));
    int64_t nSizeLimit = MaxBlockSerializedSize(IsHardForkActivated(pblock->nTime));
    if (fPreSegWit) {
        assert(nSigOpLimit % WITNESS_SCALE_FACTOR == 0);
        nSigOpLimit /= WITNESS_SCALE_FACTOR;
        assert(nSizeLimit % WITNESS_SCALE_FACTOR == 0);
        nSizeLimit /= WITNESS_SCALE_FACTOR;
    }
    result.pushKV("sigoplimit", nSigOpLimit);
    result.pushKV("sizelimit", nSizeLimit);
    if (!fPreSegWit) {
        result.pushKV("weightlimit", (int64_t)MaxBlockWeight(IsHardForkActivated(pblock->nTime)));
    }
    result.pushKV("curtime", pblock->GetBlockTime());
    result.pushKV("bits", strprintf("%08x", pblock->nBits));
    result.pushKV("height", (int64_t)(pindexPrev->nHeight+1));
    
    result.pushKV("masternode", masternodeObj);
    result.pushKV("masternode_payments_started", IsHardForkActivated(pblock->nTime));
    result.pushKV("masternode_payments_enforced", sporkManager.IsSporkActive(SPORK_5_MASTERNODE_PAYMENT_ENFORCEMENT));

    if (!pblocktemplate->vchCoinbaseCommitment.empty() && fSupportsSegwit) {
        result.pushKV("default_witness_commitment", HexStr(pblocktemplate->vchCoinbaseCommitment.begin(), pblocktemplate->vchCoinbaseCommitment.end()));
    }

    return result;
}

class submitblock_StateCatcher : public CValidationInterface
{
public:
    uint256 hash;
    bool found;
    CValidationState state;

    explicit submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), found(false), state() {}

protected:
    void BlockChecked(const CBlock& block, const CValidationState& stateIn) override {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    }
};

UniValue submitblock(const JSONRPCRequest& request)
{
    // We allow 2 arguments for compliance with BIP22. Argument 2 is ignored.
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2) {
        throw std::runtime_error(
            "submitblock \"hexdata\"  ( \"dummy\" )\n"
            "\nAttempts to submit new block to network.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n"

            "\nArguments\n"
            "1. \"hexdata\"        (string, required) the hex-encoded block data to submit\n"
            "2. \"dummy\"          (optional) dummy value, for compatibility with BIP22. This value is ignored.\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("submitblock", "\"mydata\"")
            + HelpExampleRpc("submitblock", "\"mydata\"")
        );
    }

    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;
    if (!DecodeHexBlk(block, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block does not start with a coinbase");
    }

    uint256 hash = block.GetHash();
    bool fBlockPresent = false;
    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end()) {
            CBlockIndex *pindex = mi->second;
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
                return "duplicate";
            }
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                return "duplicate-invalid";
            }
            // Otherwise, we might only have the header - process the block before returning
            fBlockPresent = true;
        }
    }

    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
        if (mi != mapBlockIndex.end()) {
            UpdateUncommittedBlockStructures(block, mi->second, Params().GetConsensus());
        }
    }

    submitblock_StateCatcher sc(block.GetHash());
    RegisterValidationInterface(&sc);
    bool fAccepted = ProcessNewBlock(Params(), blockptr, true, nullptr);
    UnregisterValidationInterface(&sc);
    if (fBlockPresent) {
        if (fAccepted && !sc.found) {
            return "duplicate-inconclusive";
        }
        return "duplicate";
    }
    if (!sc.found) {
        return "inconclusive";
    }
    return BIP22ValidationResult(sc.state);
}

UniValue estimatefee(const JSONRPCRequest& request)
{
    throw JSONRPCError(RPC_METHOD_DEPRECATED, "estimatefee was removed in v2.1.\n"
        "Clients should use estimatesmartfee.");
}

UniValue estimatesmartfee(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "estimatesmartfee conf_target (\"estimate_mode\")\n"
            "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
            "confirmation within conf_target blocks if possible and return the number of blocks\n"
            "for which the estimate is valid. Uses virtual transaction size as defined\n"
            "in BIP 141 (witness data is discounted).\n"
            "\nArguments:\n"
            "1. conf_target     (numeric) Confirmation target in blocks (1 - 1008)\n"
            "2. \"estimate_mode\" (string, optional, default=CONSERVATIVE) The fee estimate mode.\n"
            "                   Whether to return a more conservative estimate which also satisfies\n"
            "                   a longer history. A conservative estimate potentially returns a\n"
            "                   higher feerate and is more likely to be sufficient for the desired\n"
            "                   target, but is not as responsive to short term drops in the\n"
            "                   prevailing fee market.  Must be one of:\n"
            "       \"UNSET\" (defaults to CONSERVATIVE)\n"
            "       \"ECONOMICAL\"\n"
            "       \"CONSERVATIVE\"\n"
            "\nResult:\n"
            "{\n"
            "  \"feerate\" : x.x,     (numeric, optional) estimate fee rate in " + CURRENCY_UNIT + "/kB\n"
            "  \"errors\": [ str... ] (json array of strings, optional) Errors encountered during processing\n"
            "  \"blocks\" : n         (numeric) block number where estimate was found\n"
            "}\n"
            "\n"
            "The request target will be clamped between 2 and the highest target\n"
            "fee estimation is able to return based on how long it has been running.\n"
            "An error is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate for any number of blocks.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatesmartfee", "6")
            );

    RPCTypeCheck(request.params, {UniValue::VNUM, UniValue::VSTR});
    RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
    unsigned int conf_target = ParseConfirmTarget(request.params[0]);
    bool conservative = true;
    if (!request.params[1].isNull()) {
        FeeEstimateMode fee_mode;
        if (!FeeModeFromString(request.params[1].get_str(), fee_mode)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid estimate_mode parameter");
        }
        if (fee_mode == FeeEstimateMode::ECONOMICAL) conservative = false;
    }

    UniValue result(UniValue::VOBJ);
    UniValue errors(UniValue::VARR);
    FeeCalculation feeCalc;
    CFeeRate feeRate = ::feeEstimator.estimateSmartFee(conf_target, &feeCalc, conservative);
    if (feeRate != CFeeRate(0)) {
        result.pushKV("feerate", ValueFromAmount(feeRate.GetFeePerK()));
    } else {
        errors.push_back("Insufficient data or no feerate found");
        result.pushKV("errors", errors);
    }
    result.pushKV("blocks", feeCalc.returnedTarget);
    return result;
}

UniValue estimaterawfee(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "estimaterawfee conf_target (threshold)\n"
            "\nWARNING: This interface is unstable and may disappear or change!\n"
            "\nWARNING: This is an advanced API call that is tightly coupled to the specific\n"
            "         implementation of fee estimation. The parameters it can be called with\n"
            "         and the results it returns will change if the internal implementation changes.\n"
            "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
            "confirmation within conf_target blocks if possible. Uses virtual transaction size as\n"
            "defined in BIP 141 (witness data is discounted).\n"
            "\nArguments:\n"
            "1. conf_target (numeric) Confirmation target in blocks (1 - 1008)\n"
            "2. threshold   (numeric, optional) The proportion of transactions in a given feerate range that must have been\n"
            "               confirmed within conf_target in order to consider those feerates as high enough and proceed to check\n"
            "               lower buckets.  Default: 0.95\n"
            "\nResult:\n"
            "{\n"
            "  \"short\" : {            (json object, optional) estimate for short time horizon\n"
            "      \"feerate\" : x.x,        (numeric, optional) estimate fee rate in " + CURRENCY_UNIT + "/kB\n"
            "      \"decay\" : x.x,          (numeric) exponential decay (per block) for historical moving average of confirmation data\n"
            "      \"scale\" : x,            (numeric) The resolution of confirmation targets at this time horizon\n"
            "      \"pass\" : {              (json object, optional) information about the lowest range of feerates to succeed in meeting the threshold\n"
            "          \"startrange\" : x.x,     (numeric) start of feerate range\n"
            "          \"endrange\" : x.x,       (numeric) end of feerate range\n"
            "          \"withintarget\" : x.x,   (numeric) number of txs over history horizon in the feerate range that were confirmed within target\n"
            "          \"totalconfirmed\" : x.x, (numeric) number of txs over history horizon in the feerate range that were confirmed at any point\n"
            "          \"inmempool\" : x.x,      (numeric) current number of txs in mempool in the feerate range unconfirmed for at least target blocks\n"
            "          \"leftmempool\" : x.x,    (numeric) number of txs over history horizon in the feerate range that left mempool unconfirmed after target\n"
            "      },\n"
            "      \"fail\" : { ... },       (json object, optional) information about the highest range of feerates to fail to meet the threshold\n"
            "      \"errors\":  [ str... ]   (json array of strings, optional) Errors encountered during processing\n"
            "  },\n"
            "  \"medium\" : { ... },    (json object, optional) estimate for medium time horizon\n"
            "  \"long\" : { ... }       (json object) estimate for long time horizon\n"
            "}\n"
            "\n"
            "Results are returned for any horizon which tracks blocks up to the confirmation target.\n"
            "\nExample:\n"
            + HelpExampleCli("estimaterawfee", "6 0.9")
            );

    RPCTypeCheck(request.params, {UniValue::VNUM, UniValue::VNUM}, true);
    RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
    unsigned int conf_target = ParseConfirmTarget(request.params[0]);
    double threshold = 0.95;
    if (!request.params[1].isNull()) {
        threshold = request.params[1].get_real();
    }
    if (threshold < 0 || threshold > 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid threshold");
    }

    UniValue result(UniValue::VOBJ);

    for (FeeEstimateHorizon horizon : {FeeEstimateHorizon::SHORT_HALFLIFE, FeeEstimateHorizon::MED_HALFLIFE, FeeEstimateHorizon::LONG_HALFLIFE}) {
        CFeeRate feeRate;
        EstimationResult buckets;

        // Only output results for horizons which track the target
        if (conf_target > ::feeEstimator.HighestTargetTracked(horizon)) continue;

        feeRate = ::feeEstimator.estimateRawFee(conf_target, threshold, horizon, &buckets);
        UniValue horizon_result(UniValue::VOBJ);
        UniValue errors(UniValue::VARR);
        UniValue passbucket(UniValue::VOBJ);
        passbucket.pushKV("startrange", round(buckets.pass.start));
        passbucket.pushKV("endrange", round(buckets.pass.end));
        passbucket.pushKV("withintarget", round(buckets.pass.withinTarget * 100.0) / 100.0);
        passbucket.pushKV("totalconfirmed", round(buckets.pass.totalConfirmed * 100.0) / 100.0);
        passbucket.pushKV("inmempool", round(buckets.pass.inMempool * 100.0) / 100.0);
        passbucket.pushKV("leftmempool", round(buckets.pass.leftMempool * 100.0) / 100.0);
        UniValue failbucket(UniValue::VOBJ);
        failbucket.pushKV("startrange", round(buckets.fail.start));
        failbucket.pushKV("endrange", round(buckets.fail.end));
        failbucket.pushKV("withintarget", round(buckets.fail.withinTarget * 100.0) / 100.0);
        failbucket.pushKV("totalconfirmed", round(buckets.fail.totalConfirmed * 100.0) / 100.0);
        failbucket.pushKV("inmempool", round(buckets.fail.inMempool * 100.0) / 100.0);
        failbucket.pushKV("leftmempool", round(buckets.fail.leftMempool * 100.0) / 100.0);

        // CFeeRate(0) is used to indicate error as a return value from estimateRawFee
        if (feeRate != CFeeRate(0)) {
            horizon_result.pushKV("feerate", ValueFromAmount(feeRate.GetFeePerK()));
            horizon_result.pushKV("decay", buckets.decay);
            horizon_result.pushKV("scale", (int)buckets.scale);
            horizon_result.pushKV("pass", passbucket);
            // buckets.fail.start == -1 indicates that all buckets passed, there is no fail bucket to output
            if (buckets.fail.start != -1) horizon_result.pushKV("fail", failbucket);
        } else {
            // Output only information that is still meaningful in the event of error
            horizon_result.pushKV("decay", buckets.decay);
            horizon_result.pushKV("scale", (int)buckets.scale);
            horizon_result.pushKV("fail", failbucket);
            errors.push_back("Insufficient data or no feerate found which meets threshold");
            horizon_result.pushKV("errors",errors);
        }
        result.pushKV(StringForFeeEstimateHorizon(horizon), horizon_result);
    }
    return result;
}

/* ************************************************************************** */
/* Merge mining.  */

namespace {

/**
 * The variables below are used to keep track of created and not yet
 * submitted auxpow blocks.  Lock them to be sure even for multiple
 * RPC threads running in parallel.
 */
CCriticalSection cs_auxblockCache;
std::map<uint256, CBlock*> mapNewBlock;
std::vector<std::unique_ptr<CBlockTemplate>> vNewBlockTemplate;

void AuxMiningCheck()
{
  if(!g_connman)
    throw JSONRPCError(RPC_CLIENT_P2P_DISABLED,
                       "Error: Peer-to-peer functionality missing or disabled");

  if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0
        && !Params().MineBlocksOnDemand())
    throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED,
                       "GlobalToken is not connected!");

  if (IsInitialBlockDownload() && !Params().MineBlocksOnDemand())
    throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD,
                       "GlobalToken is downloading blocks...");

  /* This should never fail, since the chain is already
     past the point of merge-mining start.  Check nevertheless.  */
  {
    LOCK(cs_main);
    if (!IsHardForkActivated(chainActive.Tip()->nTime))
      throw std::runtime_error("mining auxblock method is not yet available");
  }
}

} // anonymous namespace

UniValue AuxMiningCreateBlock(const CScript& scriptPubKey)
{
    AuxMiningCheck();

    LOCK(cs_auxblockCache);

    static unsigned nTransactionsUpdatedLast;
    static const CBlockIndex* pindexPrev = nullptr;
    static uint64_t nStart;
    static CBlock* pblock = nullptr;
    static unsigned nExtraNonce = 0;

    // Update block
    {
    LOCK(cs_main);
    if (pindexPrev != chainActive.Tip()
        || (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast
            && GetTime() - nStart > 60))
    {
        if (pindexPrev != chainActive.Tip())
        {
            // Clear old blocks since they're obsolete now.
            mapNewBlock.clear();
            vNewBlockTemplate.clear();
            pblock = nullptr;
        }

        // Create new block with nonce = 0 and extraNonce = 1
        std::unique_ptr<CBlockTemplate> newBlock
            = BlockAssembler(Params()).CreateNewBlock(scriptPubKey, currentAlgo);
        if (!newBlock)
        {
            if(IsHardForkActivated(chainActive.Tip()->nTime))
            {
                throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
            }
            else
            {
                if(currentAlgo == ALGO_SHA256D)
                {
                    throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
                }
                else
                {
                    std::stringstream strstream;
                    strstream << "You cannot mine with Algorithm " << GetAlgoName(currentAlgo) << ", because Hardfork is not activated yet.";
                    throw JSONRPCError(RPC_INVALID_PARAMS, strstream.str()); 
                }
            }
        }
        
        if(IsHardForkActivated(newBlock->block.nTime) && !gArgs.GetBoolArg("-acceptdividedcoinbase", false))
        {
            throw std::runtime_error(GetCoinbaseFeeString(DIVIDEDPAYMENTS_AUXPOW_WARNING));
        }

        // Update state only when CreateNewBlock succeeded
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        pindexPrev = chainActive.Tip();
        nStart = GetTime();
	    
        // If new block is an Equihash block, set the nNonce to null, because it is randomized by default.
        if(currentAlgo == ALGO_EQUIHASH || currentAlgo == ALGO_ZHASH)
            newBlock->block.nBigNonce.SetNull();

        // Finalise it by setting the version and building the merkle root
        IncrementExtraNonce(&newBlock->block, pindexPrev, nExtraNonce);
        newBlock->block.SetAuxpowVersion(true);

        // Save
        pblock = &newBlock->block;
        mapNewBlock[pblock->GetHash()] = pblock;
        vNewBlockTemplate.push_back(std::move(newBlock));
    }
    }

    // At this point, pblock is always initialised:  If we make it here
    // without creating a new block above, it means that, in particular,
    // pindexPrev == chainActive.Tip().  But for that to happen, we must
    // already have created a pblock in a previous call, as pindexPrev is
    // initialised only when pblock is.
    assert(pblock);

    arith_uint256 target;
    bool fNegative, fOverflow;
    target.SetCompact(pblock->nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || target == 0)
        throw std::runtime_error("invalid difficulty bits in block");

    UniValue result(UniValue::VOBJ);
    result.pushKV("baseversion", (int64_t)CURRENT_AUXPOW_VERSION);
    result.pushKV("posflag", strprintf("%08x", AUXPOW_STAKE_FLAG));
    result.pushKV("equihashflag", strprintf("%08x", AUXPOW_EQUIHASH_FLAG));
    result.pushKV("zhashflag", strprintf("%08x", AUXPOW_ZHASH_FLAG));
    result.pushKV("hash", pblock->GetHash().GetHex());
    result.pushKV("chainid", pblock->GetChainId());
    result.pushKV("previousblockhash", pblock->hashPrevBlock.GetHex());
    result.pushKV("coinbasevalue", (int64_t)pblock->vtx[0]->GetValueOut());
    result.pushKV("bits", strprintf("%08x", pblock->nBits));
    result.pushKV("height", static_cast<int64_t> (pindexPrev->nHeight + 1));
    result.pushKV("target", HexStr(BEGIN(target), END(target)));

    return result;
}

bool AuxMiningSubmitBlock(const std::string& hashHex,
                          const std::string& auxpowHex,
                          const int nAuxPoWVersion)
{
    AuxMiningCheck();

    LOCK(cs_auxblockCache);

    uint256 hash;
    hash.SetHex(hashHex);
    std::string auxpowstring;
    uint32_t nVersion = CURRENT_AUXPOW_VERSION;

    const std::map<uint256, CBlock*>::iterator mit = mapNewBlock.find(hash);
    if (mit == mapNewBlock.end())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "block hash unknown");
    CBlock& block = *mit->second;
    
    if(nAuxPoWVersion == 1 && block.GetAlgo() == ALGO_ZHASH)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Zhash is not mineable with Auxpow 1.0, use Auxpow 2.0 for Zhash!");
    
    if(nAuxPoWVersion == 1)
    {
        if(block.GetAlgo() == ALGO_EQUIHASH)
            nVersion |= AUXPOW_EQUIHASH_FLAG;
        
        CDataStream ssAuxPow(SER_NETWORK, PROTOCOL_VERSION | RPCSerializationFlags());
        ssAuxPow << nVersion;
        auxpowstring = HexStr(ssAuxPow.begin(), ssAuxPow.end()) + auxpowHex;
    }
    else
    {
        auxpowstring = auxpowHex;
    }

    const std::vector<unsigned char> vchAuxPow = ParseHex(auxpowstring);
    CDataStream ss(vchAuxPow, SER_GETHASH, PROTOCOL_VERSION);
    CAuxPow auxpow;
    ss >> auxpow;
    block.SetAuxpow(new CAuxPow(auxpow));
    
    assert(block.GetHash() == hash);

    submitblock_StateCatcher sc(block.GetHash());
    RegisterValidationInterface(&sc);
    std::shared_ptr<const CBlock> shared_block 
      = std::make_shared<const CBlock>(block);
    bool fAccepted = ProcessNewBlock(Params(), shared_block, true, nullptr);
    UnregisterValidationInterface(&sc);

    return fAccepted;
}

UniValue createauxblock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "createauxblock <address>\n"
            "\ncreate a new block and return information required to merge-mine it.\n"
            "\nArguments:\n"
            "1. address      (string, required) specify coinbase transaction payout address\n"
            "\nResult:\n"
            "{\n"
            "  \"hash\"               (string) hash of the created block\n"
            "  \"chainid\"            (numeric) chain ID for this block\n"
            "  \"previousblockhash\"  (string) hash of the previous block\n"
            "  \"coinbasevalue\"      (numeric) value of the block's coinbase\n"
            "  \"bits\"               (string) compressed target of the block\n"
            "  \"height\"             (numeric) height of the block\n"
            "  \"_target\"            (string) target in reversed byte order, deprecated\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("createauxblock", "\"address\"")
            + HelpExampleRpc("createauxblock", "\"address\"")
            );

    // Check coinbase payout address
    const CTxDestination coinbaseScript
      = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(coinbaseScript)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Error: Invalid coinbase payout address");
    }
    const CScript scriptPubKey = GetScriptForDestination(coinbaseScript);

    return AuxMiningCreateBlock(scriptPubKey);
}

UniValue submitauxblock(const JSONRPCRequest& request)
{
    if (request.fHelp || (request.params.size() != 2 && request.params.size() != 3))
        throw std::runtime_error(
            "submitauxblock <hash> <auxpow>\n"
            "\nsubmit a solved auxpow for a previously block created by 'createauxblock'.\n"
            "\nArguments:\n"
            "1. hash           (string, required) hash of the block to submit\n"
            "2. auxpow         (string, required) serialised auxpow found\n"
            "3. auxpowversion  (numeric, optional, default=1) The AuxPoW Version to encode (1 = legacy, 2 = supports pos + equihash format)\n"
            "\nResult:\n"
            "xxxxx        (boolean) whether the submitted block was correct\n"
            "\nExamples:\n"
            + HelpExampleCli("submitauxblock", "\"hash\" \"serialised auxpow\"")
            + HelpExampleRpc("submitauxblock", "\"hash\" \"serialised auxpow\"")
            );

    const int nAuxPoWVersion =  (request.params.size() == 3) ? request.params[2].get_int() : 1;
    
    //throw an error if the auxpow encoding version is unknown.
    if (!(nAuxPoWVersion == 1 || nAuxPoWVersion == 2))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Unknown auxpow version.");
    
    return AuxMiningSubmitBlock(request.params[0].get_str(), 
                                request.params[1].get_str(),
                                nAuxPoWVersion);
}


/* ************************************************************************** */

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "mining",             "getalgoinfo",            &getalgoinfo,            {} },
    { "mining",             "getblocktreasury",       &getblocktreasury,       {"height"} },
    { "mining",             "getnetworkhashps",       &getnetworkhashps,       {"nblocks","height"} },
    { "mining",             "getmininginfo",          &getmininginfo,          {} },
    { "mining",             "prioritisetransaction",  &prioritisetransaction,  {"txid","dummy","fee_delta"} },
    { "mining",             "getblocktemplate",       &getblocktemplate,       {"template_request"} },
    { "mining",             "submitblock",            &submitblock,            {"hexdata","dummy"} },
    { "mining",             "createauxblock",         &createauxblock,         {"address"} },
    { "mining",             "submitauxblock",         &submitauxblock,         {"hash", "auxpow", "auxpowversion"} },


    { "generating",         "generatetoaddress",      &generatetoaddress,      {"nblocks","address","maxtries"} },

    { "hidden",             "estimatefee",            &estimatefee,            {} },
    { "util",               "estimatesmartfee",       &estimatesmartfee,       {"conf_target", "estimate_mode"} },

    { "hidden",             "estimaterawfee",         &estimaterawfee,         {"conf_target", "threshold"} },
};

void RegisterMiningRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
