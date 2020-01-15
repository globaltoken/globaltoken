// Copyright (c) 2020 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_TREASURY_H
#define BITCOIN_RPC_TREASURY_H
#include <stdint.h>
#include <script/standard.h>

class UniValue;
class CTreasuryProposal;
class CScript;

/** Sign the treasury transaction partially */
UniValue SignTreasuryTransactionPartially(CTreasuryProposal& tpsl, CBasicKeyStore *keystore, const UniValue& hashType);

/** Treasury Mempool information to JSON */
UniValue treasurymempoolInfoToJSON();

/** Treasury Proposal to JSON */
UniValue proposaltoJSON(const CTreasuryProposal* proposal, int decodeProposalTX);

/** Compute Proposal Tx Amount data */
UniValue GetProposalTxInfo(const CTreasuryProposal* pProposal);

/** Check if the treasury change address if a valid script address */
bool IsTreasuryChangeAddrValid(const CScript& scriptTreasuryChange, CTxDestination &txDestination);

#endif // BITCOIN_RPC_TREASURY_H
