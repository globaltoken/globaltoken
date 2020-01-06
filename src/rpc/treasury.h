// Copyright (c) 2020 The Globaltoken Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_TREASURY_H
#define BITCOIN_RPC_TREASURY_H
#include <stdint.h>

class UniValue;
class CTreasuryProposal;

/** Treasury Mempool information to JSON */
UniValue treasurymempoolInfoToJSON();

/** Treasury Proposal to JSON */
UniValue proposaltoJSON(const CTreasuryProposal* proposal, int decodeProposalTX);

#endif // BITCOIN_RPC_TREASURY_H
