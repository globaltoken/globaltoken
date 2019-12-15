// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2016 Daniel Kraft
// Copyright (c) 2018 The Globaltoken Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AUXPOW_H
#define BITCOIN_AUXPOW_H

#include <consensus/params.h>
#include <primitives/mining_block.h>
#include <primitives/transaction.h>
#include <globaltoken/multihasher.h>
#include <serialize.h>
#include <version.h>
#include <uint256.h>

#include <vector>

class CBlock;
class CBlockHeader;
class CBlockIndex;
class CValidationState;

/** Header for merge-mining data in the coinbase.  */
static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' };

/** Operation flags */
static const int AUXPOW_STAKE_FLAG           = 0x00001000;
static const int AUXPOW_EQUIHASH_FLAG        = 0x00002000;
static const int AUXPOW_PERS_STRING_FLAG     = 0x00004000;
static const uint32_t CURRENT_AUXPOW_VERSION = 1;

/**
 * Base class for CMerkleTx that just holds the fields and implements
 * serialisation.  This is the part that is needed for CAuxPow.  The other
 * functionality, needed by the wallet, is kept in CMerkleTx itself (defined
 * in wallet/wallet.h as in upstream Bitcoin).
 */
class CBaseMerkleTx
{
public:
    CTransactionRef tx;
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;

    /* An nIndex == -1 means that hashBlock (in nonzero) refers to the earliest
     * block in the chain we know this or any in-wallet dependency conflicts
     * with. Older clients interpret nIndex == -1 as unconfirmed for backward
     * compatibility.
     */
    int nIndex;

    CBaseMerkleTx()
    {
        SetTx(MakeTransactionRef());
        Init();
    }

    explicit CBaseMerkleTx(CTransactionRef arg)
    {
        SetTx(std::move(arg));
        Init();
    }

    void Init()
    {
        hashBlock = uint256();
        nIndex = -1;
    }

    void SetTx(CTransactionRef arg)
    {
        tx = std::move(arg);
    }
    
    /** Helper conversion operator to allow passing CBaseMerkleTx where CTransaction is expected.
     *  TODO: adapt callers and remove this operator. */
    operator const CTransaction&() const { return *tx; }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(tx);
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    }

    const uint256& GetHash() const { return tx->GetHash(); }
    
    /**
     * Actually compute the Merkle branch.  This is used for unit tests when
     * constructing an auxpow.  It is not needed for actual production, since
     * we do not care in the Namecoin client how the auxpow is constructed
     * by a miner.
     */
    void InitMerkleBranch(const CBlock& block, int posInBlock);
};

class CPOSMerkleTx
{
public:
    CPOSTransactionRef tx;
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;

    /* An nIndex == -1 means that hashBlock (in nonzero) refers to the earliest
     * block in the chain we know this or any in-wallet dependency conflicts
     * with. Older clients interpret nIndex == -1 as unconfirmed for backward
     * compatibility.
     */
    int nIndex;

    CPOSMerkleTx()
    {
        SetTx(MakePOSTransactionRef());
        Init();
    }

    explicit CPOSMerkleTx(CPOSTransactionRef arg)
    {
        SetTx(std::move(arg));
        Init();
    }

    void Init()
    {
        hashBlock = uint256();
        nIndex = -1;
    }

    void SetTx(CPOSTransactionRef arg)
    {
        tx = std::move(arg);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(tx);
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    }

    const uint256& GetHash() const { return tx->GetHash(); }
};

/**
 * Data for the merge-mining auxpow.  This is a merkle tx (the parent block's
 * coinbase tx) that can be verified to be in the parent block, and this
 * transaction's input (the coinbase script) contains the reference
 * to the actual merge-mined block.
 *
 * Blockformat : AuxPOW 2.0.
 */
class CAuxPow
{

/* Public for the unit tests.  */
public:

  /** The Auxpow Version */
  uint32_t nVersion;
  
   /**
   * The parent block's coinbase tx, which is used to link the auxpow from
   * the tx input to the parent block header.
   */
  CBaseMerkleTx coinbaseTx;

  /** The merkle branch connecting the aux block to our coinbase.  */
  std::vector<uint256> vChainMerkleBranch;

  /** Merkle tree index of the aux block header in the coinbase.  */
  int nChainIndex;

  /** Parent block header (on which the real PoW is done).  */
  CDefaultBlockHeader     defaultparentBlock;
  CEquihashBlockHeader    equihashparentBlock;
  
  /** CPOSMerkleTx to save the POS coinbase tx. */
  CPOSMerkleTx            coinbasePOSTx;
  
  /** Equihash based algo personalization string */
  std::string strEquihashPersString;

public:

  /* Prevent accidental conversion.  */
  inline explicit CAuxPow (CTransactionRef txIn)
    : coinbaseTx (txIn), coinbasePOSTx()
  {}
  
  /* Prevent accidental conversion.  */
  inline explicit CAuxPow (CPOSTransactionRef txIn)
    : coinbaseTx(), coinbasePOSTx (txIn)
  {}
  
  /* Prevent accidental conversion.  */
  inline explicit CAuxPow ()
    : coinbaseTx(), coinbasePOSTx ()
  {}

  ADD_SERIALIZE_METHODS;

  template<typename Stream, typename Operation>
    inline void
    SerializationOp (Stream& s, Operation ser_action)
  {
    READWRITE (this->nVersion);
    if(hasEquihashPersString())
        READWRITE(strEquihashPersString);
    if(isAuxPowPOS())
        READWRITE (coinbasePOSTx);
    else
        READWRITE (coinbaseTx);
    READWRITE (vChainMerkleBranch);
    READWRITE (nChainIndex);
    if(isAuxPowEquihash())
    {
        READWRITE (equihashparentBlock);
    }
    else
    {
        READWRITE (defaultparentBlock);
    }
  }

  /**
   * Check the auxpow, given the merge-mined block's hash and our chain ID.
   * Note that this does not verify the actual PoW on the parent block!  It
   * just confirms that all the merkle branches are valid.
   * @param hashAuxBlock Hash of the merge-mined block.
   * @param nChainId The auxpow chain ID of the block to check.
   * @param params Consensus parameters.
   * @param nBlockAlgo The block algo ID, of this block.
   * @return True if the auxpow is valid.
   */
  bool check (const uint256& hashAuxBlock, int nChainId,
              const Consensus::Params& params, const uint8_t nBlockAlgo) const;

  /**
   * Check if we have Equihash Auxpow or AuxPOW in POS Version.
   */   
  bool isAuxPowEquihash() const;
  bool isAuxPowPOS() const;
  bool hasEquihashPersString() const;

  /**
   * Get the parent block's hash.  This is used to verify that it
   * satisfies the PoW requirement.
   * @return The parent block hash.
   */
  inline uint256
  getParentBlockPoWHash (uint8_t nAlgo) const
  {
    if(isAuxPowEquihash() && (IsEquihashBasedAlgo(nAlgo)))
        return getEquihashParentBlock().GetHash ();
    else
        return getDefaultParentBlock().GetPoWHash(nAlgo, SER_GETHASH, LoadMultiHasherVersionFlags(true));
  }

  /**
   * Return parent block.  This is only used for the temporary parentblock
   * auxpow version check.
   * @return The parent block.
   */
  /* FIXME: Remove after the hardfork.  */
  inline const CDefaultBlockHeader&
  getDefaultParentBlock() const
  {
    return defaultparentBlock;
  }
  
  inline const CEquihashBlockHeader&
  getEquihashParentBlock () const
  {
    return equihashparentBlock;
  }
  
  /* get the version of auxpow. */
  inline const uint32_t&
  getVersion() const
  {
    return nVersion;
  }
  
  /* get the coinbase POSTransaction of auxpow. */
  inline const CPOSMerkleTx&
  getPOSTransaction() const
  {
    return coinbasePOSTx;
  }
  
  /* get the coinbase Transaction of auxpow. */
  inline const CBaseMerkleTx&
  getTransaction() const
  {
    return coinbaseTx;
  }
  
  /* get the chain merkle branch of auxpow. */
  inline const std::vector<uint256>&
  GetChainMerkleBranch() const
  {
    return vChainMerkleBranch;
  }
  
  /* get the chain index of auxpow. */
  inline const int&
  GetChainIndex() const
  {
    return nChainIndex;
  }
  
  /**
   * Check a merkle branch.  This used to be in CBlock, but was removed
   * upstream.  Thus include it here now.
   */
  static uint256 CheckMerkleBranch (uint256 hash,
                                    const std::vector<uint256>& vMerkleBranch,
                                    int nIndex);

  /**
   * Calculate the expected index in the merkle tree.  This is also used
   * for the test-suite.
   * @param nNonce The coinbase's nonce value.
   * @param nChainId The chain ID.
   * @param h The merkle block height.
   * @return The expected index for the aux hash.
   */
  static int getExpectedIndex (uint32_t nNonce, int nChainId, unsigned h);

  /**
   * Initialise the auxpow of the given block header.  This constructs
   * a minimal CAuxPow object with a minimal parent block and sets
   * it on the block header.  The auxpow is not necessarily valid, but
   * can be "mined" to make it valid.
   * @param header The header to set the auxpow on.
   */
  static void initAuxPow (CBlockHeader& header, uint32_t nAuxPowVersion);

};

#endif // BITCOIN_AUXPOW_H
