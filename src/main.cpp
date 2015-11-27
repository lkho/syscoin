// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "alert.h"
#include "checkpoints.h"
#include "db.h"
#include "txdb.h"
#include "net.h"
#include "init.h"
#include "auxpow.h"
#include "ui_interface.h"
#include "checkqueue.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/xpressive/xpressive_dynamic.hpp>

using namespace std;
using namespace boost;

//
// Global state
//
CCriticalSection cs_setpwalletRegistered;
set<CWallet*> setpwalletRegistered;

CCriticalSection cs_main;

CTxMemPool mempool;
unsigned int nTransactionsUpdated = 0;
map<uint256, CBlockIndex*> mapBlockIndex;
uint256 hashGenesisBlock(
		"0xc84c8d0f52a7418b28a24e7b5354d6febed47c8cc33b3fa20fdbe4b3a1fcd9c4");
static CBigNum bnProofOfWorkLimit(~uint256(0) >> 20); // Syscoin: starting difficulty is 1 / 2^12
static CBigNum bnProofOfWorkLimitCake(~uint256(0) >> 11); // Syscoin: cakenet is cake
CBlockIndex* pindexGenesisBlock = NULL;
int nBestHeight = -1;
uint256 nBestChainWork = 0;
uint256 nBestInvalidWork = 0;
uint256 hashBestChain = 0;
CBlockIndex* pindexBest = NULL;
set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexValid; // may contain all CBlockIndex*'s that have validness >=BLOCK_VALID_TRANSACTIONS, and must contain those who aren't failed
int64 nTimeBestReceived = 0;
int nScriptCheckThreads = 0;
bool fImporting = false;
bool fReindex = false;
bool fInit= false;
bool fBenchmark = false;
bool fTxIndex = true; // syscoin is using transaction index by default
unsigned int nCoinCacheSize = 5000;

int hardforkLaunch = 1660;
int hardforkB2 = 600000;

extern bool Solver(const CKeyStore& keystore, const CScript& scriptPubKey,
		uint256 hash, int nHashType, CScript& scriptSigRet,
		txnouttype& whichTypeRet);
extern bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey,
		const CTransaction& txTo, unsigned int nIn, unsigned int flags,
		int nHashType);

extern int64 GetTxHashHeight(const uint256 txHash);
//todo go back and address fees
/** Fees smaller than this (in satoshi) are considered zero fee (for transaction creation) */
int64 CTransaction::nMinTxFee = 100000;

/** Fees smaller than this (in satoshi) are considered zero fee (for relaying) */
int64 CTransaction::nMinRelayTxFee = 100000;

CMedianFilter<int> cPeerBlockCounts(8, 0); // Amount of blocks that other nodes claim to have

map<uint256, CBlock*> mapOrphanBlocks;
multimap<uint256, CBlock*> mapOrphanBlocksByPrev;

map<uint256, CTransaction> mapOrphanTransactions;
map<uint256, set<uint256> > mapOrphanTransactionsByPrev;

// Constant stuff for coinbase transactions we create:
CScript COINBASE_FLAGS;

const string strMessageMagic = "Syscoin Signed Message:\n";

double dHashesPerSec = 0.0;
int64 nHPSTimerStart = 0;

// Settings
int64 nTransactionFee = 0;
int64 nMinimumInputValue = DUST_HARD_LIMIT;
bool HasReachedMainNetForkB2()
{
	return fCakeNet || fTestNet || (!fCakeNet && !fTestNet && nBestHeight >= hardforkB2);
}
bool ExistsInMempool(std::vector<unsigned char> vchToFind, opcodetype type)
{
	for (map<uint256, CTransaction>::iterator mi = mempool.mapTx.begin();
		mi != mempool.mapTx.end(); ++mi) {
		CTransaction& tx = (*mi).second;
		if (tx.IsCoinBase() || !tx.IsFinal())
			continue;
		if(IsAliasOp(type))
		{
			vector<vector<unsigned char> > vvch;
			int op, nOut;
			
			if(DecodeAliasTx(tx, op, nOut, vvch, -1)) {
				if(op == type)
				{
					string vchToFindStr = stringFromVch(vchToFind);
					string vvchFirstStr = stringFromVch(vvch[0]);
					if(vvchFirstStr == vchToFindStr)
					{
						if (GetTxHashHeight(tx.GetHash()) <= 0) 
							return true;
					}
					if(vvch.size() > 1)
					{
						string vvchSecondStr = HexStr(vvch[1]);
						if(vvchSecondStr == vchToFindStr)
						{
							if (GetTxHashHeight(tx.GetHash()) <= 0) 
								return true;
						}
					}
				}
			}
		}
		else if(IsOfferOp(type))
		{
			vector<vector<unsigned char> > vvch;
			int op, nOut;
			
			if(DecodeOfferTx(tx, op, nOut, vvch, -1)) {
				if(op == type)
				{
					string vchToFindStr = stringFromVch(vchToFind);
					string vvchFirstStr = stringFromVch(vvch[0]);
					if(vvchFirstStr == vchToFindStr)
					{
						if (GetTxHashHeight(tx.GetHash()) <= 0) 
							return true;
					}
					if(vvch.size() > 1)
					{
						string vvchSecondStr = HexStr(vvch[1]);
						if(vvchSecondStr == vchToFindStr)
						{
							if (GetTxHashHeight(tx.GetHash()) <= 0)
								return true;
						}
					}
				}
			}
		}
		else if(IsCertOp(type))
		{
			vector<vector<unsigned char> > vvch;
			int op, nOut;
			
			if(DecodeCertTx(tx, op, nOut, vvch, -1)) {
				if(op == type)
				{
					string vchToFindStr = stringFromVch(vchToFind);
					string vvchFirstStr = stringFromVch(vvch[0]);
					if(vvchFirstStr == vchToFindStr)
					{
						if (GetTxHashHeight(tx.GetHash()) <= 0)
								return true;
					}
					if(vvch.size() > 1)
					{
						string vvchSecondStr = HexStr(vvch[1]);
						if(vvchSecondStr == vchToFindStr)
						{
							if (GetTxHashHeight(tx.GetHash()) <= 0) 
								return true;
						}
					}
				}
			}
		}
		else if(IsEscrowOp(type))
		{
			vector<vector<unsigned char> > vvch;
			int op, nOut;
			
			if(DecodeEscrowTx(tx, op, nOut, vvch, -1)) {
				if(op == type)
				{
					string vchToFindStr = stringFromVch(vchToFind);
					string vvchFirstStr = stringFromVch(vvch[0]);
					if(vvchFirstStr == vchToFindStr)
					{
						if (GetTxHashHeight(tx.GetHash()) <= 0)
								return true;
					}
					if(vvch.size() > 1)
					{
						string vvchSecondStr = HexStr(vvch[1]);
						if(vvchSecondStr == vchToFindStr)
						{
							if (GetTxHashHeight(tx.GetHash()) <= 0) 
								return true;
						}
					}
				}
			}
		}
		else if(IsMessageOp(type))
		{
			vector<vector<unsigned char> > vvch;
			int op, nOut;
			
			if(DecodeMessageTx(tx, op, nOut, vvch, -1)) {
				if(op == type)
				{
					string vchToFindStr = stringFromVch(vchToFind);
					string vvchFirstStr = stringFromVch(vvch[0]);
					if(vvchFirstStr == vchToFindStr)
					{
						if (GetTxHashHeight(tx.GetHash()) <= 0)
								return true;
					}
					if(vvch.size() > 1)
					{
						string vvchSecondStr = HexStr(vvch[1]);
						if(vvchSecondStr == vchToFindStr)
						{
							if (GetTxHashHeight(tx.GetHash()) <= 0) 
								return true;
						}
					}
				}
			}
		}
	}
	return false;

}
//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

// These functions dispatch to one or all registered wallets

/**
 * register wallet
 */
void RegisterWallet(CWallet* pwalletIn) {
	{
		LOCK(cs_setpwalletRegistered);
		setpwalletRegistered.insert(pwalletIn);
	}
}

/**
 * unregister wallet
 */
void UnregisterWallet(CWallet* pwalletIn) {
	{
		LOCK(cs_setpwalletRegistered);
		setpwalletRegistered.erase(pwalletIn);
	}
}

/**
 * get the wallet transaction with the given hash (if it exists)
 */
bool static GetTransaction(const uint256& hashTx, CWalletTx& wtx) {
	BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
		if (pwallet->GetTransaction(hashTx, wtx))
			return true;
	return false;
}

/**
 * erases transaction with the given hash from all wallets
 */
void static EraseFromWallets(uint256 hash) {
	BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
		pwallet->EraseFromWallet(hash);
}

/**
 * make sure all wallets know about the given transaction, in the given block
 */
void SyncWithWallets(const uint256 &hash, const CTransaction& tx,
		const CBlock* pblock, bool fUpdate) {
	BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
		pwallet->AddToWalletIfInvolvingMe(hash, tx, pblock, fUpdate);
}

/**
 * notify wallets about a new best chain
 */
void static SetBestChain(const CBlockLocator& loc) {
	BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
		pwallet->SetBestChain(loc);
}

/**
 * notify wallets about an updated transaction
 */
void static UpdatedTransaction(const uint256& hashTx) {
	BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
		pwallet->UpdatedTransaction(hashTx);
}

/**
 * dump all wallets
 */
void static PrintWallets(const CBlock& block) {
	BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
		pwallet->PrintWallet(block);
}

/**
 * notify wallets about an incoming inventory (for request counts)
 */
void static Inventory(const uint256& hash) {
	BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
		pwallet->Inventory(hash);
}

/**
 * ask wallets to resend their transactions
 */
void static ResendWalletTransactions() {
	BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
		pwallet->ResendWalletTransactions();
}


// to enable merged mining:
// - set a block from which it will be enabled
// - set a unique chain ID
//   each merged minable scrypt_1024_1_1_256 coin should have a different one
//   (if two have the same ID, they can't be merge mined together)
int GetAuxPowStartBlock() {
  if (fTestNet)
		return AUXPOW_START_TESTNET;
	else if (fCakeNet)
		return AUXPOW_START_CAKENET;
	else
		return AUXPOW_START_MAINNET;
}

//////////////////////////////////////////////////////////////////////////////
//
// CCoinsView implementations
//

bool CCoinsView::GetCoins(const uint256 &txid, CCoins &coins) {
	return false;
}
bool CCoinsView::SetCoins(const uint256 &txid, const CCoins &coins) {
	return false;
}
bool CCoinsView::HaveCoins(const uint256 &txid) {
	return false;
}
CBlockIndex *CCoinsView::GetBestBlock() {
	return NULL;
}
bool CCoinsView::SetBestBlock(CBlockIndex *pindex) {
	return false;
}
bool CCoinsView::BatchWrite(const std::map<uint256, CCoins> &mapCoins,
		CBlockIndex *pindex) {
	return false;
}
bool CCoinsView::GetStats(CCoinsStats &stats) {
	return false;
}

CCoinsViewBacked::CCoinsViewBacked(CCoinsView &viewIn) :
		base(&viewIn) {
}
bool CCoinsViewBacked::GetCoins(const uint256 &txid, CCoins &coins) {
	return base->GetCoins(txid, coins);
}
bool CCoinsViewBacked::SetCoins(const uint256 &txid, const CCoins &coins) {
	return base->SetCoins(txid, coins);
}
bool CCoinsViewBacked::HaveCoins(const uint256 &txid) {
	return base->HaveCoins(txid);
}
CBlockIndex *CCoinsViewBacked::GetBestBlock() {
	return base->GetBestBlock();
}
bool CCoinsViewBacked::SetBestBlock(CBlockIndex *pindex) {
	return base->SetBestBlock(pindex);
}
void CCoinsViewBacked::SetBackend(CCoinsView &viewIn) {
	base = &viewIn;
}
bool CCoinsViewBacked::BatchWrite(const std::map<uint256, CCoins> &mapCoins,
		CBlockIndex *pindex) {
	return base->BatchWrite(mapCoins, pindex);
}
bool CCoinsViewBacked::GetStats(CCoinsStats &stats) {
	return base->GetStats(stats);
}

CCoinsViewCache::CCoinsViewCache(CCoinsView &baseIn, bool fDummy) :
		CCoinsViewBacked(baseIn), pindexTip(NULL) {
}

bool CCoinsViewCache::GetCoins(const uint256 &txid, CCoins &coins) {
	if (cacheCoins.count(txid)) {
		coins = cacheCoins[txid];
		return true;
	}
	if (base->GetCoins(txid, coins)) {
		cacheCoins[txid] = coins;
		return true;
	}
	return false;
}

std::map<uint256, CCoins>::iterator CCoinsViewCache::FetchCoins(
		const uint256 &txid) {
	std::map<uint256, CCoins>::iterator it = cacheCoins.lower_bound(txid);
	if (it != cacheCoins.end() && it->first == txid)
		return it;
	CCoins tmp;
	if (!base->GetCoins(txid, tmp))
		return cacheCoins.end();
	std::map<uint256, CCoins>::iterator ret = cacheCoins.insert(it,
			std::make_pair(txid, CCoins()));
	tmp.swap(ret->second);
	return ret;
}

CCoins &CCoinsViewCache::GetCoins(const uint256 &txid) {
	std::map<uint256, CCoins>::iterator it = FetchCoins(txid);
	assert(it != cacheCoins.end());
	return it->second;
}

bool CCoinsViewCache::SetCoins(const uint256 &txid, const CCoins &coins) {
	cacheCoins[txid] = coins;
	return true;
}

bool CCoinsViewCache::HaveCoins(const uint256 &txid) {
	return FetchCoins(txid) != cacheCoins.end();
}

CBlockIndex *CCoinsViewCache::GetBestBlock() {
	if (pindexTip == NULL)
		pindexTip = base->GetBestBlock();
	return pindexTip;
}

bool CCoinsViewCache::SetBestBlock(CBlockIndex *pindex) {
	pindexTip = pindex;
	return true;
}

bool CCoinsViewCache::BatchWrite(const std::map<uint256, CCoins> &mapCoins,
		CBlockIndex *pindex) {
	for (std::map<uint256, CCoins>::const_iterator it = mapCoins.begin();
			it != mapCoins.end(); it++)
		cacheCoins[it->first] = it->second;
	pindexTip = pindex;
	return true;
}

bool CCoinsViewCache::Flush() {
	bool fOk = base->BatchWrite(cacheCoins, pindexTip);
	if (fOk)
		cacheCoins.clear();
	return fOk;
}

unsigned int CCoinsViewCache::GetCacheSize() {
	return cacheCoins.size();
}

/** CCoinsView that brings transactions from a memorypool into view.
 It does not check for spendings by memory pool transactions. */
CCoinsViewMemPool::CCoinsViewMemPool(CCoinsView &baseIn, CTxMemPool &mempoolIn) :
		CCoinsViewBacked(baseIn), mempool(mempoolIn) {
}

bool CCoinsViewMemPool::GetCoins(const uint256 &txid, CCoins &coins) {
	if (base->GetCoins(txid, coins))
		return true;
	if (mempool.exists(txid)) {
		const CTransaction &tx = mempool.lookup(txid);
		coins = CCoins(tx, MEMPOOL_HEIGHT);
		return true;
	}
	return false;
}

bool CCoinsViewMemPool::HaveCoins(const uint256 &txid) {
	return mempool.exists(txid) || base->HaveCoins(txid);
}

CCoinsViewCache *pcoinsTip = NULL;
CBlockTreeDB *pblocktree = NULL;
CAliasDB *paliasdb = NULL;
COfferDB *pofferdb = NULL;
CCertDB *pcertdb = NULL;
CEscrowDB *pescrowdb = NULL;
CMessageDB *pmessagedb = NULL;
//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

bool AddOrphanTx(const CTransaction& tx) {
	uint256 hash = tx.GetHash();
	if (mapOrphanTransactions.count(hash))
		return false;

	// Ignore big transactions, to avoid a
	// send-big-orphans memory exhaustion attack. If a peer has a legitimate
	// large transaction with a missing parent then we assume
	// it will rebroadcast it later, after the parent transaction(s)
	// have been mined or received.
	// 10,000 orphans, each of which is at most 5,000 bytes big is
	// at most 500 megabytes of orphans:
	unsigned int sz = tx.GetSerializeSize(SER_NETWORK,
			CTransaction::CURRENT_VERSION);
	if (sz > 5000) {
		printf("ignoring large orphan tx (size: %u, hash: %s)\n", sz,
				hash.ToString().c_str());
		return false;
	}

	mapOrphanTransactions[hash] = tx;
	BOOST_FOREACH(const CTxIn& txin, tx.vin)
		mapOrphanTransactionsByPrev[txin.prevout.hash].insert(hash);

	printf("stored orphan tx %s (mapsz %"PRIszu")\n", hash.ToString().c_str(),
			mapOrphanTransactions.size());
	return true;
}

void static EraseOrphanTx(uint256 hash) {
	if (!mapOrphanTransactions.count(hash))
		return;
	const CTransaction& tx = mapOrphanTransactions[hash];
	BOOST_FOREACH(const CTxIn& txin, tx.vin) {
		mapOrphanTransactionsByPrev[txin.prevout.hash].erase(hash);
		if (mapOrphanTransactionsByPrev[txin.prevout.hash].empty())
			mapOrphanTransactionsByPrev.erase(txin.prevout.hash);
	}
	mapOrphanTransactions.erase(hash);
}

unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans) {
	unsigned int nEvicted = 0;
	while (mapOrphanTransactions.size() > nMaxOrphans) {
		// Evict a random orphan:
		uint256 randomhash = GetRandHash();
		map<uint256, CTransaction>::iterator it =
				mapOrphanTransactions.lower_bound(randomhash);
		if (it == mapOrphanTransactions.end())
			it = mapOrphanTransactions.begin();
		EraseOrphanTx(it->first);
		++nEvicted;
	}
	return nEvicted;
}

//////////////////////////////////////////////////////////////////////////////
//
// CTransaction / CTxOut
//

bool CTxOut::IsDust() const {
	// Syscoin: IsDust() detection disabled, allows any valid dust to be relayed.
	// The fees imposed on each dust txo is considered sufficient spam deterrant.
	return false;
}

bool CTransaction::IsStandard(string& strReason) const {
	if ((nVersion > CTransaction::CURRENT_VERSION || nVersion < 1)
			&& nVersion != SYSCOIN_TX_VERSION) {
		strReason = "version";
		return false;
	}

	if (!IsFinal()) {
		strReason = "not-final";
		return false;
	}

	// Extremely large transactions with lots of inputs can cost the network
	// almost as much to process as they cost the sender in fees, because
	// computing signature hashes is O(ninputs*txsize). Limiting transactions
	// to MAX_STANDARD_TX_SIZE mitigates CPU exhaustion attacks.
	unsigned int sz = this->GetSerializeSize(SER_NETWORK,
			CTransaction::CURRENT_VERSION);
	if (sz >= MAX_STANDARD_TX_SIZE) {
		strReason = "tx-size";
		return false;
	}

	BOOST_FOREACH(const CTxIn& txin, vin) {
		// Biggest 'standard' txin is a 3-signature 3-of-3 CHECKMULTISIG
		// pay-to-script-hash, which is 3 ~80-byte signatures, 3
		// ~65-byte public keys, plus a few script ops.
		if (txin.scriptSig.size() > 500) {
			strReason = "scriptsig-size";
			return false;
		}
		if (!txin.scriptSig.IsPushOnly()) {
			strReason = "scriptsig-not-pushonly";
			return false;
		}
	}
	BOOST_FOREACH(const CTxOut& txout, vout) {
		if (!::IsStandard(txout.scriptPubKey)) {
			strReason = "scriptpubkey";
			return false;
		}
		if (txout.IsDust()) {
			strReason = "dust";
			return false;
		}
	}
	return true;
}

//
// Check transaction inputs, and make sure any
// pay-to-script-hash transactions are evaluating IsStandard scripts
//
// Why bother? To avoid denial-of-service attacks; an attacker
// can submit a standard HASH... OP_EQUAL transaction,
// which will get accepted into blocks. The redemption
// script can be anything; an attacker could use a very
// expensive-to-check-upon-redemption script like:
//   DUP CHECKSIG DROP ... repeated 100 times... OP_1
//
bool CTransaction::AreInputsStandard(CCoinsViewCache& mapInputs) const {
	if (IsCoinBase())
		return true; // Coinbases don't use vin normally

	for (unsigned int i = 0; i < vin.size(); i++) {
		const CTxOut& prev = GetOutputFor(vin[i], mapInputs);

		vector<vector<unsigned char> > vSolutions;
		txnouttype whichType;
		// get the scriptPubKey corresponding to this input:
		const CScript& prevScript = prev.scriptPubKey;

		vector<vector<unsigned char> > vvch;

		if (!Solver(prevScript, whichType, vSolutions))
			return false;

		int nArgsExpected = ScriptSigArgsExpected(whichType, vSolutions);
		if (nArgsExpected < 0)
			return false;

		// Transactions with extra stuff in their scriptSigs are
		// non-standard. Note that this EvalScript() call will
		// be quick, because if there are any operations
		// beside "push data" in the scriptSig the
		// IsStandard() call returns false
		vector<vector<unsigned char> > stack;
		if (!EvalScript(stack, vin[i].scriptSig, *this, i, false, 0))
			return false;

		if (whichType == TX_SCRIPTHASH) {
			if (stack.empty())
				return false;

			CScript subscript(stack.back().begin(), stack.back().end());
			vector<vector<unsigned char> > vSolutions2;
			txnouttype whichType2;

			if (!Solver(subscript, whichType2, vSolutions2))
				return false;

			if (whichType2 == TX_SCRIPTHASH)
				return false;

			int tmpExpected;
			tmpExpected = ScriptSigArgsExpected(whichType2, vSolutions2);
			if (tmpExpected < 0)
				return false;
			nArgsExpected += tmpExpected;
		}

		if (stack.size() != (unsigned int) nArgsExpected)
			return false;
	}

	return true;
}

unsigned int CTransaction::GetLegacySigOpCount() const {
	unsigned int nSigOps = 0;
	BOOST_FOREACH(const CTxIn& txin, vin) {
		nSigOps += txin.scriptSig.GetSigOpCount(false);
	}
	BOOST_FOREACH(const CTxOut& txout, vout) {
		nSigOps += txout.scriptPubKey.GetSigOpCount(false);
	}
	return nSigOps;
}

int CMerkleTx::SetMerkleBranch(const CBlock* pblock) {
	CBlock blockTmp;
	if (pblock == NULL) {
		CCoins coins;
		if (pcoinsTip->GetCoins(GetHash(), coins)) {
			CBlockIndex *pindex = FindBlockByHeight(coins.nHeight);
			if (pindex) {
				if (!blockTmp.ReadFromDisk(pindex))
					return 0;
				pblock = &blockTmp;
			}
		}
	}

	if (pblock) {
		// Update the tx's hashBlock
		hashBlock = pblock->GetHash();

		// Locate the transaction
		for (nIndex = 0; nIndex < (int) pblock->vtx.size(); nIndex++)
			if (pblock->vtx[nIndex] == *(CTransaction*) this)
				break;
		if (nIndex == (int) pblock->vtx.size()) {
			vMerkleBranch.clear();
			nIndex = -1;
			printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
			return 0;
		}

		// Fill in merkle branch
		vMerkleBranch = pblock->GetMerkleBranch(nIndex);
	}

	// Is the tx in a block that's in the main chain
	map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
	if (mi == mapBlockIndex.end())
		return 0;
	CBlockIndex* pindex = (*mi).second;
	if (!pindex || !pindex->IsInMainChain())
		return 0;

	return pindexBest->nHeight - pindex->nHeight + 1;
}

bool CTransaction::CheckTransaction(CValidationState &state) const {
	// Basic checks that don't depend on any context
	if (vin.empty())
		return state.DoS(10,
				error("CTransaction::CheckTransaction() : vin empty"));
	if (vout.empty() && 0 == data.size())
		return state.DoS(10,
				error(
						"CTransaction::CheckTransaction() : vout empty and 0 == data.size()"));
	// Size limits
	if (::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION)
			> MAX_BLOCK_SIZE)
		return state.DoS(100,
				error("CTransaction::CheckTransaction() : size limits failed"));

	// Check for negative or overflow output values
	int64 nValueOut = 0;
	BOOST_FOREACH(const CTxOut& txout, vout) {
		if (txout.nValue < 0)
			return state.DoS(100,
					error(
							"CTransaction::CheckTransaction() : txout.nValue negative"));
		if (txout.nValue > MAX_MONEY)
			return state.DoS(100,
					error(
							"CTransaction::CheckTransaction() : txout.nValue too high"));
		nValueOut += txout.nValue;
		if (!MoneyRange(nValueOut))
			return state.DoS(100,
					error(
							"CTransaction::CheckTransaction() : txout total out of range"));
	}

	// Check for duplicate inputs
	set<COutPoint> vInOutPoints;
	BOOST_FOREACH(const CTxIn& txin, vin) {
		if (vInOutPoints.count(txin.prevout))
			return state.DoS(100,
					error(
							"CTransaction::CheckTransaction() : duplicate inputs"));
		vInOutPoints.insert(txin.prevout);
	}

	if (IsCoinBase()) {
		if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100)
			return state.DoS(100,
					error(
							"CTransaction::CheckTransaction() : coinbase script size"));
	} else {
		BOOST_FOREACH(const CTxIn& txin, vin)
			if (txin.prevout.IsNull())
				return state.DoS(10,
						error(
								"CTransaction::CheckTransaction() : prevout is null"));
	}

    if (nVersion != SYSCOIN_TX_VERSION)
        return true;

    vector<vector<unsigned char> > vvch;
    int op;
    int nOut;
	string err = "";
	CBitcoinAddress myAddress;
    
    // alias
    if(DecodeAliasTx(*this, op, nOut, vvch, -1)) {
		if (vvch[0].size() > MAX_NAME_LENGTH) {
			err = error("alias transaction with alias too long");
		}
		switch (op) {
			case OP_ALIAS_ACTIVATE:
				if (vvch[1].size() > 20)
					err = error("aliasactivate tx with rand too big");
				break;
			case OP_ALIAS_UPDATE:
				if (vvch[1].size() > MAX_VALUE_LENGTH)
					err = error("aliasupdate tx with value too long");
				break;
			default:
				err = error("alias transaction has unknown op");
		}
		
    }
    else if(DecodeOfferTx(*this, op, nOut, vvch, -1)) {
		if (vvch[0].size() > MAX_NAME_LENGTH) {
			err = error("offer transaction with offer guid too long");
		}
		switch (op) {
			case OP_OFFER_ACTIVATE:
				if (vvch[1].size() > 20)
					err = error("offeractivate tx with rand too big");
				break;
			case OP_OFFER_UPDATE:
				if (vvch[1].size() > MAX_VALUE_LENGTH)
					err = error("offerupdate tx with value too long");
				break;
			case OP_OFFER_ACCEPT: 
				if (vvch[1].size() > 20)
					err = error("offeraccept tx with accept rand too big");
				break;
			case OP_OFFER_REFUND: 
				if (vvch[1].size() > 20)
					err = error("offerrefund tx with accept rand too big");
				if (vvch[2].size() > 20)
					err = error("offerrefund tx with refund status too long");
				break;
			default:
				err = error("offer transaction has unknown op");
		
        }
    }
    else if(DecodeCertTx(*this, op, nOut, vvch, -1)) {
		if (vvch[0].size() > MAX_NAME_LENGTH) {
			err = error("cert transaction with cert title too long");
		}
		switch (op) {

			case OP_CERT_ACTIVATE:
				if (vvch[1].size() > 20)
					err = error("cert tx with rand too big");
				if (vvch[2].size() > MAX_NAME_LENGTH)
					err = error("cert tx with value too long");
				break;
			case OP_CERT_UPDATE:
				if (vvch[1].size() > MAX_NAME_LENGTH)
					err = error("cert tx with value too long");
				break;
			case OP_CERT_TRANSFER:
        		if (vvch[0].size() > 20)
					err = error("cert transfer tx with cert rand too big");
				if (vvch[1].size() > 20)
					err = error("cert transfer tx with invalid hash length");
				break;
			default:
				err = error("cert transaction has unknown op");
		}
        
	}  
   else if(DecodeEscrowTx(*this, op, nOut, vvch, -1)) {
		if (vvch[0].size() > MAX_NAME_LENGTH) {
			err = error("escrow tx with GUID too big");
		}
		if (vvch[1].size() > 20) {
			err = error("escrow tx rand too big");
		}
		switch (op) {
			case OP_ESCROW_ACTIVATE:
				break;
			case OP_ESCROW_RELEASE:
				break;
			case OP_ESCROW_REFUND:
				break;
			case OP_ESCROW_COMPLETE:
				break;			
			default:
				err = error("escrow transaction has unknown op");
		}
	} 
   else if(DecodeMessageTx(*this, op, nOut, vvch, -1)) {
		if (vvch[0].size() > MAX_NAME_LENGTH) {
			err = error("message tx with GUID too big");
		}
		if (vvch[1].size() > 20) {
			err = error("message tx rand too big");
		}
		switch (op) {
			case OP_MESSAGE_ACTIVATE:
				break;		
			default:
				err = error("message transaction has unknown op");
		}
	} 
    if(err != "")
	{
		return state.DoS(10,error(err.c_str()));
	}
    return true;
}

int64 CTransaction::GetMinFee(unsigned int nBlockSize, bool fAllowFree,
		enum GetMinFee_mode mode) const {
	// Base fee is either nMinTxFee or nMinRelayTxFee
	int64 nBaseFee = (mode == GMF_RELAY) ? nMinRelayTxFee : nMinTxFee;

	unsigned int nBytes = ::GetSerializeSize(*this, SER_NETWORK,
			PROTOCOL_VERSION);
	unsigned int nNewBlockSize = nBlockSize + nBytes;
	int64 nMinFee = (1 + (int64) nBytes / 1000) * nBaseFee;

	if (fAllowFree) {
		// There is a free transaction area in blocks created by most miners,
		// * If we are relaying we allow transactions up to DEFAULT_BLOCK_PRIORITY_SIZE - 1000
		//   to be considered to fall into this category. We don't want to encourage sending
		//   multiple transactions instead of one big transaction to avoid fees.
		// * If we are creating a transaction we allow transactions up to 5,000 bytes
		//   to be considered safe and assume they can likely make it into this section.
		if (nBytes
				< (mode == GMF_SEND ?
						5000 : (DEFAULT_BLOCK_PRIORITY_SIZE - 1000)))
			nMinFee = 0;
	}

	// Syscoin
	// To limit dust spam, add nBaseFee for each output less than DUST_SOFT_LIMIT
	BOOST_FOREACH(const CTxOut& txout, vout)
		if (txout.nValue < DUST_SOFT_LIMIT)
			nMinFee += nBaseFee;

	// Raise the price as the block approaches full
	if (nBlockSize != 1 && nNewBlockSize >= MAX_BLOCK_SIZE_GEN / 2) {
		if (nNewBlockSize >= MAX_BLOCK_SIZE_GEN)
			return MAX_MONEY;
		nMinFee *= MAX_BLOCK_SIZE_GEN / (MAX_BLOCK_SIZE_GEN - nNewBlockSize);
	}

	if (!MoneyRange(nMinFee))
		nMinFee = MAX_MONEY;
	return nMinFee;
}

void CTxMemPool::pruneSpent(const uint256 &hashTx, CCoins &coins) {
	LOCK(cs);

	std::map<COutPoint, CInPoint>::iterator it = mapNextTx.lower_bound(
			COutPoint(hashTx, 0));

	// iterate over all COutPoints in mapNextTx whose hash equals the provided hashTx
	while (it != mapNextTx.end() && it->first.hash == hashTx) {
		coins.Spend(it->first.n); // and remove those outputs from coins
		it++;
	}
}
bool CTxMemPool::accept(CValidationState &state, CTransaction &tx,
		bool fCheckInputs, bool fLimitFree, bool* pfMissingInputs) {

	if (pfMissingInputs)
		*pfMissingInputs = false;

	if (!tx.CheckTransaction(state))
		return error("CTxMemPool::accept() : CheckTransaction failed");

	// Coinbase is only valid in a block, not as a loose transaction
	if (tx.IsCoinBase())
		return state.DoS(100,
				error("CTxMemPool::accept() : coinbase as individual tx"));

	// To help v0.1.5 clients who would see it as a negative number
	if ((int64) tx.nLockTime > std::numeric_limits<int>::max())
		return error(
				"CTxMemPool::accept() : not accepting nLockTime beyond 2038 yet");

	// Rather not work on nonstandard transactions (unless -testnet)
	string strNonStd;
	if (!fTestNet && !fCakeNet && !tx.IsStandard(strNonStd))
		return error("CTxMemPool::accept() : nonstandard transaction (%s)",
				strNonStd.c_str());

	// is it already in the memory pool?
	uint256 hash = tx.GetHash();
	{
		LOCK(cs);
		if (mapTx.count(hash))
			return false;
	}

	// Check for conflicts with in-memory transactions
	CTransaction* ptxOld = NULL;
	for (unsigned int i = 0; i < tx.vin.size(); i++) {
		COutPoint outpoint = tx.vin[i].prevout;
		if (mapNextTx.count(outpoint)) {
			// Disable replacement feature for now
			return false;

			// Allow replacing with a newer version of the same transaction
			if (i != 0)
				return false;
			ptxOld = mapNextTx[outpoint].ptx;
			if (ptxOld->IsFinal())
				return false;
			if (!tx.IsNewerThan(*ptxOld))
				return false;
			for (unsigned int i = 0; i < tx.vin.size(); i++) {
				COutPoint outpoint = tx.vin[i].prevout;
				if (!mapNextTx.count(outpoint)
						|| mapNextTx[outpoint].ptx != ptxOld)
					return false;
			}
			break;
		}
	}

	if (fCheckInputs) {
		CCoinsView dummy;
		CCoinsViewCache view(dummy);

		{
			LOCK(cs);
			CCoinsViewMemPool viewMemPool(*pcoinsTip, *this);
			view.SetBackend(viewMemPool);

			// do we already have it?
			if (view.HaveCoins(hash))
				return false;

			// do all inputs exist?
			// Note that this does not check for the presence of actual outputs (see the next check for that),
			// only helps filling in pfMissingInputs (to determine missing vs spent).
			BOOST_FOREACH(const CTxIn txin, tx.vin) {
				if (!view.HaveCoins(txin.prevout.hash)) {
					if (pfMissingInputs)
						*pfMissingInputs = true;
					return false;
				}
			}

			// are the actual inputs available?
			if (!tx.HaveInputs(view))
				return state.Invalid(
						error("CTxMemPool::accept() : inputs already spent"));

			// Bring the best block into scope
			view.GetBestBlock();

			// we have all inputs cached now, so switch back to dummy, so we don't need to keep lock on mempool
			view.SetBackend(dummy);
		}

		// Check for non-standard pay-to-script-hash in inputs
		if (tx.nVersion != SYSCOIN_TX_VERSION && !tx.AreInputsStandard(view)
				&& !fTestNet && !fCakeNet)
			return error("CTxMemPool::accept() : nonstandard transaction input");

		// Note: if you modify this code to accept non-standard transactions, then
		// you should add code here to check that the transaction does a
		// reasonable number of ECDSA signature verifications.

		int64 nFees = tx.GetValueIn(view) - tx.GetValueOut();
		unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK,
				PROTOCOL_VERSION);

		// Don't accept it if it can't get into a block
		int64 txMinFee = tx.GetMinFee(1000, true, GMF_RELAY);
		if (fLimitFree && nFees < txMinFee)
			return error(
					"CTxMemPool::accept() : not enough fees %s, %"PRI64d" < %"PRI64d,
					hash.ToString().c_str(), nFees, txMinFee);

		// Continuously rate-limit free transactions
		// This mitigates 'penny-flooding' -- sending thousands of free transactions just to
		// be annoying or make others' transactions take longer to confirm.
		if (fLimitFree && nFees < CTransaction::nMinRelayTxFee) {
			static double dFreeCount;
			static int64 nLastTime;
			int64 nNow = GetTime();

			LOCK(cs);

			// Use an exponentially decaying ~1-minute window:
			dFreeCount *= pow(1.0 - 1.0 / 60.0, (double) (nNow - nLastTime));
			nLastTime = nNow;
			// -limitfreerelay unit is thousand-bytes-per-minute
			// At default rate it would take over a month to fill 1GB
			if (dFreeCount >= GetArg("-limitfreerelay", 15) * 10 * 1000)
				return error(
						"CTxMemPool::accept() : free transaction rejected by rate limiter");
			if (fDebug)
				printf("Rate limit dFreeCount: %g => %g\n", dFreeCount,
						dFreeCount + nSize);
			dFreeCount += nSize;
		}

		// Check against previous transactions
		// This is done last to help prevent CPU exhaustion denial-of-service attacks.
		if (!tx.CheckInputs(pindexBest, state, view, true, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC,
				NULL, true, false, false)) {
			return error("CTxMemPool::accept() : CheckInputs failed %s",
					hash.ToString().c_str());
		}
	}

	// Store transaction in memory
	{
		LOCK(cs);
		if (ptxOld) {
			printf("CTxMemPool::accept() : replacing tx %s with new version\n",
					ptxOld->GetHash().ToString().c_str());
			remove(*ptxOld);
		}
		addUnchecked(hash, tx);
	}

	if (tx.nVersion == SYSCOIN_TX_VERSION) {
	    if (tx.vout.size() < 1) {
	        error("AcceptToMemoryPool() : no output in syscoin tx %s\n", tx.ToString().c_str());
	    }

 
	}

	///// are we sure this is ok when loading transactions or restoring block txes
	// If updated, erase old tx from wallet
	if (ptxOld) EraseFromWallets(ptxOld->GetHash());
	SyncWithWallets(hash, tx, NULL, true);

	printf("CTxMemPool::accept() : accepted %s (poolsz %"PRIszu")\n",
			hash.ToString().c_str(), mapTx.size());
	return true;
}

bool CTransaction::AcceptToMemoryPool(CValidationState &state, bool fCheckInputs, bool fLimitFree, bool* pfMissingInputs) {
	try {
		return mempool.accept(state, *this, fCheckInputs, fLimitFree, pfMissingInputs);
	} catch (std::runtime_error &e) {
		return state.Abort(_("System error: ") + e.what());
	}
}

bool CTransaction::RemoveFromMemoryPool(bool fRecursive) {
	try {
		return mempool.remove(*this, fRecursive);
	} catch (std::runtime_error &e) {
		return false;
	}
}

bool CTxMemPool::addUnchecked(const uint256& hash, const CTransaction &tx) {
	// Add to memory pool without checking anything.  Don't call this directly,
	// call CTxMemPool::accept to properly check the transaction first.
	{
		mapTx[hash] = tx;
		for (unsigned int i = 0; i < tx.vin.size(); i++)
			mapNextTx[tx.vin[i].prevout] = CInPoint(&mapTx[hash], i);
		nTransactionsUpdated++;
	}
	return true;
}


bool CTxMemPool::remove(const CTransaction &tx, bool fRecursive) {
	// Remove transaction from memory pool
	{
		LOCK(cs);
		uint256 hash = tx.GetHash();
		if (fRecursive) {
			for (unsigned int i = 0; i < tx.vout.size(); i++) {
				std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(
						COutPoint(hash, i));
				if (it != mapNextTx.end())
					remove(*it->second.ptx, true);
			}
		}
		if (mapTx.count(hash)) {
			BOOST_FOREACH(const CTxIn& txin, tx.vin)
				mapNextTx.erase(txin.prevout);
			mapTx.erase(hash);
			nTransactionsUpdated++;
		}
	}
	return true;
}

bool CTxMemPool::removeConflicts(const CTransaction &tx) {
	// Remove transactions which depend on inputs of tx, recursively
	LOCK(cs);
	BOOST_FOREACH(const CTxIn &txin, tx.vin) {
		std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(
				txin.prevout);
		if (it != mapNextTx.end()) {
			const CTransaction &txConflict = *it->second.ptx;
			if (txConflict != tx)
				remove(txConflict, true);
		}
	}
	return true;
}

void CTxMemPool::clear() {
	LOCK(cs);
	mapTx.clear();
	mapNextTx.clear();
	++nTransactionsUpdated;
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid) {
	vtxid.clear();

	LOCK(cs);
	vtxid.reserve(mapTx.size());
	for (map<uint256, CTransaction>::iterator mi = mapTx.begin();
			mi != mapTx.end(); ++mi)
		vtxid.push_back((*mi).first);
}

int CMerkleTx::GetDepthInMainChain(CBlockIndex* &pindexRet) const {
	if (hashBlock == 0 || nIndex == -1)
		return 0;

	// Find the block it claims to be in
	map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
	if (mi == mapBlockIndex.end())
		return 0;
	CBlockIndex* pindex = (*mi).second;
	if (!pindex || !pindex->IsInMainChain())
		return 0;

	// Make sure the merkle branch connects to this block
	if (!fMerkleVerified) {
		if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex)
				!= pindex->hashMerkleRoot)
			return 0;
		fMerkleVerified = true;
	}

	pindexRet = pindex;
	return pindexBest->nHeight - pindex->nHeight + 1;
}

int CMerkleTx::GetBlocksToMaturity() const {
	if (!IsCoinBase())
		return 0;
	if(fTestNet || fCakeNet)
		return max(0, (8 + 1) - GetDepthInMainChain());
	else
		return max(0, (COINBASE_MATURITY + 1) - GetDepthInMainChain());
}

bool CMerkleTx::AcceptToMemoryPool(bool fCheckInputs, bool fLimitFree) {
	CValidationState state;
	return CTransaction::AcceptToMemoryPool(state, fCheckInputs, fLimitFree);
}

bool CWalletTx::AcceptWalletTransaction(bool fCheckInputs) {
	{
		LOCK(mempool.cs);
		// Add previous supporting transactions first
		BOOST_FOREACH(CMerkleTx& tx, vtxPrev) {
			if (!tx.IsCoinBase()) {
				uint256 hash = tx.GetHash();
				if (!mempool.exists(hash) && pcoinsTip->HaveCoins(hash))
					tx.AcceptToMemoryPool(fCheckInputs, false);
			}
		}
		return AcceptToMemoryPool(fCheckInputs, false);
	}
	return false;
}

// Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock
bool GetTransaction(const uint256 &hash, CTransaction &txOut, uint256 &hashBlock, bool fAllowSlow) {

	CBlockIndex *pindexSlow = NULL;
	{
		LOCK(cs_main);
		{
			LOCK(mempool.cs);
			if (mempool.exists(hash)) {
				txOut = mempool.lookup(hash);
				return true;
			}
		}
	
		if (fTxIndex) {
			CDiskTxPos postx;
			if (pblocktree->ReadTxIndex(hash, postx)) {
				CAutoFile file(OpenBlockFile(postx, true), SER_DISK,
						CLIENT_VERSION);
				CBlockHeader header;
				try {
					file >> header;
					fseek(file, postx.nTxOffset, SEEK_CUR);
					file >> txOut;
				} catch (std::exception &e) {
					return error("%s() : deserialize or I/O error",
							__PRETTY_FUNCTION__);
				}
				hashBlock = header.GetHash();
				if (txOut.GetHash() != hash)
					return error("%s() : txid mismatch", __PRETTY_FUNCTION__);
				return true;
			}
		}
	
		if (fAllowSlow) { // use coin database to locate block that contains transaction, and scan it
			int nHeight = -1;
			{
				CCoinsViewCache &view = *pcoinsTip;
				CCoins coins;
				if (view.GetCoins(hash, coins))
					nHeight = coins.nHeight;
			}
			if (nHeight > 0)
				pindexSlow = FindBlockByHeight(nHeight);
		}
	}

	if (pindexSlow) {
		CBlock block;
		if (block.ReadFromDisk(pindexSlow)) {
			BOOST_FOREACH(const CTransaction &tx, block.vtx) {
				if (tx.GetHash() == hash) {
					txOut = tx;
					hashBlock = pindexSlow->GetBlockHash();
					return true;
				}
			}
		}
	}

	return false;
}

//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

static CBlockIndex* pblockindexFBBHLast;
CBlockIndex* FindBlockByHeight(int nHeight) {
	CBlockIndex *pblockindex;
	if (nHeight < nBestHeight / 2)
		pblockindex = pindexGenesisBlock;
	else
		pblockindex = pindexBest;
	if (pblockindexFBBHLast
			&& abs(nHeight - pblockindex->nHeight)
					> abs(nHeight - pblockindexFBBHLast->nHeight))
		pblockindex = pblockindexFBBHLast;
	while (pblockindex->nHeight > nHeight)
		pblockindex = pblockindex->pprev;
	while (pblockindex->nHeight < nHeight)
		pblockindex = pblockindex->pnext;
	pblockindexFBBHLast = pblockindex;
	return pblockindex;
}

bool CBlock::ReadFromDisk(const CBlockIndex* pindex) {
	if (!ReadFromDisk(pindex->GetBlockPos()))
		return false;
	if (GetHash() != pindex->GetBlockHash())
		return error("CBlock::ReadFromDisk() : GetHash() doesn't match index");
	return true;
}

void CBlockHeader::SetAuxPow(CAuxPow* pow) {
	if (pow != NULL)
		nVersion |= BLOCK_VERSION_AUXPOW;
	else
		nVersion &= ~BLOCK_VERSION_AUXPOW;
	auxpow.reset(pow);
}

uint256 static GetOrphanRoot(const CBlockHeader* pblock) {
	// Work back to the first block in the orphan chain
	while (mapOrphanBlocks.count(pblock->hashPrevBlock))
		pblock = mapOrphanBlocks[pblock->hashPrevBlock];
	return pblock->GetHash();
}

/**
 * @brief GetBlockValue Return the mining reward for a given block, this has 2 modes based on the block height due to the hard fork.
 * @param nHeight
 * @param nFees
 * @param prevHash
 * @return
 */
int64 static GetBlockValue(int nHeight, int64 nFees, uint256 prevHash) {
    int64 a,e,s;
    int64 nSubsidy = 128 * COIN;
    if(nHeight == 0)
        nSubsidy = 1024 * COIN; // genesis amount
    else if(nHeight == 1)
        nSubsidy = 364222858 * COIN; // pre-mine amount
    else if(nHeight > 259440 && nHeight <= 777840)
        nSubsidy = 96 * COIN;
    else if(nHeight > 777840 && nHeight <= 1814640)
        nSubsidy = 80 * COIN;
    else if(nHeight > 1814640 && nHeight <= 3369840)
        nSubsidy = 64 * COIN;
    else if(nHeight > 3369840 && nHeight <= 5443440)
        nSubsidy = 48 * COIN;
    else if(nHeight > 5443440 && nHeight <= 8035440)
        nSubsidy = 40 * COIN;
    else if(nHeight > 8035440 && nHeight <= 35913640)
        nSubsidy = 32 * COIN;
    else if( ( !fTestNet && !fCakeNet ) && ( nHeight > 35913640 || nHeight < 241 ) )
        nSubsidy = 0;
    else if( ( fTestNet || fCakeNet ) && ( nHeight > 35913640 ) )
        nSubsidy = 0;

    a = nSubsidy;

	e = nFees;
    s = a+e;

    if (fDebug)
		printf ("GetBlockvalue of Block %d: subsidy=%"PRI64d", fees=%"PRI64d", sum=%"PRI64d". \n", nHeight, a,e,s);
    return s;
}

static const int64 nTargetTimespan = 1 * 24 * 60 * 60; // Syscoin: 1 day
static const int64 nTargetSpacing = 60; // Syscoin: 1 minute
static const int64 nInterval = nTargetTimespan / nTargetSpacing;

//
// minimum amount of work that could possibly be required nTime after
// minimum work required was nBase
//
unsigned int ComputeMinWork(unsigned int nBase, int64 nTime) {
	// Testnet has min-difficulty blocks
	// after nTargetSpacing*2 time between blocks:
	if (fTestNet && nTime > nTargetSpacing * 2)
		return bnProofOfWorkLimit.GetCompact();

	if (fCakeNet && nTime > nTargetSpacing * 2)
		return bnProofOfWorkLimitCake.GetCompact();

	CBigNum bnResult;
	if(fCakeNet) {
		bnResult.SetCompact(nBase);
		while (nTime > 0 && bnResult < bnProofOfWorkLimitCake) {
			bnResult *= 4;
			nTime -= nTargetTimespan * 4;
		}
		if (bnResult > bnProofOfWorkLimitCake)
			bnResult = bnProofOfWorkLimitCake;		
	} else {
		bnResult.SetCompact(nBase);
		while (nTime > 0 && bnResult < bnProofOfWorkLimit) {
			// Maximum 400% adjustment...
			bnResult *= 4;
			// ... in best-case exactly 4-times-normal target time
			nTime -= nTargetTimespan * 4;
		}
		if (bnResult > bnProofOfWorkLimit)
			bnResult = bnProofOfWorkLimit;		
	}
	return bnResult.GetCompact();
}

unsigned int static KimotoGravityWell(const CBlockIndex* pindexLast,
		const CBlockHeader *pblock, uint64 TargetBlocksSpacingSeconds,
		uint64 PastBlocksMin, uint64 PastBlocksMax) {
	/* current difficulty formula - kimoto gravity well */
	const CBlockIndex *BlockLastSolved = pindexLast;
	const CBlockIndex *BlockReading = pindexLast;

	//todo look at orig code about that wierd = = that was here

	uint64 PastBlocksMass = 0;
	int64 PastRateActualSeconds = 0;
	int64 PastRateTargetSeconds = 0;
	double PastRateAdjustmentRatio = double(1);
	CBigNum PastDifficultyAverage;
	CBigNum PastDifficultyAveragePrev;
	double EventHorizonDeviation;
	double EventHorizonDeviationFast;
	double EventHorizonDeviationSlow;

	CBigNum bnPOWLimit = fCakeNet ? bnProofOfWorkLimitCake : bnProofOfWorkLimit;
	if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0
			|| (uint64) BlockLastSolved->nHeight < PastBlocksMin) {
		return bnPOWLimit.GetCompact();
	}

	for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
		if (PastBlocksMax > 0 && i > PastBlocksMax)
			break;

		PastBlocksMass++;

		if (i == 1)
			PastDifficultyAverage.SetCompact(BlockReading->nBits);
		else
			PastDifficultyAverage = ((CBigNum().SetCompact(BlockReading->nBits)
					- PastDifficultyAveragePrev) / i)
					+ PastDifficultyAveragePrev;

		PastDifficultyAveragePrev = PastDifficultyAverage;
		PastRateActualSeconds = BlockLastSolved->GetBlockTime()
				- BlockReading->GetBlockTime();
		PastRateTargetSeconds = TargetBlocksSpacingSeconds * PastBlocksMass;
		PastRateAdjustmentRatio = double(1);

		if (PastRateActualSeconds < 0)
			PastRateActualSeconds = 0;
		if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0)
			PastRateAdjustmentRatio = double(PastRateTargetSeconds)
					/ double(PastRateActualSeconds);

		EventHorizonDeviation =
				1
						+ (0.7084
								* pow((double(PastBlocksMass) / double(144)),
										-1.228));
		EventHorizonDeviationFast = EventHorizonDeviation;
		EventHorizonDeviationSlow = 1 / EventHorizonDeviation;

		if (PastBlocksMass >= PastBlocksMin) {
			if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow)
					|| (PastRateAdjustmentRatio >= EventHorizonDeviationFast)) {
				assert(BlockReading);
				break;
			}
		}
		if (BlockReading->pprev == NULL) {
			assert(BlockReading);
			break;
		}
		BlockReading = BlockReading->pprev;
	}

	CBigNum bnNew(PastDifficultyAverage);
	if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
		bnNew *= PastRateActualSeconds;
		bnNew /= PastRateTargetSeconds;
	}

	if (bnNew > bnPOWLimit)
		bnNew = bnPOWLimit;

	return bnNew.GetCompact();
}

unsigned int static GetNextWorkRequired1(const CBlockIndex* pindexLast, const CBlockHeader *pblock)
{
	CBigNum bnPOWLimit = fCakeNet ? bnProofOfWorkLimitCake : bnProofOfWorkLimit;
    unsigned int nProofOfWorkLimit = bnPOWLimit.GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    // Only change once per interval
    if ((pindexLast->nHeight+1) % nInterval != 0)
    {
        // Special difficulty rule for testnet:
        if (fTestNet || fCakeNet)
        {
            // If the new block's timestamp is more than 2 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->nTime > pindexLast->nTime + nTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % nInterval != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }

        return pindexLast->nBits;
    }

    // Go back by what we want to be 1 day worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < nInterval-1; i++)
        pindexFirst = pindexFirst->pprev;
    assert(pindexFirst);

    // Limit adjustment step
    int64 nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
	if(fDebug)
		printf("  nActualTimespan = %"PRI64d"  before bounds\n", nActualTimespan);
    if (nActualTimespan < nTargetTimespan/4)
        nActualTimespan = nTargetTimespan/4;
    if (nActualTimespan > nTargetTimespan*4)
        nActualTimespan = nTargetTimespan*4;

    // Retarget
    CBigNum bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    if (bnNew > bnPOWLimit)
        bnNew = bnPOWLimit;

    /// debug print
	if(fDebug)
	{
		printf("GetNextWorkRequired RETARGET\n");
		printf("nTargetTimespan = %"PRI64d"    nActualTimespan = %"PRI64d"\n", nTargetTimespan, nActualTimespan);
		printf("Before: %08x  %s\n", pindexLast->nBits, CBigNum().SetCompact(pindexLast->nBits).getuint256().ToString().c_str());
		printf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());
	}

    return bnNew.GetCompact();
}
// Using KGW
unsigned int static GetNextWorkRequired2(const CBlockIndex* pindexLast,
		const CBlockHeader *pblock) {
	static const int64 BlocksTargetSpacing = 60;
	uint64 PastBlocksMin = 7;
	uint64 PastBlocksMax = 98;

	return KimotoGravityWell(pindexLast, pblock, BlocksTargetSpacing,
			PastBlocksMin, PastBlocksMax);
}
unsigned int static GetNextWorkRequired(const CBlockIndex* pindexLast,
		const CBlockHeader *pblock) {
	if(HasReachedMainNetForkB2())
	{
		return GetNextWorkRequired1(pindexLast, pblock);
	}
	else
	{
		return GetNextWorkRequired2(pindexLast, pblock);	
	}

}
bool CheckProofOfWork(uint256 hash, unsigned int nBits) {
	CBigNum bnTarget;
	bnTarget.SetCompact(nBits);

	// Check range
	if ( ( bnTarget <= 0 || bnTarget > bnProofOfWorkLimit ) && !fCakeNet)
		return error("CheckProofOfWork() : nBits below minimum work");

	// Check proof of work matches claimed amount
	if (hash > bnTarget.getuint256())
		return error("CheckProofOfWork() : hash doesn't match nBits");

	return true;
}

// Return maximum amount of blocks that other nodes claim to have
int GetNumBlocksOfPeers() {
	return std::max(cPeerBlockCounts.median(),
			Checkpoints::GetTotalBlocksEstimate());
}

bool IsInitialBlockDownload() {
	if (pindexBest == NULL || fImporting || fReindex
			|| nBestHeight < Checkpoints::GetTotalBlocksEstimate())
		return true;
	static int64 nLastUpdate;
	static CBlockIndex* pindexLastBest;
	if (pindexBest != pindexLastBest) {
		pindexLastBest = pindexBest;
		nLastUpdate = GetTime();
	}
	return (GetTime() - nLastUpdate < 10
			&& pindexBest->GetBlockTime() < GetTime() - 24 * 60 * 60);
}

void static InvalidChainFound(CBlockIndex* pindexNew) {
	if (pindexNew->nChainWork > nBestInvalidWork) {
		nBestInvalidWork = pindexNew->nChainWork;
		pblocktree->WriteBestInvalidWork(CBigNum(nBestInvalidWork));
		uiInterface.NotifyBlocksChanged();
	}
	printf(
			"InvalidChainFound: invalid block=%s  height=%d  log2_work=%.8g  date=%s\n",
			pindexNew->GetBlockHash().ToString().c_str(), pindexNew->nHeight,
			log(pindexNew->nChainWork.getdouble()) / log(2.0),
			DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexNew->GetBlockTime()).c_str());
	printf(
			"InvalidChainFound:  current best=%s  height=%d  log2_work=%.8g  date=%s\n",
			hashBestChain.ToString().c_str(), nBestHeight,
			log(nBestChainWork.getdouble()) / log(2.0),
			DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexBest->GetBlockTime()).c_str());
	if (pindexBest
			&& nBestInvalidWork
					> nBestChainWork
							+ (pindexBest->GetBlockWork() * 6).getuint256())
		printf(
				"InvalidChainFound: Warning: Displayed transactions may not be correct! You may need to upgrade, or other nodes may need to upgrade.\n");
}

void static InvalidBlockFound(CBlockIndex *pindex) {
	pindex->nStatus |= BLOCK_FAILED_VALID;
	pblocktree->WriteBlockIndex(*pindex);
	setBlockIndexValid.erase(pindex);
	InvalidChainFound(pindex);
	if (pindex->pnext) {
		CValidationState stateDummy;
		ConnectBestBlock(stateDummy); // reorganise away from the failed block
	}
}

bool ConnectBestBlock(CValidationState &state) {
	do {
		CBlockIndex *pindexNewBest;
		
		{
			std::set<CBlockIndex*, CBlockIndexWorkComparator>::reverse_iterator it =
					setBlockIndexValid.rbegin();
			if (it == setBlockIndexValid.rend())
				return true;
			pindexNewBest = *it;
		}

		if (pindexNewBest == pindexBest
				|| (pindexBest
						&& pindexNewBest->nChainWork == pindexBest->nChainWork))
			return true; // nothing to do

		// check ancestry
		CBlockIndex *pindexTest = pindexNewBest;
		std::vector<CBlockIndex*> vAttach;
		do {
			if (pindexTest->nStatus & BLOCK_FAILED_MASK) {
				// mark descendants failed
				CBlockIndex *pindexFailed = pindexNewBest;
				while (pindexTest != pindexFailed) {
					pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
					setBlockIndexValid.erase(pindexFailed);
					pblocktree->WriteBlockIndex(*pindexFailed);
					pindexFailed = pindexFailed->pprev;
				}
				InvalidChainFound(pindexNewBest);
				break;
			}

			if (pindexBest == NULL
					|| pindexTest->nChainWork > pindexBest->nChainWork)
				vAttach.push_back(pindexTest);

			if (pindexTest->pprev == NULL || pindexTest->pnext != NULL) {
				reverse(vAttach.begin(), vAttach.end());
				BOOST_FOREACH(CBlockIndex *pindexSwitch, vAttach) {
					boost::this_thread::interruption_point();
					try {
						if (!SetBestChain(state, pindexSwitch))
							return false;
					} catch (std::runtime_error &e) {
						return state.Abort(_("System error: ") + e.what());
					}
				}
				return true;
			}
			pindexTest = pindexTest->pprev;
		} while (true);
	} while (true);
}

void CBlockHeader::UpdateTime(const CBlockIndex* pindexPrev) {
	nTime = max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());
	// Updating time can change work required on testnet:
	if (fTestNet || fCakeNet)
		nBits = GetNextWorkRequired(pindexPrev, this);
}

const CTxOut &CTransaction::GetOutputFor(const CTxIn& input,
		CCoinsViewCache& view) {
	const CCoins &coins = view.GetCoins(input.prevout.hash);
	assert(coins.IsAvailable(input.prevout.n));
	return coins.vout[input.prevout.n];
}

const CCoins &CTransaction::GetOutputCoinsFor(const CTxIn& input,
		CCoinsViewCache& view) {
	const CCoins &coins = view.GetCoins(input.prevout.hash);
	assert(coins.IsAvailable(input.prevout.n));
	return coins;
}

int64 CTransaction::GetValueIn(CCoinsViewCache& inputs) const {
	if (IsCoinBase())
		return 0;

	int64 nResult = 0;
	for (unsigned int i = 0; i < vin.size(); i++)
		nResult += GetOutputFor(vin[i], inputs).nValue;

	return nResult;
}

unsigned int CTransaction::GetP2SHSigOpCount(CCoinsViewCache& inputs) const {
	if (IsCoinBase())
		return 0;

	unsigned int nSigOps = 0;
	for (unsigned int i = 0; i < vin.size(); i++) {
		const CTxOut &prevout = GetOutputFor(vin[i], inputs);
		if (prevout.scriptPubKey.IsPayToScriptHash())
			nSigOps += prevout.scriptPubKey.GetSigOpCount(vin[i].scriptSig);
	}
	return nSigOps;
}

void CTransaction::UpdateCoins(CValidationState &state, CCoinsViewCache &inputs,
		CTxUndo &txundo, int nHeight, const uint256 &txhash) const {
	// mark inputs spent
	if (!IsCoinBase()) {
		BOOST_FOREACH(const CTxIn &txin, vin) {
			CCoins &coins = inputs.GetCoins(txin.prevout.hash);
			CTxInUndo undo;
			assert(coins.Spend(txin.prevout, undo));
			txundo.vprevout.push_back(undo);
		}
	}

	// add outputs
	assert(inputs.SetCoins(txhash, CCoins(*this, nHeight)));
}

bool CTransaction::HaveInputs(CCoinsViewCache &inputs) const {
	if (!IsCoinBase()) {
		// first check whether information about the prevout hash is available
		for (unsigned int i = 0; i < vin.size(); i++) {
			const COutPoint &prevout = vin[i].prevout;
			if (!inputs.HaveCoins(prevout.hash))
				return false;
		}

		// then check whether the actual outputs are available
		for (unsigned int i = 0; i < vin.size(); i++) {
			const COutPoint &prevout = vin[i].prevout;
			const CCoins &coins = inputs.GetCoins(prevout.hash);
			if (!coins.IsAvailable(prevout.n))
				return false;
		}
	}
	return true;
}

bool CScriptCheck::operator()() const {
	const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
	if (!VerifyScript(scriptSig, scriptPubKey, *ptxTo, nIn, nFlags, nHashType))
		return error("CScriptCheck() : %s VerifySignature failed",
				ptxTo->GetHash().ToString().c_str());
	return true;
}

bool VerifySignature(const CCoins& txFrom, const CTransaction& txTo,
		unsigned int nIn, unsigned int flags, int nHashType) {
	return CScriptCheck(txFrom, txTo, nIn, flags, nHashType)();
}

bool CTransaction::CheckInputs(CBlockIndex *pindex, CValidationState &state, CCoinsViewCache &inputs,
		bool fScriptChecks, unsigned int flags, std::vector<CScriptCheck> *pvChecks, bool bJustCheck, bool fBlock, bool fMiner) const {
	
	if (!IsCoinBase()) {
		if (pvChecks)
			pvChecks->reserve(vin.size());

		// This doesn't trigger the DoS code on purpose; if it did, it would make it easier
		// for an attacker to attempt to split the network.
		if (!HaveInputs(inputs))
			return state.Invalid(
					error("CheckInputs() : %s inputs unavailable",
							GetHash().ToString().c_str()));

		// While checking, GetBestBlock() refers to the parent block.
		// This is also true for mempool checks.
		int nSpendHeight = inputs.GetBestBlock()->nHeight + 1;
		int64 nValueIn = 0;
		int64 nFees = 0;
		for (unsigned int i = 0; i < vin.size(); i++) {
			const COutPoint &prevout = vin[i].prevout;
			const CCoins &coins = inputs.GetCoins(prevout.hash);

			// If prev is coinbase, check that it's matured
			if (coins.IsCoinBase()) {
                if (nSpendHeight - coins.nHeight < ( fTestNet || fCakeNet ? 8 : COINBASE_MATURITY) )
					return state.Invalid(
							error(
									"CheckInputs() : tried to spend coinbase at depth %d",
									nSpendHeight - coins.nHeight));
			}

			// Check for negative or overflow input values
			nValueIn += coins.vout[prevout.n].nValue;
			if (!MoneyRange(coins.vout[prevout.n].nValue)
					|| !MoneyRange(nValueIn))
				return state.DoS(100,
						error("CheckInputs() : txin values out of range"));
		}

		vector<vector<unsigned char> > vvchArgs;
		int op;
		int nOut;

		if(HasReachedMainNetForkB2())
		{
			if(DecodeAliasTx(*this, op, nOut, vvchArgs, -1))
			{
				if (!CheckAliasInputs(pindex, *this, state, inputs, fBlock, fMiner, bJustCheck))
					return false;
				
			}
			else if(DecodeOfferTx(*this, op, nOut, vvchArgs, -1))
			{	
				if (!CheckOfferInputs(pindex, *this, state, inputs, fBlock, fMiner, bJustCheck))
					return false;		 
			}
			else if(DecodeCertTx(*this, op, nOut, vvchArgs, -1))
			{
				if (!CheckCertInputs(pindex, *this, state, inputs, fBlock, fMiner, bJustCheck))
					return false;			
			}
			else if(DecodeEscrowTx(*this, op, nOut, vvchArgs, -1))
			{
				if (!CheckEscrowInputs(pindex, *this, state, inputs, fBlock, fMiner, bJustCheck))
					return false;			
			}
			else if(DecodeMessageTx(*this, op, nOut, vvchArgs, -1))
			{
				if (!CheckMessageInputs(pindex, *this, state, inputs, fBlock, fMiner, bJustCheck))
					return false;			
			}
		}

		if (nValueIn < GetValueOut())
			return state.DoS(100,
					error("CheckInputs() : %s value in < value out",
							GetHash().ToString().c_str()));

		// Tally transaction fees
		int64 nTxFee = nValueIn - GetValueOut();
		if (nTxFee < 0)
			return state.DoS(100,
					error("CheckInputs() : %s nTxFee < 0",
							GetHash().ToString().c_str()));

		// syscoin: enforce transaction fees for every block
		if (nTxFee < GetMinFee())
			return state.DoS(100,
					error(
							"CheckInputs() : %s not paying required fee=%s, paid=%s",
							GetHash().ToString().substr(0, 10).c_str(),
							FormatMoney(GetMinFee()).c_str(),
							FormatMoney(nTxFee).c_str()));

		// add txn fee to existing fees and verify that total fees within range
		nFees += nTxFee;
		if (!MoneyRange(nFees))
			return state.DoS(100, error("CheckInputs() : nFees out of range"));

		// The first loop above does all the inexpensive checks.
		// Only if ALL inputs pass do we perform expensive ECDSA signature checks.
		// Helps prevent CPU exhaustion attacks.

		// Skip ECDSA signature verification when connecting blocks
		// before the last block chain checkpoint. This is safe because block merkle hashes are
		// still computed and checked, and any change will be caught at the next checkpoint.
		if (fScriptChecks) {
			for (unsigned int i = 0; i < vin.size(); i++) {
				const COutPoint &prevout = vin[i].prevout;
				const CCoins &coins = inputs.GetCoins(prevout.hash);

				// Verify signature
				CScriptCheck check(coins, *this, i, flags, 0);
				if (pvChecks) {
					pvChecks->push_back(CScriptCheck());
					check.swap(pvChecks->back());
				} else if (!check()) {
					if (flags & SCRIPT_VERIFY_STRICTENC) {
						// For now, check whether the failure was caused by non-canonical
						// encodings or not; if so, don't trigger DoS protection.
						CScriptCheck check(coins, *this, i,
								flags & (~SCRIPT_VERIFY_STRICTENC), 0);
						if (check())
							return state.Invalid();
					}
					return state.DoS(100, false);
				}
			}
		}
	}

	return true;
}

bool DisconnectAlias( CBlockIndex *pindex, const CTransaction &tx, int op, vector<vector<unsigned char> > &vvchArgs ) {
	
	TRY_LOCK(cs_main, cs_maintry);
	string opName = aliasFromOp(op);
	vector<CAliasIndex> vtxPos;
	if (!paliasdb->ReadAlias(vvchArgs[0], vtxPos))
		return error("DisconnectBlock() : failed to read from alias DB for %s %s\n",
				opName.c_str(), stringFromVch(vvchArgs[0]).c_str());

	// vtxPos might be empty if we pruned expired transactions.  However, it should normally still not
	// be empty, since a reorg cannot go that far back.  Be safe anyway and do not try to pop if empty.
	if (vtxPos.size()) {
		if (vtxPos.back().txHash == tx.GetHash())
			vtxPos.pop_back();
		// TODO validate that the first pos is the current tx pos
	}
	
	if(!paliasdb->WriteAlias(vvchArgs[0], vtxPos))
		return error("DisconnectBlock() : failed to write to alias DB");
	if(fDebug)
		printf("DISCONNECTED ALIAS TXN: alias=%s op=%s hash=%s  height=%d\n",
		stringFromVch(vvchArgs[0]).c_str(),
		aliasFromOp(op).c_str(),
		tx.GetHash().ToString().c_str(),
		pindex->nHeight);

	return true;
}

bool DisconnectOffer( CBlockIndex *pindex, const CTransaction &tx, int op, vector<vector<unsigned char> > &vvchArgs ) {
    string opName = offerFromOp(op);
	
	COffer theOffer(tx);
	if (theOffer.IsNull())
		error("CheckOfferInputs() : null offer object");

	TRY_LOCK(cs_main, cs_maintry);
    // make sure a DB record exists for this offer
    vector<COffer> vtxPos;
    if (!pofferdb->ReadOffer(vvchArgs[0], vtxPos))
        return error("DisconnectBlock() : failed to read from offer DB for %s %s\n",
        		opName.c_str(), stringFromVch(vvchArgs[0]).c_str());

    if(op == OP_OFFER_ACCEPT ) {
    	vector<unsigned char> vvchOfferAccept = vvchArgs[1];
    	COfferAccept theOfferAccept;

    	// make sure the offeraccept is also in the serialized offer in the txn
    	if(!theOffer.GetAcceptByHash(vvchOfferAccept, theOfferAccept))
            return error("DisconnectBlock() : not found in offer for offer accept %s %s\n",
            		opName.c_str(), HexStr(vvchOfferAccept).c_str());
		
		
        // make sure offer accept db record already exists
        if (pofferdb->ExistsOfferAccept(vvchOfferAccept))
        	pofferdb->EraseOfferAccept(vvchOfferAccept);
		
    }

    // vtxPos might be empty if we pruned expired transactions.  However, it should normally still not
    // be empty, since a reorg cannot go that far back.  Be safe anyway and do not try to pop if empty.
    if (vtxPos.size()) {
        if(vtxPos.back().txHash == tx.GetHash())
            vtxPos.pop_back();
    }

    // write new offer state to db
	if(!pofferdb->WriteOffer(vvchArgs[0], vtxPos))
		return error("DisconnectBlock() : failed to write to offer DB");
	
	if(fDebug)
		printf("DISCONNECTED offer TXN: offer=%s op=%s hash=%s  height=%d\n",
			stringFromVch(vvchArgs[0]).c_str(),
			aliasFromOp(op).c_str(),
			tx.GetHash().ToString().c_str(),
			pindex->nHeight);

	return true;
}

bool DisconnectCertificate( CBlockIndex *pindex, const CTransaction &tx, int op, vector<vector<unsigned char> > &vvchArgs ) {
	string opName = certFromOp(op);
	
	CCert theCert(tx);
	if (theCert.IsNull())
		error("CheckOfferInputs() : null  object");


	TRY_LOCK(cs_main, cs_maintry);
	// make sure a DB record exists for this cert
	vector<CCert> vtxPos;
	if (!pcertdb->ReadCert(vvchArgs[0], vtxPos))
		return error("DisconnectBlock() : failed to read from certificate DB for %s %s\n",
				opName.c_str(), stringFromVch(vvchArgs[0]).c_str());

	// vtxPos might be empty if we pruned expired transactions.  However, it should normally still not
	// be empty, since a reorg cannot go that far back.  Be safe anyway and do not try to pop if empty.
	if (vtxPos.size()) {
		if(vtxPos.back().txHash == tx.GetHash())
			vtxPos.pop_back();
		// TODO validate that the first pos is the current tx pos
	}

	// write new offer state to db
	if(!pcertdb->WriteCert(vvchArgs[0], vtxPos))
		return error("DisconnectBlock() : failed to write to offer DB");
	if(fDebug)
		printf("DISCONNECTED CERT TXN: title=%s hash=%s height=%d\n",
		   stringFromVch(vvchArgs[0]).c_str(),
			tx.GetHash().ToString().c_str(),
			pindex->nHeight);

	return true;
}

bool DisconnectEscrow( CBlockIndex *pindex, const CTransaction &tx, int op, vector<vector<unsigned char> > &vvchArgs ) {
	string opName = escrowFromOp(op);
	
	CEscrow theEscrow(tx);
	if (theEscrow.IsNull())
		error("CheckOfferInputs() : null  object");


	TRY_LOCK(cs_main, cs_maintry);
	// make sure a DB record exists for this cert
	vector<CEscrow> vtxPos;
	if (!pescrowdb->ReadEscrow(vvchArgs[0], vtxPos))
		return error("DisconnectBlock() : failed to read from escrow DB for %s %s\n",
				opName.c_str(), stringFromVch(vvchArgs[0]).c_str());

	// vtxPos might be empty if we pruned expired transactions.  However, it should normally still not
	// be empty, since a reorg cannot go that far back.  Be safe anyway and do not try to pop if empty.
	if (vtxPos.size()) {
		if(vtxPos.back().txHash == tx.GetHash())
			vtxPos.pop_back();
		// TODO validate that the first pos is the current tx pos
	}

	// write new escrow state to db
	if(!pescrowdb->WriteEscrow(vvchArgs[0], vtxPos))
		return error("DisconnectBlock() : failed to write to escrow DB");
	if(fDebug)
		printf("DISCONNECTED ESCROW TXN: escrow=%s hash=%s height=%d\n",
		   stringFromVch(vvchArgs[0]).c_str(),
			tx.GetHash().ToString().c_str(),
			pindex->nHeight);

	return true;
}

bool DisconnectMessage( CBlockIndex *pindex, const CTransaction &tx, int op, vector<vector<unsigned char> > &vvchArgs ) {
	string opName = messageFromOp(op);
	
	CMessage theMessage(tx);
	if (theMessage.IsNull())
		error("CheckOfferInputs() : null  object");


	TRY_LOCK(cs_main, cs_maintry);
	// make sure a DB record exists for this cert
	vector<CMessage> vtxPos;
	if (!pmessagedb->ReadMessage(vvchArgs[0], vtxPos))
		return error("DisconnectBlock() : failed to read from message DB for %s %s\n",
				opName.c_str(), stringFromVch(vvchArgs[0]).c_str());

	// vtxPos might be empty if we pruned expired transactions.  However, it should normally still not
	// be empty, since a reorg cannot go that far back.  Be safe anyway and do not try to pop if empty.
	if (vtxPos.size()) {
		if(vtxPos.back().txHash == tx.GetHash())
			vtxPos.pop_back();
		// TODO validate that the first pos is the current tx pos
	}

	// write new message state to db
	if(!pmessagedb->WriteMessage(vvchArgs[0], vtxPos))
		return error("DisconnectBlock() : failed to write to message DB");
	if(fDebug)
		printf("DISCONNECTED MESSAGE TXN: message=%s hash=%s height=%d\n",
		   stringFromVch(vvchArgs[0]).c_str(),
			tx.GetHash().ToString().c_str(),
			pindex->nHeight);

	return true;
}
bool CBlock::DisconnectBlock(CValidationState &state, CBlockIndex *pindex, CCoinsViewCache &view, bool *pfClean) {
	assert(pindex == view.GetBestBlock());

	if (pfClean)
		*pfClean = false;
	bool fClean = true;

	CBlockUndo blockUndo;
	CDiskBlockPos pos = pindex->GetUndoPos();
	if (pos.IsNull())
		return error("DisconnectBlock() : no undo data available");
	if (!blockUndo.ReadFromDisk(pos, pindex->pprev->GetBlockHash()))
		return error("DisconnectBlock() : failure reading undo data");

	if (blockUndo.vtxundo.size() + 1 != vtx.size())
		return error("DisconnectBlock() : block and undo data inconsistent");

	// undo transactions in reverse order
	for (int i = vtx.size() - 1; i >= 0; i--) {
		const CTransaction &tx = vtx[i];
		uint256 hash = tx.GetHash();

		// check that all outputs are available
		if (!view.HaveCoins(hash)) {
			fClean =
					fClean
							&& error(
									"DisconnectBlock() : outputs still spent? database corrupted");
			view.SetCoins(hash, CCoins());
		}
		CCoins &outs = view.GetCoins(hash);

		CCoins outsBlock = CCoins(tx, pindex->nHeight);
		// The CCoins serialization does not serialize negative numbers.
		// No network rules currently depend on the version here, so an inconsistency is harmless
		// but it must be corrected before txout nversion ever influences a network rule.
		if (outsBlock.nVersion < 0)
			outs.nVersion = outsBlock.nVersion;
		if (outs != outsBlock)
			fClean =
					fClean
							&& error(
									"DisconnectBlock() : added transaction mismatch? database corrupted");
		// remove outputs
		outs = CCoins();

	    if (tx.nVersion == SYSCOIN_TX_VERSION && HasReachedMainNetForkB2()) {
		    vector<vector<unsigned char> > vvchArgs;
		    int op, nOut;
			if(DecodeAliasTx(tx, op, nOut, vvchArgs, -1))
			{
				DisconnectAlias(pindex, tx, op, vvchArgs);	
			}
			else if(DecodeOfferTx(tx, op, nOut, vvchArgs, -1))
			{
				DisconnectOffer(pindex, tx, op, vvchArgs); 
			}
			else if(DecodeCertTx(tx, op, nOut, vvchArgs, -1))
			{
				DisconnectCertificate(pindex, tx, op, vvchArgs);
				
			}
			else if(DecodeEscrowTx(tx, op, nOut, vvchArgs, -1))
			{
				DisconnectEscrow(pindex, tx, op, vvchArgs);	
			}
			else if(DecodeMessageTx(tx, op, nOut, vvchArgs, -1))
			{
				DisconnectMessage(pindex, tx, op, vvchArgs);	
			}
		}

		// restore inputs
		if (i > 0) { // not coinbases
			const CTxUndo &txundo = blockUndo.vtxundo[i - 1];

			if (txundo.vprevout.size() != tx.vin.size())
				return error(
						"DisconnectBlock() : transaction and undo data inconsistent");

			for (unsigned int j = tx.vin.size(); j-- > 0;) {
				const COutPoint &out = tx.vin[j].prevout;
				const CTxInUndo &undo = txundo.vprevout[j];
				CCoins coins;

				view.GetCoins(out.hash, coins); // this can fail if the prevout was already entirely spent
				if (undo.nHeight != 0) {
					// undo data contains height: this is the last output of the prevout tx being spent
					if (!coins.IsPruned())
						fClean =
								fClean
										&& error(
												"DisconnectBlock() : undo data overwriting existing transaction");
					coins = CCoins();
					coins.fCoinBase = undo.fCoinBase;
					coins.nHeight = undo.nHeight;
					coins.nVersion = undo.nVersion;
				} else {
					if (coins.IsPruned())
						fClean =
								fClean
										&& error(
												"DisconnectBlock() : undo data adding output to missing transaction");
				}

				if (coins.IsAvailable(out.n))
					fClean =
							fClean
									&& error(
											"DisconnectBlock() : undo data overwriting existing output");
				if (coins.vout.size() < out.n + 1)
					coins.vout.resize(out.n + 1);
				coins.vout[out.n] = undo.txout;

				if (!view.SetCoins(out.hash, coins))
					return error(
							"DisconnectBlock() : cannot restore coin inputs");
			}
		}
	}

	// move best block pointer to prevout block
	view.SetBestBlock(pindex->pprev);

	if (pfClean) {
		*pfClean = fClean;
		return true;
	} else {
		return fClean;
	}
}

void static FlushBlockFile(bool fFinalize = false) {
	LOCK(cs_LastBlockFile);

	CDiskBlockPos posOld(nLastBlockFile, 0);

	FILE *fileOld = OpenBlockFile(posOld);
	if (fileOld) {
		if (fFinalize)
			TruncateFile(fileOld, infoLastBlockFile.nSize);
		FileCommit(fileOld);
		fclose(fileOld);
	}

	fileOld = OpenUndoFile(posOld);
	if (fileOld) {
		if (fFinalize)
			TruncateFile(fileOld, infoLastBlockFile.nUndoSize);
		FileCommit(fileOld);
		fclose(fileOld);
	}
}

bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos,
		unsigned int nAddSize);

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck() {
	RenameThread("bitcoin-scriptch");
	scriptcheckqueue.Thread();
}

bool CBlock::ConnectBlock(CValidationState &state, CBlockIndex* pindex,
		CCoinsViewCache &view, bool fJustCheck) {
//	printf( "*** ConnectBlock height %d %s\n", pindex->nHeight, fJustCheck ? "JUSTCHECK" : "" );

	// Check it again in case a previous version let a bad block in
	if (!CheckBlock(state, pindex, !fJustCheck, !fJustCheck))
		return false;

	// verify that the view's current state corresponds to the previous block
	assert(pindex->pprev == view.GetBestBlock());

	// Special case for the genesis block, skipping connection of its transactions
	// (its coinbase is unspendable)
	if (GetHash() == hashGenesisBlock) {
		view.SetBestBlock(pindex);
		pindexGenesisBlock = pindex;
		return true;
	}

	bool fScriptChecks = pindex->nHeight >= Checkpoints::GetTotalBlocksEstimate();

	// Do not allow blocks that contain transactions which 'overwrite' older transactions,
	// unless those are already completely spent.
	// If such overwrites are allowed, coinbases and transactions depending upon those
	// can be duplicated to remove the ability to spend the first instance -- even after
	// being sent to another address.
	// See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
	// This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
	// already refuses previously-known transaction ids entirely.
	// This rule was originally applied all blocks whose timestamp was after October 1, 2012, 0:00 UTC.
	// Now that the whole chain is irreversibly beyond that time it is applied to all blocks,
	// this prevents exploiting the issue against nodes in their initial block download.
	bool fEnforceBIP30 = true;

	if (fEnforceBIP30) {
		for (unsigned int i = 0; i < vtx.size(); i++) {
			uint256 hash = GetTxHash(i);
			if (view.HaveCoins(hash) && !view.GetCoins(hash).IsPruned())
				return state.DoS(100,
						error( "ConnectBlock() : tried to overwrite transaction"));
		}
	}

	// BIP16 didn't become active until Oct 1 2012
	int64 nBIP16SwitchTime = 1349049600;
	bool fStrictPayToScriptHash = (pindex->nTime >= nBIP16SwitchTime);

	unsigned int flags =
			SCRIPT_VERIFY_NOCACHE
					| (fStrictPayToScriptHash ?
							SCRIPT_VERIFY_P2SH : SCRIPT_VERIFY_NONE);

	CBlockUndo blockundo;

	CCheckQueueControl<CScriptCheck> control(
			fScriptChecks && nScriptCheckThreads ? &scriptcheckqueue : NULL);

	int64 nStart = GetTimeMicros();
	int nInputs = 0;
	int64 nFees = 0;
	unsigned int nSigOps = 0;
	CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(vtx.size()));
	std::vector<std::pair<uint256, CDiskTxPos> > vPos;
	vPos.reserve(vtx.size());
	for (unsigned int i = 0; i < vtx.size(); i++) {
		const CTransaction &tx = vtx[i];

		nInputs += tx.vin.size();
		nSigOps += tx.GetLegacySigOpCount();
		if (nSigOps > MAX_BLOCK_SIGOPS)
			return state.DoS(100, error("ConnectBlock() : too many sigops"));

		if (!tx.IsCoinBase()) {
			if (!tx.HaveInputs(view))
				return state.DoS(100,
						error("ConnectBlock() : inputs missing/spent"));

			if (fStrictPayToScriptHash) {
				// Add in sigops done by pay-to-script-hash inputs;
				// this is to prevent a "rogue miner" from creating
				// an incredibly-expensive-to-validate block.
				nSigOps += tx.GetP2SHSigOpCount(view);
				if (nSigOps > MAX_BLOCK_SIGOPS)
					return state.DoS(100,
							error("ConnectBlock() : too many sigops"));
			}

			nFees += tx.GetValueIn(view) - tx.GetValueOut();

			std::vector<CScriptCheck> vChecks;

			if (!tx.CheckInputs(pindex, state, view, fScriptChecks, flags, nScriptCheckThreads ? &vChecks : NULL, fJustCheck, true, false))
				return false;

			control.Add(vChecks);
		}

		CTxUndo txundo;
		tx.UpdateCoins(state, view, txundo, pindex->nHeight, GetTxHash(i));
		if (!tx.IsCoinBase())
			blockundo.vtxundo.push_back(txundo);

		vPos.push_back(std::make_pair(GetTxHash(i), pos));
		pos.nTxOffset += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);
	}

	int64 nTime = GetTimeMicros() - nStart;
	if (fBenchmark)
		printf("- Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin)\n",
				(unsigned) vtx.size(), 0.001 * nTime,
				0.001 * nTime / vtx.size(),
				nInputs <= 1 ? 0 : 0.001 * nTime / (nInputs - 1));

		int64 bValue = GetBlockValue(pindex->nHeight, nFees, 0);

		if (!HasReachedMainNetForkB2())
		    bValue += (bValue * 8); // 800% float till fork

		if (nFees >= 0 && vtx[0].GetValueOut()
				> bValue
                && pindex->nHeight > 1) // blocks 0 (genesis) and 1 (premine) have no max restrictions
		{
			return state.DoS(100,
						error( "ConnectBlock() : coinbase pays too much for %d (actual=%"PRI64d" vs limit=%"PRI64d")",
								pindex->nHeight, vtx[0].GetValueOut(),
								bValue));
			
		}
    if(nFees < 0) {
        std::string strHash = pindex->GetBlockHash().ToString();
        uint256 hash(strHash);
    
        if (mapBlockIndex.count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    
        CBlock block;
        CBlockIndex* pblockindex = mapBlockIndex[hash];
        block.ReadFromDisk(pblockindex);
    
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << block;
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return printf("%s", strHex.c_str());
    }

	if (!control.Wait())
		return state.DoS(100, false);
	int64 nTime2 = GetTimeMicros() - nStart;
	if (fBenchmark)
		printf("- Verify %u txins: %.2fms (%.3fms/txin)\n", nInputs - 1,
				0.001 * nTime2,
				nInputs <= 1 ? 0 : 0.001 * nTime2 / (nInputs - 1));

	if (fJustCheck)
		return true;

	// Write undo information to disk
	if (pindex->GetUndoPos().IsNull()
			|| (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS) {
		if (pindex->GetUndoPos().IsNull()) {
			CDiskBlockPos pos;
			if (!FindUndoPos(state, pindex->nFile, pos,
					::GetSerializeSize(blockundo, SER_DISK, CLIENT_VERSION)
							+ 40))
				return error("ConnectBlock() : FindUndoPos failed");
			if (!blockundo.WriteToDisk(pos, pindex->pprev->GetBlockHash()))
				return state.Abort(_("Failed to write undo data"));

			// update nUndoPos in block index
			pindex->nUndoPos = pos.nPos;
			pindex->nStatus |= BLOCK_HAVE_UNDO;
		}

		pindex->nStatus = (pindex->nStatus & ~BLOCK_VALID_MASK)
				| BLOCK_VALID_SCRIPTS;

		if (!pblocktree->WriteBlockIndex(*pindex))
			return state.Abort(_("Failed to write block index"));
	}

	if (fTxIndex)
		if (!pblocktree->WriteTxIndex(vPos))
			return state.Abort(_("Failed to write transaction index"));

	// add this block to the view's block chain
	assert(view.SetBestBlock(pindex));

	// Watch for transactions paying to me
	for (unsigned int i = 0; i < vtx.size(); i++)
		SyncWithWallets(GetTxHash(i), vtx[i], this, true);

	return true;
}
bool SetBestChain(CValidationState &state, CBlockIndex* pindexNew) {
	// All modifications to the coin state will be done in this cache.
	// Only when all have succeeded, we push it to pcoinsTip.
	CCoinsViewCache view(*pcoinsTip, true);

	// Find the fork (typically, there is none)
	CBlockIndex* pfork = view.GetBestBlock();
	CBlockIndex* plonger = pindexNew;
	while (pfork && pfork != plonger) {
		while (plonger->nHeight > pfork->nHeight) {
			plonger = plonger->pprev;
			assert(plonger != NULL);
		}
		if (pfork == plonger)
			break;
		pfork = pfork->pprev;
		assert(pfork != NULL);
	}

	// List of what to disconnect (typically nothing)
	vector<CBlockIndex*> vDisconnect;
	for (CBlockIndex* pindex = view.GetBestBlock(); pindex != pfork; pindex =
			pindex->pprev)
		vDisconnect.push_back(pindex);

	// List of what to connect (typically only pindexNew)
	vector<CBlockIndex*> vConnect;
	for (CBlockIndex* pindex = pindexNew; pindex != pfork;
			pindex = pindex->pprev)
		vConnect.push_back(pindex);
	reverse(vConnect.begin(), vConnect.end());

	if (vDisconnect.size() > 0) {
		printf("REORGANIZE: Disconnect %"PRIszu" blocks; %s..\n",
				vDisconnect.size(), pfork->GetBlockHash().ToString().c_str());
		printf("REORGANIZE: Connect %"PRIszu" blocks; ..%s\n", vConnect.size(),
				pindexNew->GetBlockHash().ToString().c_str());
	}

	// Disconnect shorter branch
	vector<CTransaction> vResurrect;
	BOOST_FOREACH(CBlockIndex* pindex, vDisconnect) {
		CBlock block;
		if (!block.ReadFromDisk(pindex))
			return state.Abort(_("Failed to read block"));
		int64 nStart = GetTimeMicros();
		if (!block.DisconnectBlock(state, pindex, view))
			return error("SetBestBlock() : DisconnectBlock %s failed",
					pindex->GetBlockHash().ToString().c_str());
		if (fBenchmark)
			printf("- Disconnect: %.2fms\n",
					(GetTimeMicros() - nStart) * 0.001);

		// Queue memory transactions to resurrect.
		// We only do this for blocks after the last checkpoint (reorganisation before that
		// point should only happen with -reindex/-loadblock, or a misbehaving peer.
		BOOST_FOREACH(const CTransaction& tx, block.vtx)
			if (!tx.IsCoinBase()
					&& pindex->nHeight > Checkpoints::GetTotalBlocksEstimate())
				vResurrect.push_back(tx);
	}

	// Connect longer branch
	vector<CTransaction> vDelete;
	BOOST_FOREACH(CBlockIndex *pindex, vConnect) {
		CBlock block;
		if (!block.ReadFromDisk(pindex))
			return state.Abort(_("Failed to read block"));
		int64 nStart = GetTimeMicros();
		if (!block.ConnectBlock(state, pindex, view)) {
			if (state.IsInvalid()) {
				InvalidChainFound(pindexNew);
				InvalidBlockFound(pindex);
			}
			return error("SetBestBlock() : ConnectBlock %s failed",
					pindex->GetBlockHash().ToString().c_str());
		}
		if (fBenchmark)
			printf("- Connect: %.2fms\n", (GetTimeMicros() - nStart) * 0.001);

		// Queue memory transactions to delete
		BOOST_FOREACH(const CTransaction& tx, block.vtx)
			vDelete.push_back(tx);
	}

	// Flush changes to global coin state
	int64 nStart = GetTimeMicros();
	int nModified = view.GetCacheSize();
	assert(view.Flush());
	assert(paliasdb->Flush());
	assert(pofferdb->Flush());
	assert(pcertdb->Flush());
	assert(pescrowdb->Flush());
	int64 nTime = GetTimeMicros() - nStart;
	if (fBenchmark)
		printf("- Flush %i transactions: %.2fms (%.4fms/tx)\n", nModified,
				0.001 * nTime, 0.001 * nTime / nModified);

	// Make sure it's successfully written to disk before changing memory structure
	bool fIsInitialDownload = IsInitialBlockDownload();
	if (!fIsInitialDownload || pcoinsTip->GetCacheSize() > nCoinCacheSize) {
		// Typical CCoins structures on disk are around 100 bytes in size.
		// Pushing a new one to the database can cause it to be written
		// twice (once in the log, and once in the tables). This is already
		// an overestimation, as most will delete an existing entry or
		// overwrite one. Still, use a conservative safety factor of 2.
		if (!CheckDiskSpace(100 * 2 * 2 * pcoinsTip->GetCacheSize()))
			return state.Error();
		FlushBlockFile();
		pblocktree->Sync();
		if (!pcoinsTip->Flush())
			return state.Abort(_("Failed to write to coin database"));
	}

	// At this point, all changes have been done to the database.
	// Proceed by updating the memory structures.

	// Disconnect shorter branch
	BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
		if (pindex->pprev)
			pindex->pprev->pnext = NULL;

	// Connect longer branch
	BOOST_FOREACH(CBlockIndex* pindex, vConnect)
		if (pindex->pprev)
			pindex->pprev->pnext = pindex;

	// Resurrect memory transactions that were in the disconnected branch
	BOOST_FOREACH(CTransaction& tx, vResurrect) {
		// ignore validation errors in resurrected transactions
		CValidationState stateDummy;
		if (!tx.AcceptToMemoryPool(stateDummy, true, false))
			mempool.remove(tx, true);
	}

	// Delete redundant memory transactions that are in the connected branch
	BOOST_FOREACH(CTransaction& tx, vDelete) {
		mempool.remove(tx);
		mempool.removeConflicts(tx);
	}

	// Update best block in wallet (so we can detect restored wallets)
	if ((pindexNew->nHeight % 20160) == 0
			|| (!fIsInitialDownload && (pindexNew->nHeight % 144) == 0)) {
		const CBlockLocator locator(pindexNew);
		::SetBestChain(locator);
	}

	// New best block
	hashBestChain = pindexNew->GetBlockHash();
	pindexBest = pindexNew;
	pblockindexFBBHLast = NULL;
	nBestHeight = pindexBest->nHeight;
	nBestChainWork = pindexNew->nChainWork;
	nTimeBestReceived = GetTime();
	nTransactionsUpdated++;
	printf(
			"SetBestChain: new best=%s  height=%d  log2_work=%.8g  tx=%lu  date=%s progress=%f\n",
			hashBestChain.ToString().c_str(), nBestHeight,
			log(nBestChainWork.getdouble()) / log(2.0),
			(unsigned long) pindexNew->nChainTx,
			DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexBest->GetBlockTime()).c_str(),
			Checkpoints::GuessVerificationProgress(pindexBest));

	// Check the version of the last 100 blocks to see if we need to upgrade:
	if (!fIsInitialDownload) {
		int nUpgraded = 0;
		const CBlockIndex* pindex = pindexBest;
		for (int i = 0; i < 100 && pindex != NULL; i++) {
			// mask out the high bits of nVersion;
			// since they indicate merged mining information
			if ((pindex->nVersion & 0xff) > CBlock::CURRENT_VERSION)
				++nUpgraded;
			pindex = pindex->pprev;
		}
		if (nUpgraded > 0)
			printf("SetBestChain: %d of last 100 blocks above version %d\n",
					nUpgraded, CBlock::CURRENT_VERSION);
		if (nUpgraded > 100 / 2)
			// strMiscWarning is read by GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
			strMiscWarning = _(
					"Warning: This version is obsolete, upgrade required!");
	}

	std::string strCmd = GetArg("-blocknotify", "");

	if (!fIsInitialDownload && !strCmd.empty()) {
		boost::replace_all(strCmd, "%s", hashBestChain.GetHex());
		boost::thread t(runCommand, strCmd); // thread runs free
	}

	return true;
}

bool CBlock::AddToBlockIndex(CValidationState &state,
		const CDiskBlockPos &pos) {
	// Check for duplicate
	uint256 hash = GetHash();
	if (mapBlockIndex.count(hash))
		return state.Invalid(
				error("AddToBlockIndex() : %s already exists",
						hash.ToString().c_str()));

	// Construct new block index object
	CBlockIndex* pindexNew = new CBlockIndex(*this);
	assert(pindexNew);
	map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(
			make_pair(hash, pindexNew)).first;
	pindexNew->phashBlock = &((*mi).first);
	map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(
			hashPrevBlock);
	if (miPrev != mapBlockIndex.end()) {
		pindexNew->pprev = (*miPrev).second;
		pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
	}
	pindexNew->nTx = vtx.size();
	pindexNew->nChainWork =
			(pindexNew->pprev ? pindexNew->pprev->nChainWork : 0)
					+ pindexNew->GetBlockWork().getuint256();
	pindexNew->nChainTx = (pindexNew->pprev ? pindexNew->pprev->nChainTx : 0)
			+ pindexNew->nTx;
	pindexNew->nFile = pos.nFile;
	pindexNew->nDataPos = pos.nPos;
	pindexNew->nUndoPos = 0;
	pindexNew->nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
	setBlockIndexValid.insert(pindexNew);

	/* write both the immutible data (CDiskBlockIndex) and the mutable data (BlockIndex) */
	if (!pblocktree->WriteDiskBlockIndex(
			CDiskBlockIndex(pindexNew, this->auxpow))
			|| !pblocktree->WriteBlockIndex(*pindexNew))
		return state.Abort(_("Failed to write block index"));

	// New best?
	if (!ConnectBestBlock(state))
		return false;

	if (pindexNew == pindexBest) {
		// Notify UI to display prev block's coinbase if it was ours
		static uint256 hashPrevBestCoinBase;
		UpdatedTransaction(hashPrevBestCoinBase);
		hashPrevBestCoinBase = GetTxHash(0);
	}

	if (!pblocktree->Flush())
		return state.Abort(_("Failed to sync block index"));

	uiInterface.NotifyBlocksChanged();
	return true;
}


int GetOurChainID() {
    return 0x0001;
}

bool CBlockHeader::CheckProofOfWork(int nHeight) const {
	if (nHeight >= GetAuxPowStartBlock()) {
		// Prevent same work from being submitted twice:
		// - this block must have our chain ID
		// - parent block must not have the same chain ID (see CAuxPow::Check)
		// - index of this chain in chain merkle tree must be pre-determined (see CAuxPow::Check)
		if (!fTestNet && !fCakeNet && nHeight != INT_MAX && GetChainID() != GetOurChainID())
			return error(
					"CheckProofOfWork() : block does not have our chain ID");

		if (auxpow.get() != NULL) {
			if (!auxpow->Check(GetHash(), GetChainID()))
				return error("CheckProofOfWork() : AUX POW is not valid");
			// Check proof of work matches claimed amount
			if (!::CheckProofOfWork(auxpow->GetParentBlockHash(), nBits))
				return error("CheckProofOfWork() : AUX proof of work failed");
		} else {
			// Check proof of work matches claimed amount
			if (!::CheckProofOfWork(GetPoWHash(), nBits))
				return error("CheckProofOfWork() : proof of work failed");
		}
	} else {
		if (auxpow.get() != NULL) {
			return error(
					"CheckProofOfWork() : AUX POW is not allowed at this block");
		}

		// Check if proof of work marches claimed amount
		if (!::CheckProofOfWork(GetPoWHash(), nBits))
			return error("CheckProofOfWork() : proof of work failed");
	}
	return true;
}

bool FindBlockPos(CValidationState &state, CDiskBlockPos &pos,
		unsigned int nAddSize, unsigned int nHeight, uint64 nTime, bool fKnown =
				false) {
	bool fUpdatedLast = false;

	LOCK(cs_LastBlockFile);

	if (fKnown) {
		if (nLastBlockFile != pos.nFile) {
			nLastBlockFile = pos.nFile;
			infoLastBlockFile.SetNull();
			pblocktree->ReadBlockFileInfo(nLastBlockFile, infoLastBlockFile);
			fUpdatedLast = true;
		}
	} else {
		while (infoLastBlockFile.nSize + nAddSize >= MAX_BLOCKFILE_SIZE) {
			printf("Leaving block file %i: %s\n", nLastBlockFile,
					infoLastBlockFile.ToString().c_str());
			FlushBlockFile(true);
			nLastBlockFile++;
			infoLastBlockFile.SetNull();
			pblocktree->ReadBlockFileInfo(nLastBlockFile, infoLastBlockFile); // check whether data for the new file somehow already exist; can fail just fine
			fUpdatedLast = true;
		}
		pos.nFile = nLastBlockFile;
		pos.nPos = infoLastBlockFile.nSize;
	}

	infoLastBlockFile.nSize += nAddSize;
	infoLastBlockFile.AddBlock(nHeight, nTime);

	if (!fKnown) {
		unsigned int nOldChunks = (pos.nPos + BLOCKFILE_CHUNK_SIZE - 1)
				/ BLOCKFILE_CHUNK_SIZE;
		unsigned int nNewChunks = (infoLastBlockFile.nSize
				+ BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
		if (nNewChunks > nOldChunks) {
			if (CheckDiskSpace(nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos)) {
				FILE *file = OpenBlockFile(pos);
				if (file) {
					printf(
							"Pre-allocating up to position 0x%x in blk%05u.dat\n",
							nNewChunks * BLOCKFILE_CHUNK_SIZE, pos.nFile);
					AllocateFileRange(file, pos.nPos,
							nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos);
					fclose(file);
				}
			} else
				return state.Error();
		}
	}

	if (!pblocktree->WriteBlockFileInfo(nLastBlockFile, infoLastBlockFile))
		return state.Abort(_("Failed to write file info"));
	if (fUpdatedLast)
		pblocktree->WriteLastBlockFile(nLastBlockFile);

	return true;
}

bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos,
		unsigned int nAddSize) {
	pos.nFile = nFile;

	LOCK(cs_LastBlockFile);

	unsigned int nNewSize;
	if (nFile == nLastBlockFile) {
		pos.nPos = infoLastBlockFile.nUndoSize;
		nNewSize = (infoLastBlockFile.nUndoSize += nAddSize);
		if (!pblocktree->WriteBlockFileInfo(nLastBlockFile, infoLastBlockFile))
			return state.Abort(_("Failed to write block info"));
	} else {
		CBlockFileInfo info;
		if (!pblocktree->ReadBlockFileInfo(nFile, info))
			return state.Abort(_("Failed to read block info"));
		pos.nPos = info.nUndoSize;
		nNewSize = (info.nUndoSize += nAddSize);
		if (!pblocktree->WriteBlockFileInfo(nFile, info))
			return state.Abort(_("Failed to write block info"));
	}

	unsigned int nOldChunks = (pos.nPos + UNDOFILE_CHUNK_SIZE - 1)
			/ UNDOFILE_CHUNK_SIZE;
	unsigned int nNewChunks = (nNewSize + UNDOFILE_CHUNK_SIZE - 1)
			/ UNDOFILE_CHUNK_SIZE;
	if (nNewChunks > nOldChunks) {
		if (CheckDiskSpace(nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos)) {
			FILE *file = OpenUndoFile(pos);
			if (file) {
				printf("Pre-allocating up to position 0x%x in rev%05u.dat\n",
						nNewChunks * UNDOFILE_CHUNK_SIZE, pos.nFile);
				AllocateFileRange(file, pos.nPos,
						nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos);
				fclose(file);
			}
		} else
			return state.Error();
	}

	return true;
}

bool CBlock::CheckBlock(CValidationState &state, CBlockIndex* pindex,
		bool fCheckPOW, bool fCheckMerkleRoot) const {
	int nHeight = (pindex == NULL ? INT_MAX : pindex->nHeight);
	// These are checks that are independent of context
	// that can be verified before saving an orphan block.
	// Size limits
	if (vtx.empty() || vtx.size() > MAX_BLOCK_SIZE
			|| ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION)
					> MAX_BLOCK_SIZE)
		return state.DoS(100, error("CheckBlock() : size limits failed"));

	// Check proof of work matches claimed amount
	if (fCheckPOW && !CheckProofOfWork(nHeight))
		return state.DoS(50, error("CheckBlock() : proof of work failed"));

	// Check timestamp
	if (GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
		return state.Invalid(
				error("CheckBlock() : block timestamp too far in the future"));

	// First transaction must be coinbase, the rest must not be
	if (vtx.empty() || !vtx[0].IsCoinBase())
		return state.DoS(100, error("CheckBlock() : first tx is not coinbase"));

	for (unsigned int i = 1; i < vtx.size(); i++) {
		if (vtx[i].IsCoinBase())
			return state.DoS(100,
					error("CheckBlock() : more than one coinbase"));
	}

	// Check transactions
	BOOST_FOREACH(const CTransaction& tx, vtx) {
		if (!tx.CheckTransaction(state))
			return error("CheckBlock() : CheckTransaction failed");
	}

	// Build the merkle tree already. We need it anyway later, and it makes the
	// block cache the transaction hashes, which means they don't need to be
	// recalculated many times during this block's validation.
	BuildMerkleTree();

	// Check for duplicate txids. This is caught by ConnectInputs(),
	// but catching it earlier avoids a potential DoS attack:
	set<uint256> uniqueTx;
	for (unsigned int i = 0; i < vtx.size(); i++) {
		uniqueTx.insert(GetTxHash(i));
	}
	if (uniqueTx.size() != vtx.size())
		return state.DoS(100, error("CheckBlock() : duplicate transaction"),
				true);

	unsigned int nSigOps = 0;
	BOOST_FOREACH(const CTransaction& tx, vtx) {
		nSigOps += tx.GetLegacySigOpCount();
	}
	if (nSigOps > MAX_BLOCK_SIGOPS)
		return state.DoS(100, error("CheckBlock() : out-of-bounds SigOpCount"));

	// Check merkle root
	if (fCheckMerkleRoot && hashMerkleRoot != BuildMerkleTree())
		return state.DoS(100, error("CheckBlock() : hashMerkleRoot mismatch"));

	return true;
}

bool CBlock::AcceptBlock(CValidationState &state, CDiskBlockPos *dbp) {
	// Check for duplicate
	uint256 hash = GetHash();
	if (mapBlockIndex.count(hash))
		return state.Invalid(
				error("AcceptBlock() : block already in mapBlockIndex"));

	// Get prev block index
	CBlockIndex* pindexPrev = NULL;
	int nHeight = 0;
	if (hash != hashGenesisBlock) {
		map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(
				hashPrevBlock);
		if (mi == mapBlockIndex.end())
			return state.DoS(10, error("AcceptBlock() : prev block not found"));
		pindexPrev = (*mi).second;
		nHeight = pindexPrev->nHeight + 1;
		// Check proof of work
		if (nBits != GetNextWorkRequired(pindexPrev, this))
			return state.DoS(100,
					error("AcceptBlock() : incorrect proof of work"));

		// Check timestamp against prev
		if (GetBlockTime() <= pindexPrev->GetMedianTimePast())
			return state.Invalid(
					error("AcceptBlock() : block's timestamp is too early"));

		// Check that all transactions are finalized
		BOOST_FOREACH(const CTransaction& tx, vtx)
			if (!tx.IsFinal(nHeight, GetBlockTime()))
				return state.DoS(10,
						error(
								"AcceptBlock() : contains a non-final transaction"));

		// Check that the block chain matches the known block chain up to a checkpoint
		if (!Checkpoints::CheckBlock(nHeight, hash))
			return state.DoS(100,
					error(
							"AcceptBlock() : rejected by checkpoint lock-in at %d",
							nHeight));

		// Don't accept any forks from the main chain prior to last checkpoint
		CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(
				mapBlockIndex);
		if (pcheckpoint && nHeight < pcheckpoint->nHeight)
			return state.DoS(100,
					error(
							"AcceptBlock() : forked chain older than last checkpoint (height %d)",
							nHeight));
	

	//	// Reject block.nVersion=1 blocks when 95% (75% on testnet) of the network has upgraded:
	//	if ((nVersion & 0xff) < 2) {
	//		if ((!fTestNet && !fCakeNet
	//				&& CBlockIndex::IsSuperMajority(2, pindexPrev, 950, 1000))
	//				|| ( (fTestNet || fCakeNet)
	//						&& CBlockIndex::IsSuperMajority(2, pindexPrev, 75,
	//								100))) {
	//			return state.Invalid(
	//					error("AcceptBlock() : rejected nVersion=1 block"));
	//		}
	//	}
	//	// Enforce block.nVersion=2 rule that the coinbase starts with serialized block height
	//	if ((nVersion & 0xff) >= 2) {
	//		// if 750 of the last 1,000 blocks are version 2 or greater (51/100 if testnet):
	//		if ((!fTestNet && !fCakeNet
	//				&& CBlockIndex::IsSuperMajority(2, pindexPrev, 750, 1000))
	//				|| ( (fTestNet || fCakeNet)
	//						&& CBlockIndex::IsSuperMajority(2, pindexPrev, 51,
	//								100))) {
	//			CScript expect = CScript() << nHeight;
	//			if (vtx[0].vin[0].scriptSig.size() < expect.size()
	//					|| !std::equal(expect.begin(), expect.end(),
	//							vtx[0].vin[0].scriptSig.begin()))
	//				return state.DoS(100,
	//						error(
	//								"AcceptBlock() : block height mismatch in coinbase"));
	//		}
	//	}

	}

	// Write block to history file
	try {
		unsigned int nBlockSize = ::GetSerializeSize(*this, SER_DISK,
				CLIENT_VERSION);
		CDiskBlockPos blockPos;
		if (dbp != NULL)
			blockPos = *dbp;
		if (!FindBlockPos(state, blockPos, nBlockSize + 8, nHeight, nTime,
				dbp != NULL))
			return error("AcceptBlock() : FindBlockPos failed");
		if (dbp == NULL)
			if (!WriteToDisk(blockPos))
				return state.Abort(_("Failed to write block"));
		if (!AddToBlockIndex(state, blockPos))
			return error("AcceptBlock() : AddToBlockIndex failed");
	} catch (std::runtime_error &e) {
		return state.Abort(_("System error: ") + e.what());
	}

	// Relay inventory, but don't relay old inventory during initial block download
	int nBlockEstimate = Checkpoints::GetTotalBlocksEstimate();
	if (hashBestChain == hash) {
		LOCK(cs_vNodes);
		BOOST_FOREACH(CNode* pnode, vNodes)
			if (nBestHeight
					> (pnode->nStartingHeight != -1 ?
							pnode->nStartingHeight - 2000 : nBlockEstimate))
				pnode->PushInventory(CInv(MSG_BLOCK, hash));
	}

	return true;
}

bool CBlockIndex::IsSuperMajority(int minVersion, const CBlockIndex* pstart,
		unsigned int nRequired, unsigned int nToCheck) {
	unsigned int nFound = 0;
	for (unsigned int i = 0;
			i < nToCheck && nFound < nRequired && pstart != NULL; i++) {
		if ((pstart->nVersion & 0xff) >= minVersion)
			++nFound;
		pstart = pstart->pprev;
	}
	return (nFound >= nRequired);
}

bool ProcessBlock(CValidationState &state, CNode* pfrom, CBlock* pblock,
		CDiskBlockPos *dbp) {
	// Check for duplicate
	uint256 hash = pblock->GetHash();
	if (mapBlockIndex.count(hash))
		return state.Invalid(
				error("ProcessBlock() : already have block %d %s",
						mapBlockIndex[hash]->nHeight, hash.ToString().c_str()));
	if (mapOrphanBlocks.count(hash))
		return state.Invalid(
				error("ProcessBlock() : already have block (orphan) %s",
						hash.ToString().c_str()));

	// Preliminary checks
	if (!pblock->CheckBlock(state, NULL))
		return error("ProcessBlock() : CheckBlock FAILED");

	CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(mapBlockIndex);
	if (pcheckpoint && pblock->hashPrevBlock != hashBestChain) {
		// Extra checks to prevent "fill up memory by spamming with bogus blocks"
		int64 deltaTime = pblock->GetBlockTime() - pcheckpoint->nTime;
		if (deltaTime < 0) {
			return state.DoS(100,
					error(
							"ProcessBlock() : block with timestamp before last checkpoint"));
		}
		CBigNum bnNewBlock;
		bnNewBlock.SetCompact(pblock->nBits);
		CBigNum bnRequired;
		bnRequired.SetCompact(ComputeMinWork(pcheckpoint->nBits, deltaTime));
		if (bnNewBlock > bnRequired) {
			return state.DoS(100,
					error(
							"ProcessBlock() : block with too little proof-of-work"));
		}
	}

	// If we don't already have its previous block, shunt it off to holding area until we get it
	if (pblock->hashPrevBlock != 0
			&& !mapBlockIndex.count(pblock->hashPrevBlock)) {
		printf("ProcessBlock: ORPHAN BLOCK, prev=%s\n",
				pblock->hashPrevBlock.ToString().c_str());

		// Accept orphans as long as there is a node to request its parents from
		if (pfrom) {
			CBlock* pblock2 = new CBlock(*pblock);
			mapOrphanBlocks.insert(make_pair(hash, pblock2));
			mapOrphanBlocksByPrev.insert(
					make_pair(pblock2->hashPrevBlock, pblock2));

			// Ask this guy to fill in what we're missing
			pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(pblock2));
		}
		return true;
	}

	// Store to disk
	if (!pblock->AcceptBlock(state, dbp))
		return error("ProcessBlock() : AcceptBlock FAILED");

	// Recursively process any orphan blocks that depended on this one
	vector<uint256> vWorkQueue;
	vWorkQueue.push_back(hash);
	for (unsigned int i = 0; i < vWorkQueue.size(); i++) {
		uint256 hashPrev = vWorkQueue[i];
		for (multimap<uint256, CBlock*>::iterator mi =
				mapOrphanBlocksByPrev.lower_bound(hashPrev);
				mi != mapOrphanBlocksByPrev.upper_bound(hashPrev); ++mi) {
			CBlock* pblockOrphan = (*mi).second;
			// Use a dummy CValidationState so someone can't setup nodes to counter-DoS based on orphan resolution (that is, feeding people an invalid block based on LegitBlockX in order to get anyone relaying LegitBlockX banned)
			CValidationState stateDummy;
			if (pblockOrphan->AcceptBlock(stateDummy))
				vWorkQueue.push_back(pblockOrphan->GetHash());
			mapOrphanBlocks.erase(pblockOrphan->GetHash());
			delete pblockOrphan;
		}
		mapOrphanBlocksByPrev.erase(hashPrev);
	}
	return true;
}

CMerkleBlock::CMerkleBlock(const CBlock& block, CBloomFilter& filter) {
	header = block.GetBlockHeader();

	vector<bool> vMatch;
	vector<uint256> vHashes;

	vMatch.reserve(block.vtx.size());
	vHashes.reserve(block.vtx.size());

	for (unsigned int i = 0; i < block.vtx.size(); i++) {
		uint256 hash = block.vtx[i].GetHash();
		if (filter.IsRelevantAndUpdate(block.vtx[i], hash)) {
			vMatch.push_back(true);
			vMatchedTxn.push_back(make_pair(i, hash));
		} else
			vMatch.push_back(false);
		vHashes.push_back(hash);
	}

	txn = CPartialMerkleTree(vHashes, vMatch);
}

uint256 CPartialMerkleTree::CalcHash(int height, unsigned int pos,
		const std::vector<uint256> &vTxid) {
	if (height == 0) {
		// hash at height 0 is the txids themself
		return vTxid[pos];
	} else {
		// calculate left hash
		uint256 left = CalcHash(height - 1, pos * 2, vTxid), right;
		// calculate right hash if not beyong the end of the array - copy left hash otherwise1
		if (pos * 2 + 1 < CalcTreeWidth(height - 1))
			right = CalcHash(height - 1, pos * 2 + 1, vTxid);
		else
			right = left;
		// combine subhashes
		return Hash(BEGIN(left), END(left), BEGIN(right), END(right));
	}
}

void CPartialMerkleTree::TraverseAndBuild(int height, unsigned int pos,
		const std::vector<uint256> &vTxid, const std::vector<bool> &vMatch) {
	// determine whether this node is the parent of at least one matched txid
	bool fParentOfMatch = false;
	for (unsigned int p = pos << height;
			p < (pos + 1) << height && p < nTransactions; p++)
		fParentOfMatch |= vMatch[p];
	// store as flag bit
	vBits.push_back(fParentOfMatch);
	if (height == 0 || !fParentOfMatch) {
		// if at height 0, or nothing interesting below, store hash and stop
		vHash.push_back(CalcHash(height, pos, vTxid));
	} else {
		// otherwise, don't store any hash, but descend into the subtrees
		TraverseAndBuild(height - 1, pos * 2, vTxid, vMatch);
		if (pos * 2 + 1 < CalcTreeWidth(height - 1))
			TraverseAndBuild(height - 1, pos * 2 + 1, vTxid, vMatch);
	}
}

uint256 CPartialMerkleTree::TraverseAndExtract(int height, unsigned int pos,
		unsigned int &nBitsUsed, unsigned int &nHashUsed,
		std::vector<uint256> &vMatch) {
	if (nBitsUsed >= vBits.size()) {
		// overflowed the bits array - failure
		fBad = true;
		return 0;
	}
	bool fParentOfMatch = vBits[nBitsUsed++];
	if (height == 0 || !fParentOfMatch) {
		// if at height 0, or nothing interesting below, use stored hash and do not descend
		if (nHashUsed >= vHash.size()) {
			// overflowed the hash array - failure
			fBad = true;
			return 0;
		}
		const uint256 &hash = vHash[nHashUsed++];
		if (height == 0 && fParentOfMatch) // in case of height 0, we have a matched txid
			vMatch.push_back(hash);
		return hash;
	} else {
		// otherwise, descend into the subtrees to extract matched txids and hashes
		uint256 left = TraverseAndExtract(height - 1, pos * 2, nBitsUsed,
				nHashUsed, vMatch), right;
		if (pos * 2 + 1 < CalcTreeWidth(height - 1))
			right = TraverseAndExtract(height - 1, pos * 2 + 1, nBitsUsed,
					nHashUsed, vMatch);
		else
			right = left;
		// and combine them before returning
		return Hash(BEGIN(left), END(left), BEGIN(right), END(right));
	}
}

CPartialMerkleTree::CPartialMerkleTree(const std::vector<uint256> &vTxid,
		const std::vector<bool> &vMatch) :
		nTransactions(vTxid.size()), fBad(false) {
	// reset state
	vBits.clear();
	vHash.clear();

	// calculate height of tree
	int nHeight = 0;
	while (CalcTreeWidth(nHeight) > 1)
		nHeight++;

	// traverse the partial tree
	TraverseAndBuild(nHeight, 0, vTxid, vMatch);
}

CPartialMerkleTree::CPartialMerkleTree() :
		nTransactions(0), fBad(true) {
}

uint256 CPartialMerkleTree::ExtractMatches(std::vector<uint256> &vMatch) {
	vMatch.clear();
	// An empty set will not work
	if (nTransactions == 0)
		return 0;
	// check for excessively high numbers of transactions
	if (nTransactions > MAX_BLOCK_SIZE / 60) // 60 is the lower bound for the size of a serialized CTransaction
		return 0;
	// there can never be more hashes provided than one for every txid
	if (vHash.size() > nTransactions)
		return 0;
	// there must be at least one bit per node in the partial tree, and at least one node per hash
	if (vBits.size() < vHash.size())
		return 0;
	// calculate height of tree
	int nHeight = 0;
	while (CalcTreeWidth(nHeight) > 1)
		nHeight++;
	// traverse the partial tree
	unsigned int nBitsUsed = 0, nHashUsed = 0;
	uint256 hashMerkleRoot = TraverseAndExtract(nHeight, 0, nBitsUsed,
			nHashUsed, vMatch);
	// verify that no problems occured during the tree traversal
	if (fBad)
		return 0;
	// verify that all bits were consumed (except for the padding caused by serializing it as a byte sequence)
	if ((nBitsUsed + 7) / 8 != (vBits.size() + 7) / 8)
		return 0;
	// verify that all hashes were consumed
	if (nHashUsed != vHash.size())
		return 0;
	return hashMerkleRoot;
}

bool AbortNode(const std::string &strMessage) {
	strMiscWarning = strMessage;
	printf("*** %s\n", strMessage.c_str());
	uiInterface.ThreadSafeMessageBox(strMessage, "",
			CClientUIInterface::MSG_ERROR);
	StartShutdown();
	return false;
}

bool CheckDiskSpace(uint64 nAdditionalBytes) {
	uint64 nFreeBytesAvailable = filesystem::space(GetDataDir()).available;

	// Check for nMinDiskSpace bytes (currently 50MB)
	if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
		return AbortNode(_("Error: Disk space is low!"));

	return true;
}

CCriticalSection cs_LastBlockFile;
CBlockFileInfo infoLastBlockFile;
int nLastBlockFile = 0;

FILE* OpenDiskFile(const CDiskBlockPos &pos, const char *prefix,
		bool fReadOnly) {
	if (pos.IsNull())
		return NULL;
	boost::filesystem::path path =
			GetDataDir() / "blocks" / strprintf("%s%05u.dat", prefix, pos.nFile);
	boost::filesystem::create_directories(path.parent_path());
	FILE* file = fopen(path.string().c_str(), "rb+");
	if (!file && !fReadOnly)
		file = fopen(path.string().c_str(), "wb+");
	if (!file) {
		printf("Unable to open file %s\n", path.string().c_str());
		return NULL;
	}
	if (pos.nPos) {
		if (fseek(file, pos.nPos, SEEK_SET)) {
			printf("Unable to seek to position %u of %s\n", pos.nPos,
					path.string().c_str());
			fclose(file);
			return NULL;
		}
	}
	return file;
}

FILE* OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly) {
	return OpenDiskFile(pos, "blk", fReadOnly);
}

FILE* OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly) {
	return OpenDiskFile(pos, "rev", fReadOnly);
}

CBlockIndex * InsertBlockIndex(uint256 hash) {
	if (hash == 0)
		return NULL;

	// Return existing
	map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
	if (mi != mapBlockIndex.end())
		return (*mi).second;

	// Create new
	CBlockIndex* pindexNew = new CBlockIndex();
	if (!pindexNew)
		throw runtime_error("LoadBlockIndex() : new CBlockIndex failed");
	mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
	pindexNew->phashBlock = &((*mi).first);

	return pindexNew;
}

bool static LoadBlockIndexDB() {
	if (!pblocktree->LoadBlockIndexGuts())
		return false;

	boost::this_thread::interruption_point();

	// Calculate nChainWork
	vector<pair<int, CBlockIndex*> > vSortedByHeight;
	vSortedByHeight.reserve(mapBlockIndex.size());
	BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*)& item, mapBlockIndex) {
		CBlockIndex* pindex = item.second;
		vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
	}
	sort(vSortedByHeight.begin(), vSortedByHeight.end());
	BOOST_FOREACH(const PAIRTYPE(int, CBlockIndex*)& item, vSortedByHeight) {
		CBlockIndex* pindex = item.second;
		pindex->nChainWork = (pindex->pprev ? pindex->pprev->nChainWork : 0)
				+ pindex->GetBlockWork().getuint256();
		pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0)
				+ pindex->nTx;
		if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS
				&& !(pindex->nStatus & BLOCK_FAILED_MASK))
			setBlockIndexValid.insert(pindex);
	}

	// Load block file info
	pblocktree->ReadLastBlockFile(nLastBlockFile);
	printf("LoadBlockIndexDB(): last block file = %i\n", nLastBlockFile);
	if (pblocktree->ReadBlockFileInfo(nLastBlockFile, infoLastBlockFile))
		printf("LoadBlockIndexDB(): last block file info: %s\n",
				infoLastBlockFile.ToString().c_str());

	// Load nBestInvalidWork, OK if it doesn't exist
	CBigNum bnBestInvalidWork;
	pblocktree->ReadBestInvalidWork(bnBestInvalidWork);
	nBestInvalidWork = bnBestInvalidWork.getuint256();

	// Check whether we need to continue reindexing
	bool fReindexing = false;
	pblocktree->ReadReindexing(fReindexing);
	fReindex |= fReindexing;

	// Check whether we have a transaction index
	pblocktree->ReadFlag("txindex", fTxIndex);
	printf("LoadBlockIndexDB(): transaction index %s\n",
			fTxIndex ? "enabled" : "disabled");

	// Load hashBestChain pointer to end of best chain
	pindexBest = pcoinsTip->GetBestBlock();
	if (pindexBest == NULL)
		return true;
	hashBestChain = pindexBest->GetBlockHash();
	nBestHeight = pindexBest->nHeight;
	nBestChainWork = pindexBest->nChainWork;

	// set 'next' pointers in best chain
	CBlockIndex *pindex = pindexBest;
	while (pindex != NULL && pindex->pprev != NULL) {
		CBlockIndex *pindexPrev = pindex->pprev;
		pindexPrev->pnext = pindex;
		pindex = pindexPrev;
	}
	printf("LoadBlockIndexDB(): hashBestChain=%s  height=%d date=%s\n",
			hashBestChain.ToString().c_str(), nBestHeight,
			DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexBest->GetBlockTime()).c_str());

	return true;
}

bool VerifyDB(int nCheckLevel, int nCheckDepth) {
	if (pindexBest == NULL || pindexBest->pprev == NULL)
		return true;


	// Verify blocks in the best chain
	if (nCheckDepth <= 0)
		nCheckDepth = 1000000000; // suffices until the year 19000
	if (nCheckDepth > nBestHeight)
		nCheckDepth = nBestHeight;
	nCheckLevel = std::max(0, std::min(4, nCheckLevel));
	printf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
	CCoinsViewCache coins(*pcoinsTip, true);
	CBlockIndex* pindexState = pindexBest;
	CBlockIndex* pindexFailure = NULL;
	int nGoodTransactions = 0;
	CValidationState state;
	for (CBlockIndex* pindex = pindexBest; pindex && pindex->pprev; pindex =
			pindex->pprev) {
		boost::this_thread::interruption_point();
		if (pindex->nHeight < nBestHeight - nCheckDepth)
			break;
		CBlock block;
		// check level 0: read from disk
		if (!block.ReadFromDisk(pindex))
			return error(
					"VerifyDB() : *** block.ReadFromDisk failed at %d, hash=%s",
					pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
		// check level 1: verify block validity
		if (nCheckLevel >= 1 && !block.CheckBlock(state, pindex))
			return error("VerifyDB() : *** found bad block at %d, hash=%s\n",
					pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
		// check level 2: verify undo validity
		if (nCheckLevel >= 2 && pindex) {
			CBlockUndo undo;
			CDiskBlockPos pos = pindex->GetUndoPos();
			if (!pos.IsNull()) {
				if (!undo.ReadFromDisk(pos, pindex->pprev->GetBlockHash()))
					return error(
							"VerifyDB() : *** found bad undo data at %d, hash=%s\n",
							pindex->nHeight,
							pindex->GetBlockHash().ToString().c_str());
			}
		}
		// check level 3: check for inconsistencies during memory-only disconnect of tip blocks
		if (nCheckLevel >= 3 && pindex == pindexState
				&& (coins.GetCacheSize() + pcoinsTip->GetCacheSize())
						<= 2 * nCoinCacheSize + 32000) {
			bool fClean = true;
			if (!block.DisconnectBlock(state, pindex, coins, &fClean))
				return error(
						"VerifyDB() : *** irrecoverable inconsistency in block data at %d, hash=%s",
						pindex->nHeight,
						pindex->GetBlockHash().ToString().c_str());
			pindexState = pindex->pprev;
			if (!fClean) {
				nGoodTransactions = 0;
				pindexFailure = pindex;
			} else
				nGoodTransactions += block.vtx.size();
		}

	}
	if (pindexFailure)
		return error(
				"VerifyDB() : *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n",
				pindexBest->nHeight - pindexFailure->nHeight + 1,
				nGoodTransactions);

	// check level 4: try reconnecting blocks
	if (nCheckLevel >= 4) {
		CBlockIndex *pindex = pindexState;
		while (pindex != pindexBest) {
			boost::this_thread::interruption_point();
			pindex = pindex->pnext;
			CBlock block;
			if (!block.ReadFromDisk(pindex))
				return error(
						"VerifyDB() : *** block.ReadFromDisk failed at %d, hash=%s",
						pindex->nHeight,
						pindex->GetBlockHash().ToString().c_str());
			if (!block.ConnectBlock(state, pindex, coins))
				return error(
						"VerifyDB() : *** found unconnectable block at %d, hash=%s",
						pindex->nHeight,
						pindex->GetBlockHash().ToString().c_str());
		}
	}

	printf(
			"No coin database inconsistencies in last %i blocks (%i transactions)\n",
			pindexBest->nHeight - pindexState->nHeight, nGoodTransactions);

	return true;
}

void UnloadBlockIndex() {
	mapBlockIndex.clear();
	setBlockIndexValid.clear();
	pindexGenesisBlock = NULL;
	nBestHeight = 0;
	nBestChainWork = 0;
	nBestInvalidWork = 0;
	hashBestChain = 0;
	pindexBest = NULL;
}

bool LoadBlockIndex() {
	if (fTestNet) {
        pchMessageStart[0] = 0xac;
        pchMessageStart[1] = 0xdc;
        pchMessageStart[2] = 0xdc;
        pchMessageStart[3] = 0xac;
		hashGenesisBlock =
				uint256("0x2f42154af40613d1fc0f5c63fcade17c1fbf4aff311722b38dd6698b77668b34");
	}

	if (fCakeNet) {
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xf1;
        pchMessageStart[2] = 0xf1;
        pchMessageStart[3] = 0xf9;
		hashGenesisBlock =
				uint256("0xa86ee2d873489d24564405287c18807f369f0c82d54dfe756f2d8c3d2af15908");
	}	

	//
	// Load block index from databases
	//
	if (!fReindex && !LoadBlockIndexDB())
		return false;

	return true;
}
#define GENESIS_MESSAGE "QlpoOTFBWSZTWY8+ZMkAAMN///////////7/9///v//3//////v///3f////////////wAH9242drtIAAAAAAAAABoAAAAAAAAAyAAAAAAAAAAAAAGgAAAAAAAaCTNTamNEzSaYmaCegJk0wTJgmT0jAAEwaIwGiME9ARmpmkzRlMmBqYEZMTR6ADSMn6ieUbQaACegANJhGTGg0CRk9AajCabRMQ3qE0wjRoZMIMmNNB6pk2homTEM1NGBM0BNqZPJBgMgBPUxNoBqYJ6mTTTaJ6janpNonpMaT0GhoaAAymIgTEwABoNIwABoAmDU3qNJhMAAAAACYaCbUwEYmCaYTAA0APUGgAAA0EYNCMJkwJptGowTGK/l+SIkqrsenvYwjd2lmJKCiRwfpTj0tNvVgDic5xaJdnjIlQC+tq836ITQJBW0sCLXg7A27vTsTnQYy4Qp/Ih/xqFAQfesgyXcwS3LWdD7B0EKX8YmUmwsE9oRtdnJ/mPDFLkpYjf/cAOtZsjwDT+c23KeWr8SCg+1gFN4Cajd+fzzs3XA740CvY/tg5WM1kn8FdoFhdb62JopuWlLHHdfjsJawzzBJ7MbBsdVMeOaOABFOFv5W8HtZQIW/oaDnHXx1wf0RZcfBaZLh33hrmnEmmuQc/YsQGJZjAM0GGk+CrIlKfqqd2l7ItbOaaU7Nh9sqoqFASXpQQw5gZY6Qv4XHSVoTU/KKCvw8XgBt8Itz5j7m6Ppst+AKGatv7KvOF5U2PLff7N1Y8ET83x8IZbXIJN68L8VEkcsxJXCkAKo+/zP2aBAPiIresWK9zvILcchqD0oDyI03poSCXbKpvoXXtgvVoB7DWJ2YLum/Ga/d5BCQCIsvgOiienOSn3wdYefj7tzAZneE4NoBYKl8Z0s8IL0amDzrmmVbLYwOe0Na6acWZ8AgfYqZg3DoQH5btdZ6StED/LEvhfUn8+E4hyuMFzwrahLluaLr9d77EfejG4xINBWTIgslQ//lDZ8gkwgCv2GwBSGTj+Ev2+bNCbggEaRCdzrMAkVg6LY1fTOdssPpIDvNniNmfkbM9k0pd3qC9Y9iNYsRk648PjDEcH3ARQYtzjfS6wKoKdihHsK324UKYbqc5AhvTI/2gGgAOP9hByZ45/lsl7vOPwPfi0e6yHC2ezZO6VN9tHiBEEqlSqd+SMhkc3nrgRYgZA/YyP9I39JAkQWvIr6JRwGqkVsYaDFKk7vgE3Y8QVP0mg7/5RI41BDst36K7Xe7cMO1HUaLHNcOiUIg39ADjzDXe88SoZ7wPSuADvM+e3dz77yhrPYuB8aQ5eZI6QXnF3JFOFCQjz5kyUJaaDkxQVkmU1mHZVKFAAiK/////////////////////////////////////////////+AVO+nuvvN3vT7b2eZ977eMm815nwJX3zXver6b3d7753VxXeuO+beFu9vvevm6XV7aXzcs773uffa++e+Wdr73uZ9fd7IVPyNqYFTzBMJkY0E0xonoBUfiYUn6bUYm0DRE8NANJhpGFPA1MEwI02ptR6TQzQp+iaGmmRiNMCMTAJmQaZU81PTQyZAxAaFRCn6ptGNAANKfqntMlPImTegACeimzSDJp6psJNongymTJqflT2gU2CZJ+mSeUT9AJkMmjaT0mNNDRoaDU9AZNMRM1MmmTTKbTTAEyM0TTSJT0xNGJhT0xPKn5CjzQNFPaU9omT1T1N6Q0xMo8T0TGqeU3qam2o8ibTU9A0TGp5JsUwwjRo1M0BlMTJNtJhNTeoekTNJ+UeptI2oxMp6GU2mahPRmphqRR6Gj1TTynqe0Qnp6ap6aaaY0CGam0RmppqeaE2pgp+U8jI1PAjRpkxJtBpTw1T2ingnpMU9J7VP0TA1NNoTExqaanjU8pM1PTRqbKemmib1Mmmm1E2TTNR6TCiFHmimm1P0TJkxTym9KeTAMjTRo0NNNMTIm0YmlPRNtJkwap41J5omU8TRqemT0RiejUjZGnqYCngAmmBkKbBGTamTU2mRjSYnqaan6amCZqTY1Q6p5oMjIaam0MTU8nqaaCn6aRiNNJ6ZNTxM0E9U8JphT9U/UxJ+qbR6AU9TxNJtGFNP0ATTahPDIFPE2lPTA0BNMBPSNMp5o1PUymnlNtBMTRP1NTxHqagHTh7DLmBDSqMvX0zznfk+w6oxL4juuW8dfDveY7mHB5sX1ccmqH8tETfTqKQdJb0ZXtVCXMQ9rqLsmHkBMdBrXE/VpmxrrPElbQ3kCi6Leo0tdHJh/ZlWEEB0CISMhflx+bzl6miIv2ARJBrlhHk/Uv5zB1eIFa/aaHEtrrcA0f6El6QlmSzj4FqV+vrC7jCx36tQcBNu2qRoCezIw+8CQqWcro5kQwqlgKIQV4ahujeQkmV9r61N4XpTNtRwfQ4EOgT62Bt62U5r9Nq/slygFJRescxInR88hdsLWUYj7csMLVcA42fNgia+NguM1F17YhutAtHJQRx5KPCheVe8lWCodUpkvoo/LesSqhCjgoM3YaeAfA7nHH/HQ6VUye+39hqgZg7jzBvOyZwHfZerUQjnYwEOz5zHGpVsH+xehEhKpAbBGyd1irp1U5zKdfUSMfe1570+aXNoUp0nGED3SrKQjHcew6QBl0QrkNXLiQq+3su5gN1mqcO98N/TlCEKCOtIplf/mwJ6929QL3TmGt3s6CZuQgxBt+jFQ9YYqJN7HceMs0NfJZlF7FV32zZ/eY+nKcJsWHTGE9u0/LVEMEN8SvK7P7NAf4MG0XIaxcUoJjhUN5MydGfE01y1cdVC9DEdOKRtLDKwMv3tVrnRsk8UDRRq35Pfr+PltkccMeDq5ZjGXZNYzYhXjxoZCnmm11ePQOCPgZHfPIIa+Yu/rMpR3idG4cxaj4ayyoBHW4NPYmObc9kYVCQ/oNWHXQrId7X9iuU/SpypKwgnhSJU4c9AfkRtXocd3L2saTbOrpjjY+DnOX2/+upneS/j/l1Od0c/0Wda4aTjg5yB7b5qSCyoNXpPnAnFyp7ZseBuECs+etM6Q7knVcZ/1x1sWmISULQ4jHoG9bwUdNGVQMMNgRyW937jFHmfwZWEZbsWuWy5ssSsQnuwque5Zh4jpxrrmNbDH7pYNbhN2YhjWHP4LPCvzLHlAxUn0+PFW8qX+eVE77AAtDHuCYj44ZyoS+fEGCgWAVMvXUnyjNBdK0YT7xRZKyW6w+mJDaqLOKd6z2jFNTNcIn1yWz8LxJZJajuZb/PuY7kADRmUyDWlCM1aQDCb6PKYb+a1wXIAtLFSy5RtGkxrkvrxjsVuPkK94YFSbugfBAeKz3hfEUZqK1CWizYcHNq9zGEjXJuvlUuvhLDNtMnOPV+rLPZDtJuJajxtuR0gr+VwzveU+K3P8gr5vbMCJvh3Mg1SwsryhYmI2qUxEaTKGbO4MhmmunVbsSwB9pK8/i4IB6k2a4bhDDQRmrcdrIXrSHjLlDdopc9umnu8b+dDQ+A01MuzW67xNGRCOK/d5lene2rHIfjbIpkiGvwQ0p8JwBt8B8bv3PaTo9PyiBY4hUmd7eZ/IAujbs0B6Yei6SzGa+eUgFf0IHCatq0yL3x+FO8yushYI8P2cmS61BXyixGnaPZJfObXNGIe6rMTdxhaRER1SgP6Q12Ox1+XTstv2bsY1oeERbFehqYbL9BBTfqhADmU9gDPE2HcQptQ+1e9uEXaw+MB/9eo2WV/DJWN5zWe+FToE4qUsT4GeJ14GPDM7iI2NBQHcZO9HyPLb9KDyPqVzF0kOe7SSIsOOpysM7eWX5EfFkXRv/RKjdraMaTxBgY/XOooe+PjN7qq06uchJ7p7uDx5go24S0LGk/Wd12Xu77ynViFQQLUpQciNS2cW+3vVG0Zyfyxn+nf67o9S1tBt7LsCSRphGdZndXPG3QrGc2jzyDuwC5u7vkC0I53XmXYJVfRfajNBoKgPbQVDCoB350dCwhe07O0kawfsp8lhwuKS56mrIgo2i8KUT+GSGTjXAfrVn1M8uZ+KpN+Etrs0F2Wez5CTRPNLFXL1vnixb5gGvDDIynoz5bsc6EnvKF1S/CI14cCd5MYnqfnQvl0HXBKHh69TcGNN6/xz8LTP1C6h6lIsaUfwhnjAUDx6arU3CxyiUYNRO8kEL/CYIkQkBpYvu/KljT7p1Tjlfs2QMF/C0QTrrh7Urp9s+z4NzpHg1Pvqp957jf3BwX2Xaw/QpZ8UhzPtKY2xSfKN9ECBpOOcn3RKaj26XHUEqHboogecHJmvuePLTgNmTOoa6RT8kYrZarkUp6jKl2oefkI66tFgmVqxrvRAA1qv8Lu122MT7gteM0t032usMvexTlMoYpZfNwsdZD7dvfhwH704MwvafPtRrQrobE8AQYBNqdng99XQNVOndSGgW+sIpphc62feK0Uy9uNDhTATa0l3yUgW8lTOJ72a3s3ObsqpIpRCT1hYRDG4JK8W6jDSYRCHNwoLKzBoxQR0os1CkMhGv+UmlwOLTbbGvpp7SlLx+mu60GD+YSvZiaAS2B/34TsknbTDdEyLp95FJWEz0zmZ7UnUAONnVlZIrU/cJAAoobzMuiaoZE64AmHJj1KX92+HUMT2vkpqq0Zm0Bl17Gbq4QSQsyjKRqTeR0d2onzwW2cM/FF+2rHGwhHiKYwUegauKM0x9ACsLFXjb/RbzW82z4OlWSOt2CjhbvOudfs0D/amwGek+f56xvQd9aO4VH3l5TFivFzkUaAwy4PI3SOKqwcblMuJOLO0hdC1fAT+IJNfX6WQS7tfQuBaSslPXrPdlDTryZoTIYKb0azs/pAqLX+11KwMNY0XQnluUJvC+NzhA0UkAn2e7m2II1H+hx4Ilm1102aa+o7qkR4yV+88xHXeRf8XyXD0zrmHqc607uZOwJlU+7GamUQ5jlN98UeVRia7/xapSLiE4Dsl6af8kij39eMFWJNcyJ2WSef3LHFMvS/IjVinTqTf34d2QidUbIq78/8lLpbLR2vBAATDT0q10KFu37Msq4UkbTQeiCliDPxuEwibU7qjjyA4kPOGdmwfAdLcMEy42wQUlotabgvg6XkIXLcFwSRmmfd9eRjSIK+dQcEHwWoBGl8I40yC9LzeVuM45tdStMayJWX/gdd8GxKZlYiW/0XwSuI3jt/0soDPrj5H0l0cBw3yq/OEDiZKhltWkNpmpv8nok5tbxfv6INIW56kFVV4WghYf53pRdbp2CauFYE1+t4SJeUfUDlUseS48WJfpLuQTz9i7w5mrNZtbEaMAtOi/pujrE4BhhclSzplWjAuZTg57qYHzoztcPxukMCtkc+mkvSsP3GO9awKu4msLSd1tyVEN6DnWxjbreet4N7bC/j4WeyJphnKrvELa8u3Fa/VAsNErHrfs+SCVWBp1ZZ4JyqY+Vu2b8gTreabqHibDTpyjfJEkIgnDwEDHnaeUFp7Xy06KSJ5poIfn8PUJDMUPOTSlY5De9irlR5qKEQxtfZK7JoGBx1Gd2EjCbbAkr2dZSDEDbHdkit7DiKVH+4UQ0iH4Taz8NaLkFee9t242FT3FgpS6aoz8gRbmRHxRvX3SoCLqrawdkCrLxfcHe82Za+9iFjWNt/nncqUS8eiYDkMCeh6pGOoGJaFhe3ZIyPuWr/OYOuJDCcNzMgwZfWSKtf5lHMamMvVKKJPIjy+f18FTvXhlvtErWAm477kio8LQvqPSU3O6veSb2PM+YkVqXekRYywwYE6Unm0LfEjHV8tS7CD7LpMeobPzuEdZWAmOToGefw662sfZkdvTD78CJstvBnuR5jIlUx3ayJwbZM30AVVnomWbra4NzK+Nc/y4htSYjsPbYT/mTW55x96AfDMi+S7DmMgcKxJLaEiZArJoPTJ10pDsxWT8auZXvTw6t8/MYnV7DFP4BKx1JoszjlnBF1yJjc4Jo4GDM2qd5gYfeobLNuTXFm57gcnysALajlGxL2Qp4a+wTauT7WwtMna7nuDcvrG6SCVrcDe2v+eXEbnD7KvQs8BVKyKGlm6ksx04Gy/RwxcOwAjupJKpHHVddrf/zNf0tmz7g1Frfx4TK4Yp3xpEnxG028X2v3gWHAs2Yfea8pI7Bk0e1BKwqlDwkSq51Ory1/bkwahyXAJbHMsy12+MU650cL9KFdX5EVYFO/RtvVHNuw2pOn9BxuFod8zm9Ty516moU9PlKneVp3IO7Uu9dl8Zcp5/QvV4KhbBmbblRtBcT5BBUxUh60wCNq4VdyxihHvl/8CynycIKSYuaZuiEJkoBbOZNh9PCQjUYwj/mBWSYoMxx6cz3XYdk0QS5SjP3evvjLX6fJjavUYL0IiMbh53e56J3gBXeho3j3d5cg8ZgzHMKAtZvGs+6PNNTJpiqU5HUPWOD3dawVOAf9jlXH0Kz2uovMGOhzsruwLUjJ+cL1XlW8DoSDCYkgF5polPpL6N2VImfs9PYhNtEThkoHZoKS84AK/hXL3WVDWiDkYgkWlbKUvnYfjsfEiwbrwyhahFcgnJ1UNlpmixlt8I+f8G6hutk4Szkbj4cxkhkJIY0YuYANiq9t4QaRo/QGRTilp3jdbUujhUW2kwXwoQ3+yNTkOJIYbmzdMyK39pxyU0v+Z65K4+SyJqNIlEMrUYWSgG21thc1q1asbFwp6eeheu0VoRYrXutIsDjRWFScfgPUsC1+XetfafsGyzWBEjYYR7i0tGfQVGWuaF1KizfBmdh2HR+ozMqj0yui/4kmJcKC1hdLeCYZGVjZNSEFOmPCI17q0i+cmsb4TQltkiYCrrnXtC3qfyQpy5GWesxppMsH3UnTYZR74YAZv8NezQuHM2vL7EluL4t39ydH1PLLySUegxB3RP56w1C+oG76q9K6+Bh0TpQuq/rKfGYqyPSwcnhwKrOtoERG5cVkgBD7d3SFKljafjPlnlSfl+lJGxQ+1tPUGI+rpc/Ss2JozWjiScT4uzajvgXsJDSlRD1+agR8CSERBZ4H66PtY2smaABbWmwcnmkiKfsCpR+bs0RSV9g7Ttn7gJ0Pt7BOZzZddLLHxRLsTWHufi3/GoGqXKDGVsQi1G3SASSV64VfSgN+/DbQdYwtN/rYjYPhqUBPnrx80crf7v/SjL0r1OgDNLIcFTx87pxBdz3ev+rglCJmyiacECf0uAvz7PE5I+ybYMfrWrtYNcwmie4avvTV3ayD5Zhc4P2WmfGNJWEuxGPHx/Y18VLVyPvWannC3IiKFylpeg3z3cEcy8gmWxvQOCJfMaH++wHa0p3d0EjpYYLXN/D+lF2xq0Wh9IStLpyVQFvtVSVrUFGTub9uxDrXnteO9dw4AvwT94uuwB7JnshJvo/xnX9NmumsTrG1AeUotvhdByrwgUIMJqX+oN9p0LDei4nWK6FzzmwtaX6CCVb3Y/X5lg7+Dc53gpPdVEaoXKDdTx9a3smBYGgnaTKeEZerAB4BZTCdgBWVIGtrHxPOzZhKJO0dxATMViZgEfYeoSvGjL2mnGoxJRELY9SOgi8dteqjTbHe6GOhrzzlCGmLPslRmAuWBq3QqNRFPa4BtUrV4naRhRzFUGDt+57jzD7303KWpBKBV2n9GfDUBkacCsR7XlWPOgLY2WBD5CGG8EZsixcyY5ilCLRnxc/u+EYbfOQP8aKf3vBS5fD70b0SWjRMA9r3zAbBmSfFxTHgrsKrzCkeD5LMIlhsLG3uGdC6W/SQF3pgPtNI1krQ8rQgExaOtdod7+BJ2COVDRugj5Z3bKMmL+BeGowzA0OZDy/JHvqhA2Ck4loOvHFTYT5ZNo+1RMMp0FPoU5VaX5UNVsYJoWJeVR4uym5PeL2zMIMYDcZN+GLJbmbuyIJF4EStHhX+cP98rynn7eBHRL4rHvemRgZm2qKYpKwFnF4DRIre2HuNqJS+Dwr0hoc6VUNvESlpblsE82yDO5eq5M1g7PuR202b/bHE8JF5YQfw8Q0xzR2DGfgjlQjluVAhOs+umvB5WZ3AlU/URsk4T3trO8y6qWrKK4bdhDsU/wz40H2KdPATA238zSCb4+jgcxR1TUdhUOenrYT1J0jtfN8zBRcLKvVKHYdwmPAeEr/BBY7CZ86zMEk6XVZcxXNZZAtaZOftVElZK+WVUcrmmWw/btxWHIY2kzD6RJugpjoYBvVhDUPceh27Dg5t2Sa383r8C/bJN7urwFiWnNH2ej5q1YDAhWce1Upp4X0KRLUjT+xz0jZrd4l9CVCZgxkg0fkXvc4vwfuKdYyBcXbi/RjpmGwqi6Zv+oa9CZbZtOtBG5WQODgLn7NdhWmcrkMOnn/hPZPJhA18ljs8Hfb8fDzA5ipv5o78HTedlcaDlPvhDKUidf69u+5gxOLBC98V8EUVtcsEUbEr+LV4olBpoMt9k3tqKngT5GmknGoMwlQwLGDg9sEnmUUisiOAC3uD1/GyTnT5/CrpjyIp5Q1OCjYlEBG5qUee9WZgpiRqWaDVCgr5Qn4cd3tAJnc3J+Q8ExRyqDf8PeqTfg4pK+pwrTyeKyHVAED/b7cnbysP60UIwE0OKuysNS7Oltxsz2Uhx0HtZ3Yj8Gh6NRH+KwzU0yt9tk7lfTr/N3bS41jWT2N9zWzIaIhTP+DSegKll2pNI8+YbabcS4zbECMuP9j8uPAnsPjlJ+I3rRTKvcPXDF4FkkjUlWf0DI6vAK0J69d+q4CNOlvILmW5nXXbxVnWz4xQYXRzZ2N/Ut3vYf0jbbcKMXe6YS1xywt+vT7M/1yty9RCfGLEpwv5y2SMnu5iWrR8dD+bi0aPgM7rBtXCqXjiRvk8+0z0t9oA3HtIh6kYbb+PNWwsuldBbRHrHT+PpklTdHZIl2teahD0NpPSbXMs2DVlZKzKK+761P2SuJsSL97nDItW1LPbUmiekQScXjb778aEuNJ1H9y4S5g+1aGw2qTK23CE4ro3SnGhlTrvTm1yVa/PKUloR3Wd9dFa9IljRWSOi7E5kTmHTKm41HlLxF8aibqQjzJF4N7Dn6Mn5oPrGSLpDUteBlnZ8MbgmBYwYoQ1bJ9c5zYhv7/4XT7Z4DW8tKEAa7FDk47WdJA6cgiUUzrNvnRE6bj8ELjyQxLU+ikcRYXednimHCfNx+rfbrQi6P4Gdl8NTdGOlGbQLEWqE5GSpQmtTzywKhDsWyG9v5bLMfUxeTuLQWPHwMZmWmCeoACEpXKv3FuEzPRF85L+fnmMqPkKJ2I9U/603GvOc4OP9rkDlqN0i0nOfzR7EN92GWiZZL4FC7EYGFON6bbW8d5knisYbsuzPc2QSCwNAyuY7HN0xiAFatkXw6vVthTnwJ8W/t2hbGKNdby2atP+9mUK4RLO65Qyl0Ew8qKvsYyMzPyI+r2S94OF3iPAuvJFwgiuVm6my+ALhFkqH0gGA7mY15cII4DjHVJbpy0FbnGR9NzSPjM7fjJ2/hm8ai2FVKFE5Rwk9HAjpGZXQz5Vn+L+R63VG2ik0UOmnNLYeGseKlM7oQ2HKVy5wnAwsN06+2wemT+OqNetpkCtfkMWO0AwnPilE125cEYBzFKWlLkt8+pgkSDtxoiNutt1g8GxoTgUACE64rvGKTZR+ZQXnv7Ayiz9HXSEVjX3d8zfptyLGzLLYzCUknYFM69iZ4aDcVfPDoPtlcEcyi/nRInKBBBuWawPUM01mVkbUmITb+e2pCm4MIUWWG7MRMcqpcPNWTnmYzC2VsRtyu0sBHkTF2GP6J4/gbLjO7Uu7rnRkuQzXWEkoCI9ANEsosn+Jx/sxRbpZna69TSLwlrqCWa624a+mMXNzvhtTE7Ru1xgjHPai6TlHPRICodIAtQB39PjPrWTux5tForoQ6srvYvmUZ4d/jCd954lD9x17v+LjNfrsaSzzwGm1T6CB/byFMv8TpYnPjqtG9F3zC3i9PdsbYOm9wvixBG/lZm2qHxFcmpScgHoVKUKKWQN5MbpNnFpLZ2HYZZDglfy/vexSSN9DJN9cKo9tGRjpPTaWr2aFkccZGplSapZEv+nLG52D47qajP5RLuu883nFuroGfYofwK9mkFBIYH89FzYvmXi/VNsZFMoqtAcxfHgSqDGt3LUMJHi7o4ZV9TlB2b/8kToivmk+osvHhnYH4LDiO/F47LC3ixI5q66y4mYhsthhUk6r1vjVHQ4GIrjZ5s8BukFcSE5NeenvagKggDGbOvnhcatSEm75MDrI1NPmuIH2lNI1/eMsEh10bpB2UDVVXuks2nAaBHXH+/8AV8qPPpkWiPnf5QFVt/fqCTadSR/Th6ifGEa/PxOKfmYiqsJsgTr6XfonB6OKhag9mTeo+t7B3ENO9WfJ4ydR3JlsitMvMPCs8tnJMhx1Q5wXR4vr7Fs0tHSG+HalH34nJ3EFQ0od4bvmy1ITPDOplz+3N34KG+racmD4btoulrQc8jswmkTy5SLrcf3W2A5lapHYks+yvh9PJy32h5n1M3d9qRVZWYZaFUQZUNqlY/jdu6RaGoTIj4sFfYoZpNEFbI3hkV16PEoX0JxDnlrcPtrauKWWTslLeJ5TV0IoZsTuBAcvdw/aqKvcOCYq6Ho5JXtMgNDkcYK84+iU1typKgp/DVnX2oxf/do7lG66pSglb3cUA2VCroE7etwduErKaZ3eb3H7xIBfMDwHlWFrvTMJIwUk8pZT0rLa0agj8kRSYu0E/9waZ3oIfBUDF7aySS1JTrXCIpHm3Lznv+iA0O4aJ2L02+ddRDktFCl/OJOtxTVHc8nC4bLcQ/ci1j++pzftkK+URQQQMKzPuE+mpo7onI2pkoJNg0OfK4B60fdhWeFeO3dW9Q3TxfwRnkZW+yCPGBZzwLqEPAN8cPXx/VE1HsHbuPnzAlalvXwmERkHScYcwxBGNwVuo0d7okQ2EYPrkW4bEu7RjTiBzFRN87qzwoiGKTKhHG8aL19zekogJ73ygNVXtR7Uq94aPIjAF5v3muQ+tnkkEys6bCxb6OKrvANdM5/ir+vVjO7IopBGCszDpw2JBnV2CRdKcAoIQEaU4tbb1Lwiv2LK7jfMr4C0sxa3jbUgj1z3ynVdbMAsG8m7ex3AcMmJSGF8Zmoyac7ubW0uQxB8Wa8kaCsnwrTuL+xTd+ESNnnLqRSO4OuiG/9bibYazRgQ9TaMiwwkFPBqaZRD0Ki8x7RkOQMm25GZy+843PtPHrUwhYgB6+sgICcccR9mFW9gKqObZKn5Z1Sq230mWfLJwfHzR6scz3oRsrIATf1bB9y9Dhy2vmuYqtweqBOU+jXK16SZrhIqj8JYJdr7gJlscvLEwYv8eqi9vk4pfsHuV14SmydxpCrUQPhTx2IIPXRX2jguenxMMqmOpPfoUpYruaDg/CyS7o94g5VUVlUK+M+9draiKsNaxs0L34C6GPMzj7ILxoExvPMU+/ie6MJh8zEodUGrPrKv+DOs6wFXQO0AKtCCZF69dse50TiW1f0zWQVy+UYQ9iU9WEexPF5lcDL6dHnb/eygdbfsT8IMTVCJLW7OroGcPg6yQKGVeLYui2br0g/aMRm1zM82DO4dO2JIqR64PFGXcWOMCs5oa1AGxOHmz5HYSwvR5Abx5cweBb7oiYNCv+jKgSYv/UbxfD9ngtjvFEgJqUiyXFMsX89/tDiVnqZE2YE58g8rHAWUtm4QWvrOIc25rdslN5GHZ6s1j7EgdODshUx3ToRsH2d7P18bnzzdw53bWQwu4LWWDAlKSI6dU7n8TopcyjhQsWF4xE5oDV5sYgYF7NRON/qPVqGjS8mcNMq7XFJUJ/eN/bXTVfCWQ8Qkoc6gwtn1FX8PEMDInkeNurgZ0eNIGaQWr1uhd/n5ITxxBe89a/nd571gu7h/ufXhPi1YQDpHYDgTkYt7qofa/EQ4xIKxVYTpGRd4Iv3+abEqEqs3HywCn9OWpvijY0yC0SR9C3AsV92aUOswaF3ebZNERTWq2+DSlitjcecSvrcAweY4H3CnQa6IufmsF55MLGN8Dj1kcSmV19JvUxAyid2UFssGAUYO82SffWcyyMzIi+URTy9BTPl0tO2SgsT62wlsXgrv4NfGHxMQC7zI95U+8Z1c08CpeCgN1JqrqRhseZxvKlYht54TKxLL5+0nC7HZtG8tltZBxKTIVwKB9QyllabbVc8QuH3XowPfCNMpOjGnEX/4pMUts2x8gZ/bkT+fU8GerI//mTjyBc+WCGvHVGtzaxTGfCbUPYtLNo9ISFpL9yhDFNE++xmjOoqmnTMhVz7qI+xLQt4Mtwog9Mc05LPNpsBVIXAenckgEZh4aqRGf+LKObqqruw9/DtiKgLvD4h4iPKsugplegAcuuOoiphM8ArnT2nBB6qdziZsrwWJLN8Jye8FPVUqHcoVSli55CT0ROIwi8KQYWieEH0Nu8lmDoBDaQp91Itwe4byV3XghMnnvq6tKehgiOpprPTIUcKol56hBVzwce72wavcpLp3H/bF9RVkGnb793t76M7KWukJxadbNbDp0+bbrtMxsyDD2AhRKBV5IldA6xtgKLQGdoK9s8jxM+PrVyw0bQ/ePvYyrcEtrj+D/GqOK8t2EomHuLRfr5x2qWcEn9GDKkd2w+PU+AuSdT0SUTEPKU9C3m39FrtyUY1h/POM7iKWdsvrL8xLeZyhifEqqQH8iFyTfdHqdQba6lwaIuWhHqp+JJ/kHDE0GQ4hXP2qYmjpKcAyrMlk68jAh+klM/6fcOrUfGV1ouFJGPXvUwWQPjc7obkuwUtbRnSGxzlDtQcQerK91HlZNngkx20qwXbM5lBu1rxao1296hBjRS9XzlEy0PXYhwvrrMJrT4W5nvWWzhah3xcZZ9UKt8FKHNgNBebnbSmL+kwlbxC3Kfssy21q59JfJuf4S1nX0PX3HFTDF/T7SyQqJOxdFHUO+f+ST37FjawDyM/yE8A23Dg764QjP2IcDUKlU0eXyCyLWPEpYQHqt12OEoSQdb6UkBvn8cIHlpF+nbKr99KeUDW4NbXDxHlqtMgbecCflMatREXaAOJNIDWIlXcsTipWbFie/5EGPQNets2BUbhWfWzFFHtzD69GXW7g0bQH2J+9k6gxDnVEEuWABSvzbP7/fSAbw9Xj4hgqgXI/MuOzZK9mNbu+4BU+BHY/OmQ/ccDawXmxAvVaVVILtE8XsXYTtB4jgnm1VQO2HPlDy9/d6dsUatAMBD/xdyRThQkIdlUoUEJaaDkxQVkmU1n2tlFCAAH+f///////////f//////////////9///f///9/////////9AEvgddMtHbGy5GmiKmVNqG9U0PRqHppqNPUekYmjQ0ZP1TJkDQekBoDammjQ0Y1NG1BtJ6myQyAAeppkeKDNQ0yNMj1DYSPRNNND1NMQ2pp6mjaj9U9Q8o09EMPVHoRVPKjTT9SYGiek9T9UaYIZpMjTT1MhoMmmPUmhtDSaYhkyMjNNBMJpo0MTam1GaAExGaBMTymTRpiaAwmRkDNTRmiZPUyMNE0YJoIkqYmjR6mhowEeo9Q09CZpNo0CGmJiD0anoTGRMANBNMRhqDTIaHqaNBiMnoJpptBDT0JtNTTAZIaGTTEaY1GNCZAxGnqZAgAAAAAAAAADQAAAAAAAAAGgAAAAAAAAAAAAAAAAAAAAABKJJpNM1U9qmZTeqeITR+inpk9TQ1NGj9TU8mp4p+pGRp6j1NGjNTR6Q9T1D1NNP1T1NNqNoj0EPSNNP1QHpqP1Q8o0NB6m0nqDNQGjyho09E0AGajR6TTEH6SaDvMrSOCSiI3TIlMqsRBNY3rttz8N26V07ZyulK0le4GxKZQQ4pQUVFUvWNwFdDFCAqEFUEl2ATADQg0wMROQYTcHFPBXTt027kpIeGHGPeFftANKKK/V6qqqq0MYqqtnZf9lGzpFBxysYDQo0KKY3A6NEbP6RNUzJKEXTNT2PRM53RsdPnasXbv0ShSUUIJWbqZ4EnNzHTre41EcROtld5/FThZzoTefvkdlXO+dlDCD0Ke5mWwSvRQUKZtpDrlSKpDmFR8Y+2/2vo7j6b5hIbgYYYYwptpK6IEwUACzgTJdNk6EQh4hTI5OWWMbQcrVoWxVZCJxmBwSuDiJoNHXD2FL20B5JyPiupn0rd51HuwcWS4oowTX1Ink5xEo41ZGCAvEUnapxRZHF8IKNdrdZWGnYYArMHgAc1Ajk3U1m4pqoeFMJ5bZfMytDZscefVeku5FhxsW1CFuDNbaRearoA/Z6qigKqqvwXNVJBzVfkqIov0z+o2dpQVtDrfVs9ZDoW678o3RcPs9dY4SiB633mOjhKhsAnNkh1aiqgoCqRt2vKhMAn1oq0KPsRpntQB36CLGfFEoympxHyO3bYXi1loACM7QolkwA6Wa7WV3qxeHGbgyqGYOyTHMbl45MCgSJDCqnfpIlh/MbXI8fBuRTiO1DJCE0JNj5Y7IWOJAxES4oJN/ZT0XYpIXMblwDAq7qLJYIFRoaWJHbJ3er7+e955tbycbfUihByBez7C/FCHU4jTIQTspuVCTb24hhUD2L1aUc2hKuvIOctKSgB/jnWwO/37ZR0hxc/xwdVfATo+1uo1L6+9OWx03nqR/e5EDrN/wMD4byFhbAVRiIqlVm7bkyy3+VwebiTfn6v6KP85E/m/Ql+3NpbMKnGCWqobMDey3sOR4lo8QSahYvsdBtMPZ4bMHhpaDBiMMTEosGqy93F6ng96e0cZG8DMvhEhgARsv9zKxgnjZrCSJbvVKsR/YgbZQByY43Ljv88KXq517SvOb8xFQMTHAAacAAmAeIKl/RwnYHAVGJQQ0iHJMfaomPH7/LbicLpKAEFBBJdB51HVAaB9Omtu5l9PPTAX4XG60dbodxyH2clpn8seNEDP5Av+Y/X6vMmppV7+g7meDA7SneBOKqqGv5nLVNJwd32s/y0y/h9tsM7J29Pd0L0E5SDmgw2VBLXS4yW8IEsOX4e5xW7qAj0+rygUsA0kZ7dWMdsHA9bJlzczv40tvqcttYAVlRfPB5AzTZhbwgBkYtCwAUoBiTs5qLN6kwrz/ESPrfzVHTDyjYgLQObQhVqwXUyOzA4LA3LXQxe/RF4IyuAjoauKPlkLR7dd+sPat9KlxRADlad0dBgmH68ZNAeuuE0pWkmckWfL9qkkGBJQMydcjFXPH8faBokDQpny916TYWqBfP2BkZeDok0mzXoqcVuXkqZalia0gasbyp3wUCXo7qjFxeurYx33lrH3ieyzRUe/S+ZdAhAEEAQSGXPnHP0nW7W7Y3OwR8/bamJAIgjKZZN8oUTfY/CWWMZ6bky2DUgPFaZp+xEkVNdH/f0uYT7Si2RYeOLjgRI2U9MsW1/J5fsZ3nxTzjr984KnkdHuDWeZpEF/1vu2m/pzurD3E4ifBynu7RJfMgZnzQ1+ck+1s5KHAiUKm23KHz5E7mnYIy4wf49JK6KtfF2fY+nZeG2Tr9PhMxHbFscSuQVjzbkE4aW0a2pcSFtNYJfz1ggCCFCgAkRY08z0D2oi5sdzUpT9k1F6hEE2quPXQaFr56MehrgR0X7cI4YAWfyq+bJhSGEE2OxB8iZrDtokZ3TIsm3wTOk+FPlEY0h3EiyGM9eCv0vXKrix/VX9mIb+GZNSTNi+UXH6BvQaQtW5q8K/A8gACBdSsg76uiBfPdLSzpVRpIF175YAgr45dd7tlTWxGz3kyt0nZgqdIVtf9Ym7Fl/z5qlkaU2gfkL+4Lp2Ng7HJhDLWHxNJpOk6Av2R3LCEIAoERDJrtgq8AGzwBJkOH+1Oi0uPurvJLdOUxX8lquFvhAM43uZLYEMZGa+7qIc1g7zbwVvFz9P6/eTAJCvcvcfBh46iUUmWyim4t2LuSKcKEh7WyihEJaaDkxQVkmU1kU74hcAAbd/////////////////////////////////////////////+Abvwb16b1K69u7d1d7vdrur0597y8+76d7tu993e3uzd67nc+ve9eO++t7t333e86fd8vvbd27633vfHpzbs977723d773Dtj5tO+91vvZ93u933vu77uHut3vXb3fdvuvnPvvGVU/CMEyZoyT1MJk09Ck/Jp6qfpgKbJiMEwFT9J6p+jJtCaM0insqfmmqn4aBPRMqfinhTyYIyYBMmAAE09TBMTFPEbTU2TaIGg0psGQyZFQ6qfmiGAjJPJgQaPSYCm001NgCJmp5kBTyeppNkxqY1MTJtNSep+mQDQk8p5GSemJ6npTYmGRkxAyaNGhpkaGENTTTAQyYmQxHqaZMqHVT/RNTbRNkJ6mqfkaZMTTA0Kek8mk9PSegJip+TEbVT9omjCYie1MTBMmRptDBMjJqemINGmiZqn6TKn6ep5NSbExPSYE0n6hk9JqemnpGJk0YnqaYEepQ6qeYNCelPGpmhqabQmmTBGCPIJiYnlNNPU09BoDEaBpppoaaNMSYR6p5MU8FPEYCZoQwExI2JgU2gxMEI2TAaTTJmgmTCaeiohTyYNJim2k09I0Zok8ynpiaBT9T00xTyNMk2jQynpTaNpGak8Jip/pU/NTENG1PUPVPU8jam0TKepp6PQmBMDRU96IyaGiaemjAJp6RgKe0ZKb0Jppg1JCqmBDRlPRhMTRpoyam0TKemKeInkwmk8E00ehMjQZNNGE1MaegmmNEaZGSfpGDUNGJgk8k8jAI0yZG1BkxpT1PNJ6CYJoeUym0wjamKCTZcAYyAKFUFBYACKAMDSw/yQQFIQACgKAEAADGAIoDNeZDKAAdx2Cg3PA2gCJEEWFKgHjg4yeEnlVbAENjAqh83XnhgLDz2wymAaLq4/O+RoeUFAIJ8Kj+RUky6uXQE9eRmo/AVRwsDcOBCA7emBatsbSxAVgTYCcpOyiq6h02zYdRQChziUZA0uT1rDtcJ8z64jCeYwoHtOYotV2SsGqzi9xij9mqQvF5+NKxni1yZGD6Gh7poS/V9Igxptmlt64gKKtvFv+yA7lAsR7+YxclbRMu+/RNZZKeDGl6d3Q3BaOkih3kwStCiOLOydDz/AJ/9BKnN6GpylSKJPF7yBSpWuYVXKMDt7sPiI9oq4KRwLfWG8XuIqD0y3D7UftYebfup9Dgm5UGanNGDjTCOJ+uS9z8bTsRSZJvHl/ywffJamRouJc2/t6j+G5Y7nSkvYEmENBndga14TeYW4wjDKG7qLFS69Wuxc7zX6GYdyINqWRx7eypYT2eBm/rcz+UpogAB9en6HxBm47FaB7SWVXnVLqzQhgbUEuKfypNf4ADUQ8HbgeJMt+IsBdjIoqYvCg8XURaKZaEqGLcpsqp6qIPxuS18BQlneendaDKeyW9nyxX7eoi9LDRbh42V9k8Z4jnuhASIgj9Ox2m7h7ahL2DthjJylaCZPNMjzAnVUMazGLqxgS4z5l2mBTpFPIZIpxelCsIIJuDT9GN28J+hmrNh4XyOXqvUHCJRNrBf41GDXWwJ56omL6eHSjk/EPoCT6sRX50RntkdZ7f5Nw8VeQ/DIy7c2wz13+DGR/9Fu6wTPczrBz67v2wZtANRKsBerMCXmCoLrHfRNBHTGESmXiep515eud3qkEE204kWnLnElB8A0IrL2PD8sq5FthnJrmxyOzLXN0wnpS2Hgge/9BMLVEAiRa/uN8SU5JCdtcTV0ix17HXcbidaeW/Y4WCTaZJHZPzP4oT1gYQk2YDchx/WS8bls/KoKyHabIwhEHg9yc4P/OXgMiM6RbdUQnxz8aznamkHYQw897Rnn4pDlaBLLvEBWRaz38o0JGwO689m1bGgT9EmIx4HgceRwECvnt3QfxqC/7aBdW6iONfzNivm9ezuF1zFQpRT6bfQUBbEEK3EAfMdLg7/t+vBlV+UzeBQkH90gpO4Lr6TpRdO1gQNXVnQU++k/CasnFhOAEC7d19uWm87uVA+p74fF8UpmKCbc9SUaED1Xh6cQCp1IK9RTfGIyV3Z4z1HsbIzGfZ2rKEaNWc/abgjcAcYN5yMBYIpAy7F4hSfzbP87m58Q/xJnOi4hIDcqiK9SUtDLzZG0rJi/67ei1FeBjSrpVKh6AgVoD23Rs6YTfSmbHdyckLcqsJhUJPn/Czdaq80BktU9JMKd7l9Wu/oe4pFpIob31Sv1paoGu9uiggI530cBF/HOyzGLmXRu2VdqA6NI6etBFEjQ9EfL9Op8VsS+xHgttqHNqPeRx3ip8arbSjc5WwPmFBUCJQLiTdZfSB8qppSt8mKrUdw/BNxnNOb9Fr+NDGaeZ5AiLSpyC3a1k6P+kMIV+BffD6QzCgUVkF15ODVFl4M4MDCV7KMKlpFWJHKDfqRXyxR8kmvs/0jbyr/9cfrwstFcJZfbEWLKiQvalP9hVo4G5Xl3v/U0EMZpcS9e031hSd4orWznBJi90HtgEzDbkFfrDyXhsk5t1u1thKHk7VNVwseXtzFpcWBH4o4z2d6t/R8A2YplZXZM4Il/vO7m8S6q2LybduA9eTOl48ZfOcyC+Ae6T14Kh4AlVfv2XknQ8et+qrz4HftZl0DZOCcYvOOE9R7OUsH2bvrHy0qqvoprfczy1HlS/+983QSLhEBjAHIheuoOZT22KXg4HEyHyBSUWbmo82tAGjRMm+0orkaHJNBKDQ6PQAC9VCBsc4hskYTnOo6be6XlAKKP+6TDXoNFnY6u1g3P/SRUUall2B86YfUqrwSRyGkTyV1+N8uLtlPxat2d3nygBNt/24bwmboCMu9y/aSmYKq8WpZJ5W7a6ZLamsYQYor4GWGrwhvpxElALKpeszfTUc5OZ9HFjlgdfj02rBFnmm7JHdA0SOCjiBjLWY1zbElD4ECojc+PyMBZnwdSClzqJ7RhNusNuVqpFGboA2OtiB9eTrl22YS/ooxgUtw0TOa13GAVzLceEOJN95ceN5aunUrvM4+byTtu211qktb7FJj1A4DmlXB1oc4cf35oJ7Cf4DT/ZrbfXFYb8vHDV4q2pL1Va1Em8dpTOFxjvKpn4UTtPofbaOXo2bLktrrgTIGk8zJBVrQPyWipCfm+Hkt7Zm1pVFrfIv/0pjys1ytWSm2xskZMf9aEVqxHUDkugYWImAYFOeHr/C8I+NzDuRoDhbQw6CBkOX1LBLUe5uZyHzwh+PZqzb5I5OeA2OJ6fhcd/IAKVASaIqhh/R2fOk0DyD+yEi70wsUB0pPIfItae+RATDKJOFxo/ZJzkXy7f3hvbdaEmR9FtvoJCd26b7K00yMru0UZngs9jlPjIVbLpfwScdIxOEinlTpB8/TaQW71vlrnA2Is26KUMgK3x645mobG1ePMx/scZj5s7a2h3Z+n5+MrCTTzaB1zjSjTqPKqRIRF5pibanxcNQtuQAgJECA/elJbetXYXuEQhZW8DkINqOLp1kIljLOgXygu7fqxvpXTpv18bbtf1OEzhs1FoP44Z7+Ig80OfgkacEl8/yRMUxt0kL1l2hofoM2CsqShTl4P/xygF7UrI3UY4bJhoHeswfJ2Be5Dow1VLDLmk4Lr6q+ARyB1fQ38M6eWlsEcMqjZV5P599BGqZwTWAH0sUPrzRkUgtJw26xvretnqxf65Dz0AtHJMzUhFPCSgek2X9LN+ZsTlhKYyknqnWex2pnV5Bu6Zecmhs6KcpooCkK3Spm0S1lQbMaIWL9dm6gKBcyji50Pt3/KrzuMrA+XumpXb94K3IL11bfuK1ZpdpBlrrPIzP84sThGtTIfedbcLCmXFa0hg6yv+1c/GrYv1tm9LgXcl/HXR2Qvi0bVbYtZsvXP1BB9SjsjxSgisSqhmd3G2JuQwtbmYO6Zc9xHtNXpX6lANSdjTHUmF76JyqYCFUTAid+PoZ+SIb2y6JIhLNZVw/xN6DZ/V1D0LU7J/UUOxv/AzswMbeae75AZY1PX76GqH22n0IFm+KiqZBNnKGwTWdsgbI0tgIXZZanaGwBMyhlaQr/P9epjdfv/l5IP+APfjkc5eZp61WwMY6MZriosztj07MFVLc69DWizsNGjdLr26O5ZKqKNgIeMZ7Kb9jQ7zmOy7FRIv5ltlVnCrSaqgG/hqPhpRRbHPn1FDQa8NLz7z9dc6xvX6auTwz857yIPh+5G8Nb8+jzRWrpW675yFkWJuTcIlzZaJQEyz0jyinEmDeENd1X+uRuhZpIOOke9qtE4xyFdNshjSLsM3KifIWEcVxttw+PCangkylfMjsPIlbm93OnKkEtzwnLlclMB4L/wk4ay/ZkhiOeQ98tbo6ffSmVIMsH8TfEyadbJgshLn3P5kKdR4C0+RKZ0iwq5EKCWIsN+aVnPAVvGgsyj8DP70w8M66OxcXK/MaohlM20E6xhKOEKms7AHs5RX0FSdCrnfeBaiMrrL7qcK5/toPZ021sRfbOsRtB0R8NxUlFr0R0OEQIhG3XNydnU3g3DKErP2FaRlG9kQJXDgifofcf55BGf0QNdwITFp3WGqlYr2D80jqwUn8cg5LMhir4Q1XqdzpYUYqmNMQgI1TvdMnMw3HChPvC7PowCAOm8gO9M+f+raNFJ6y80NRUP0JpDJpIL0hVWCwmD1FMQ8lQ92G8oYsRIqmvwi+W21+AdulppU9af8cdUgRaAB8ryMN68iP7PN+MYqGFmKJhd6RLrOnfLm4Jn2IpqQ5Xz+20opxS1InnCMC2cTocjDlbHN92+wFegdk2C6yOdsorCPQBes4AHUQwWEfmnectS9peZuEGFnTkjgLSonqghPR9k4YYSVWQ7frl2hMa1K2BekZA2NUwTJodM0pOticnNkMJAqmcbPSjUieY7unojjnSjc+xUHJzq+uYrvu2GQo1lTy4IcjUmPfSyhjef3aOaK09pCVHtkcnImFvDAJ07xGtf4PIqVgPceiZsbO1gic2dSLqzFcWGdHYvuznYukVUsCYT7LjpbCBW7i+D9SCpVory2NWsDnW1QEiEPEOj+LvGcByRI6xTXGclY9HIGGLcP9y0i8zdPaWINvR7icM/KCSEmzqIlP1IY+8X0kseWYmeZa7TBfeE7PAXtmbQL1bFUqJvBYeWL1ibYrg4PwAlzX+NMu3sJ9lR2KFQ9XGfktmi5RJgmaN5sjpMaRg5aRZbPJi3tL0LWSmkqB5THQHsrn/ZOk7TY7N4QXpB+4c3naNchPFlL0TDMHKGbxXOlv8oCF/VWSXhpPZ61f6EF1q4BhTkeO6DKSCc7jI4W6zgBQZg+TsEUdhJQLutagfeqwPmCQ0gwPh4dV2NxkvRq9rxS1NQqlSVqza7vM6vb0ThV8N0efEGye+bhom+xsVoigdGlCrdAaPfe9ubpAywTJ4RytpbfivoKp/FS38FfI6JOI0I6VSSpL9C9CKj16BuzesbMVwIIXWHYJMBL/Oa2tRxg/F3BNndqzYjK4zkKR1WlU0ZbjLGOHAhGy1PwV8bM4OentS1RJJCzhjq7unGF3PLkr/d45y8rGXATr7bjKfoSCzUcLT3g3H1zId6bSwKVMjWD+dpmzKncPUWW3Z66vCYTHeHkR0MR18UkSkJVRD4jwzpYLB71arxfyI+Ahw3rWlGHNzOVU0rkSalkASSNYQnStiVCdYQsLfXHObOmvcPpUywznVZRI4OfPTsBPtp/IzbvZ/mDHXozQMej1RUPwD4TgKSVb7GBlF/EWRdIaFb0EG/4VLFBaReXN9YT0D0+btUOH33p7XF9m4A/0xQQCTxAO1rGYg9KRfNqf2beO+wbq/z/c5ManZvTC6JwgcKJZSIWZX8lKn8rtMNZcvfKjLFhVQu4Ba9HC9KldFtb8Sjvwm5c9NIJ8GoYPnp3ZdmtpM8LeTgjd3Rmfh/IPiEEXfa2TzTZuH+glLX1G7WxSjR6LVil9C3asj9ye3pemqMNqI7uIn2OFSoVNJvxWeicI2RmW2KdNO6Mrkku3GgnhMMPmtrZdwEgLC3QbMFvdCskwlCkIQfMpozM8JqWM96GY6jkiwYvihKvQT+2LX3T9vazNVyi01R8FBteiJcLeTahgykQy1R7ST36pMrVGt2O0E59DbzRsJ8wUOS79v9MzszuyvxmCkgSNJe0liZhaDwRUcIwy6t2cmBD5XrQTtsMkOXCcYe0OGZh1BkLjba3vB2L4tcdNsgsiltJc4K6wqDEc0eoSWbG9sE9LBmCDmpfMnnEWZTGtvtiDzYvZx18WDAG/ornNdwf0qtb/Bcy4dUXH6kdv4v0aPUky2H40/oKWcGsHjedn/1uMQ86o433BdfK6Ql1o06GKpu/SUy1Z8J/MtKk3a6S57TBXkZcokWFQWemyLVcAta7kmrMfHUC+6Fy5d1le+9pv/ne9J+RHgTU5H9HxnzFLiQN0KlLDrgJXWEsD7WYNzHALunXcqJqpUn2F0MPfxxiS3WDEXStzq73F5Aghb7GKbGByWNb18Gl6n56DSfC2Hz27xLWDygMAyGq/AwAy/JIv79RvF+HWMpY2GAtlfkEzH1zQnhJSljXDGHc+KdVQWc0ywigEJqx8JsE40APjc48nk5jazpfYjzUS50yOir2JO4jNmLKSlmX2M7FogLT16NUbMlby4y7yHU6tlFqYtsudizEKZ+QXmRC/z1kU99bDO0FKVu9N/sl8gqP4h2RmluO2Onw8R45J97lqBN0iKLosGT/GHekytnE5Lg+9w1dvLByxKgRpRFidtwTre+ZANOsApAtz9ioNk+YixowbaPP4h2CdeqY1BW0PhRNstV6it+ZjVbHcE8xsgCQa/xmaaru/ruidpqyJG1dEgQVYwXahbviflXaHtt324pmt81z0MQmQ9ElGjez0D/z4rhdS89uu8mpAuo7wUZPDkqptPJjuLlT6PWJcAAIuygFYA6A2bvF3LQ4jmKdpm5xmyeRzPOJZkt7o5BZevJxzSLQYhGywv6nnRcN0qluE8bzoxFLIA10z73SiyieJG1Jnb1qJ8YNH6mr3qeXVE3av5FxKAbFVOVQioUfFtbbpyESqdLEaYsHXqjC7B9pXqRzH0jh9Z4UKgVmzHlUYeASCsNgZFLw2UrLHTXH9aCH6jOTsYi+QtWShr3chYPuoxoKQim4f9z8G6dqIVBYm++eg64aABFfGZZbQPdhS8vywEGED5lcNir33fD7CWJvBpJo97BTeoNGYeDOp9/e3knYe0bkH14DYzTDS2Fg4/7qIF/89eQf2eyue8mz7LcyGPoCuvVg7/x0lD0e2N28Bvbh0a+83ZXs2KwEIAVxsKMrA81sJkwu6tsPwsyvWLbJpNsfBhJtfRnHe0RW9SQCuC7JD8OTWbtwHcHGkY9GM/yi33LlIfG4TEWkXDg5/5GlwcgcACTwAQ3gG+43N394T8KnsHCVaxXx0n2wZHIFDx9+jHrvmYGluxGLA1D5YQZVGk5weSMRDKKUCcPK4nYmTN125jy0/oDMNm9/kriSEuscsTUB5uoANUkcSNZ4jaVhwx9rf7xh+fxd/LZU7QaIr72TLVJAxYJDacf9vfCkRR2FetQouDOkJFiAFkcecVXOzlZYdCVTL+QLv3gHpHNkkq0e4FoE7yXAOb7VLjNJPmKvb0IULED6RrDnAQdqUn3TzDE3ztfJOgJkHmkctcyjmq2FdGdnbmyI21Q0nQ52uCqYmsN42oj3Zk/yxwpkptFCAJI+Lw1uBsXy9ZCXxaPghYT9Nen+gfchnWqhGCyZhfypVG3GgN96raPX48NxS8XXYEeVV+SEHLpYR1amdzJhf2n3rGY4ojrtYNXE4NbXbvGiFrhYDvRfvTCM2q/RBZj37n3KaNYuhN8j7l4CXuloCUMzi87UZIeAglZ1e51LrUPCB0p4uauv+v/KfoIy6fXvU3yMzWtIQJh4DbksQlRh2p2WgddGWmyoYK6aj4I1Nch6THORJK+hqoecw5TrUWKqfvGjQGP8Z/jHHfol/fPmaLzxomfyh0t0XCK2uLaJxctb2D4dLkwsjuR+klDBFV3K5oVGcQA9OGR/jxJUhPhF36cMQ1PfvI9WiicR89KSyVTtZ8bILIv/lbPq5VBsmrybuirci3eK4EcqFn7RF4vpmR546kh86eO81o0WRlMQLp4zpgEAfLDLsxFyOp3OhCLt8RR43YNpd/vJxuaSvwbIOxn+n6buk2+hkzs46b4m/HXwWnA7fDtF+5lE3vIqrQZy0nInPWe4FqXanSMc+gbpDMZvRbVNyqxJTNIhiW/v282BR3CXr7otqUZQW2Sd2+tNq49nwwzVB6LM/r1IQaIMCztvltg+fXG/42uAhDE2ntFpmKeCRcB1bDFiKj/uCXQcVDD+hGjHS/KycnZVTHJ2hS+Oki5W2r+7h9Pok7LyYLO7duWrnDE7WvLRs+GTu/Vq5+GuB6eAy+JDr2ea8VupQhgaXRcYRRoV8ZxuBMqG78wJrRp31bRaqGccuxhuV0P5AqB06kQfqHCUPViMw+A7ubjdVoSmqY6vbQVBIq3bCDqpXKFyBVc6Nh3YmENxapoMBv0yPFjkYlkd5x61NtuHMWL5zco4/3w6U9DG82VW5tNuw7og+jmsFFw3G8RQF5ZhGUUQ1aouju/P+XaLbC8Wkn1h8ty8fpqbKXys1jQO/QLobNhSzfMYeUBD2JWr2Aw3W+mTwq0Z7qVqSzimUvmKX6+u9PZ5O8fTaeN0Zxc7ulAq/yNPlCFa0rHePSWVC/eLpi3suhCnBuAr5scn/3eCzAtb6t21z6ZGFvgjqs6t6ZptqOPQRGdmIqIg19dGgwZoboqyCz1vm7vPD+vGeou0ZKNisFEz69iR5pAwde/HTkKxFrXSwtjVhTPWK99iHGxnePsbeYNS66l7qDdFJuL6jO0Vd/kd8+ADAR7tmirzj7Mef5+vSoGg++2a+Ha3uf76LAltFdyePLDg8SG3vuxjZV1DVzLbe6hxMnbHdeejyXfRNTSwCJ9rntvdrrt1hHAzvWRAQxXdMLoXl3zUu82J4b4h3XOmqGSud80FeZmtsWaH+BeffW3x3lnlTVqdpMjnQ68D6xZzupGL5qHtmNDCx8ZxR6k0hUkGVlzfcn/KfWl8epViJiKUFvy0gHDRverTgEVdvEuIRR0WhG3oT0DsRD3ADoFU6SEmx4xZI17RuoyJHWZQoGAmngq8Jz220y8xxDr+0fi+Mv1fme5juj9be2zdClaNSHN8GrA7avXSUTFHV/Xaa3IvkihU/UsryFjQ1La4aIeWE1hKjPfktv3KLrxExZmaSn+TeaDtYMTNRTe5PNYObfGc09xip+tTSFqih3biw9slOD0KH8CknpMovWsocHm/y2j2/pCjGQl5ryrVNHNjclAc4esuq3PY81Pr5BkLRvKIuF4vGlW+UtUA2Od/SFimM20aAreN7tPrTJiMhHJHFqC2va/0+79tK5QbaQIVNxN2RhKH5rwPhCcffcjZe8ntaPe6V9JR7ro7P4Zux0dySbaK6LUeFDeyhoYrXS5vBQnk1NhKef7BjlS6iYV+LJly8tNm3Hfiu8/mvkCsPn9ootdCrL0IO5zHTYgE5pd9ER1Ojm8kcobvMYbbX140NrM5oUQ2ip4SPF+o/1jUG7zJDAmVzX9YWiPBbIM60XBvzBLQAwXqj7e0mOEeVnZf8WIviSj4tC/ovyhfnxULBbFLoGF+Hcw32HzlZmfnSVjF5e9ZNTDwfVDZDqluRuS80vZLJAjqrZ18hkrs2GHGS1EXZ9Cxsz8VLnR40npLndJQF5RFDzFylMtbmvAgzTmgy84uvKeZIAf4DxXrC1914ZniPUVILF5Vq9HnNDtWPB+jVY+U8gD/w3u4kF+c5lWwOwcjwqsOeA4BSZ+J+wmCa9jn33238eQAbjwiCsTe81eYlMoVURgJLoLocVwPYD3MDO9m/IZg6e8uz9JiR/odI/MhM1fgnhY43uhKvcTTzLC6Pgw4vbQd/rYMenXiufaxmFGrvDiIjx2r4NVWwOabCGlKK5qb77ONGxctAd8kanLhUQ04nDOsR/V3oLfWRvCjc2rXJL/dPMYkTqE43p9mBSlfwPaqYyyIrK+0fkNQV8o1tdyynfrsEfdNDsE1zEDd+Q8CTluaV68Q+cuEX4nmilp8xXvuEAg7vlthfNLX3IYfO038PxDE4i38PM/FiEqayhFWn2hliNv+RroKA9oj/D+Z2DfSFzd3lIfZlMBGBU189Hmm8h11VwRzGTpZzvW1nG76kLKEbXbfG9xtNmLxUmJZ7ijn+ChDWEKF3wzxbCnPuV757r7GECLrcLy7ESO1NqJAEq53LWueK5cRRrblk7tHjlbjTs6qCGklb8eUbRR+k8EXpnjMb9Nf+tgA6fw4LEQ66mz1EX3rBLj/0JMm6W9mEaU1lqQ31xOfbXrYaBWEfBNkCH1/OzWjkoT+crMZXP7TIRjVO0neUByNLQby/kN/kWZurRqK3h2fM1GeQ5hN1Y0XyJUJeZJgqPM3ktamQ0yHwfaWyxg+xYm3Ms5JYrs4x9XVqWyX1FqgnaSQ3F8d/UnK6jGtryxO8NvNliecUFscaiJgyVn/eSK+LSWk2YnEqILrrGhnQdkU0p+ofwI2Vmj0GQFnp4Ug1FGGOBe68J2sLwiP6+XUqu4yFz/TQ36Ag57xe9vVorAR4y1k42b7MnMqQWADKcbTlF4JZSHJXrv4uSSnN/RHA/btvVr4XIAsgtd2Y6MFeMsXN/V96S2WX7g8SI8BGf3q/gID7Wm9IwIyHrbzEHfZZyOgFc2/ECbR2wLrpjfD7yTt4Ey9X8cRqYQzO+0RaCnHboGW5CIC1M+fMxMiJGqZQv0RNp6Ax7hSvmEc/FFtWhUnf+di04AkNwWc/EvBzQOeCOVf5N3Vdw/xzZ2BmK2DYLhGaUKnZHVEQpHvAnn8HV1xYeuSf25jZhGZMKo2Ym8Isr9BUAv+Ae9UxRGnqANfPh62PEgXVSf73DFeRsIj10DgTGUxxLezVPRGPOjKvOkuXj3qhgS8tUW87Nll1k50Pq+AsQHvY01FTu6MZgMCY3WCxLW/t+wTBRG53xrno32JC+aWfeU5cNnxYfTyrHa2AWQpF4Gc6svt0xKmAwZjonk8gMexJM319vdyaxEuM4fSuIVvlWNFl15lcmKOt1lBnawlbxC8+hSZHTlSwnysheIWf5lwWDretxv4Tb9HIRlOJxpeAbERQzTuNFhr21Xfe1zcru3oijqhb9b3MiYQ5/q9m2OtKR9BaU5agI2bqWHvuTqAmkoUDJNcC5dubv5m4V8T/nZ6q1AT6l+QLcTDX7jAJATR8WVslrYxbsmFA6mf5Cib97qyE8cRF/ur2pvX1KY0MxappmPFOeMZ+AkGYSHdPqSX7nDyGlE2qtDficfQQB+9yWk7ZOwZp/CCk2N8NG0z14rPGKpgkj5M9+XdDz7hAINNa5yblrh2P2K4b4pgQJ9nv+q+/38mm8eEWA9IDmfTwCXcA3IlkfbxM5OqrD833fLssdgXoEhiFmsY85pzsHrt9zo5mdmeBAZs9yvyI98v/F7Ht7n28fxLVJ5Cxy2pS9OEyNPlhh11bBRis3oSd72MDqHlUTGx7lU2Eg6FF7sSo3k29M/Jj044uXGDJaJROENV5r2JIuc89vvmiHeYLjY4/e0TdJyCwes56ElZCRbx9e+1kAtUPTpQg2sxYjOiEWlXrKrLDapNn/PV/JKe/6t3dOzKxoyfSLRbnQDpeTtVe/9ywH580HVWoMWTqbEpqoaC5LM0KIydBOn8ef5G0nWlpZ4fRWSrbrTe60N78Yf+xChKBBBZ4OgMln3LqfBx6qsEUX22+ZZgU8hgkFiDe+OdejU++fzYPHkzCSwA7dvf3I6RhtCx9mJPXFIaqcz3c9x5b/BsN9fHybkni6330K5w33MKHA7Qe1dO/XWpg0yTgyYMSEU2fWUu0I/lj4BnuKWWCXtLu5YIcp+Tqa2yZm6qUUACSZGemqVP4Z8KdDZSWPn9ytfCtyox44Kh8mnrmVyevvP0mSt1VmVq15kXXhO7frXa+w/fgWUxg+OAxrfjh3ioDMJLhU3lZV/mm30G+5/13Lkc+8E+9T4t5jumtiCIWHazVBgmT5uMTQPoNcvao5xDOxYZs76FsJXtfXWO1b8TD8GMIfosddHBPGfq19HwWdkn+p9Tfw8jw1soBfEfDjaaY9ntwMn0PY9sWfN6VSSrI9oPcz8WYy8G4XRvNtp65hXx4oKr6X6fEhAj4kWkodKWCPxoEeG8R5dMZ34g2Gi/XE7aNiRXkOlBlPx3fV/FZwGB8dZNS4cW+vlHtQNInIFFI0AeeGOikA2/05c9wISeobPCurj9DsOAl5qDJsv38I4MX0xkqvR8/o+RHntn/sdHI0zhzpgdCSzJBv5oaXfvOUVvGj2Fay2kBm92hL9Kjthea4Ie/vH3lQy5gwYiwSYspHK2Pf+NwJGT1bNWdJJXSxPi1xBSkhv5Lijwch1+RZ7toQBV7he1T8sXBeyAf+UwU+wj5POMppmUdlcZMXxWAm2ZjIIouffaNV9jUj/cCtEyyy7oumrFYBiTFiERGV69XOy7y/ZmbH50PTfUtn8whzlrvsP+tquFC/x4W69rjQegvn7iqUQgR3FFTwYaryLNCcM2g0YvgWXcmrT23kF73kigQu8q5umHX8d4H3upyO2FiykCSvRwvKJd2jbdf0CyOOxfsu1w38NUgyaCpi/xgU6N0VPIDpk4qampph5bnXaatPf7B3PBSi8MnqKGnZXKqwMJ8vAcWIn4Iu6Q0gM7tcz4trn/o3v3ZGTGMfhszieCT4rZFSM2oG23Cyt7CVZ7++4PaXCEC6/YcxflyT9C7nx6eXqJ3sWdZU4MWKd9cVjbVAohouTxvjrzyiWnjAjjBv8hA+DAT1j14q4KUz9qL9lF6DmSPGCCYw6EYM9aun1idl7NTQIEOwsd7CX6RfvhOGixSnYOLrGe5o5qCpnWezPfHiMWHMOdJ9ToiTRTX6HcAMKaPK0xG9/y4wQzjUx38UwaFOcidYq9jP/7TZ5Y4+vfZprzdXnnnn75InZ80sqV7zVJJMUdBayrRwH8k5gEksffx1mra1hNgng6VxfHqOkXTT+YgTj3Q3BdfGIvy/H8zlyiXQoF3Y8pthZ/ENflLfKsuWGcva0L3Bt0y0Yu+l9ez4R3BlhFfmiup9Wiu/LnuBcwP/Wb8zrTnyk5QxKTDeTAl4aC7i6q7GMepNzAb/4b5bBNg94PXXxOohEg2ASa+lPfeXuVuagB7jp7OP5yshx6W6LxucKXKswmdIudvpTxAKcSaV2u99Gz4whOc5X/NitQGfmyxtBwWEOpEl03NVvh1imTE2FY3TY6ffrpT0oLX6fL6Hgwrh5ZNhZvoM3IQuxb2M6I913CjlUjC+m5zNA/GcqOrgoA4HFYqirNpeoLffT/O7iPgnLWu8lzI0MB8pn7Aok8LkOKiPkzHP7erIqOzyiOdUALzEgMEWy8ec5POx6bai2Osa6XP7YwliDcqIMUqV5TqCWT3ym9xcDIjjizDjeulawwP7OHFfC0jhDm6JyRilG6DAfH3TySYfDZAovUk6daW4+EkQEc6kx7v8t8oW8XdHPQSqF3JoLF3DR1Mh7sHMrkORsGYnsEgztm8iquapuGVnC2+frNJ+DGlpAJq8ucS22NSiNxvQIsjpnkdOwUWh2WSPfU3o9TsxEg1+helyjtPl9kasCuxhv+/lr8lohMwFMfDLuBNX5WhLP9lzewn1MedJWBZAW/FDiZW6338Dh0cIrXMFRAXl+RNrsZdgdLwXotzGtJu1C1Rq74EwDSJoo+3Z2OJYvR7JcYGoZJdNMHQt9bx4ob4WLIbpb8q2Qr7fVtevZJyRCF9m0P+hp197MCGd8qKz48/+gm7TpJrZKRzu/1yo+Ud5wNFvvaMTupklAfAcHEYKei3a29bybAhngmR3V4cppRJh9W/HbUC78HyqJZC+FNmKdE9nOMD8MptoQfDg0y8Nq5VKweVsC/udEHZLvMdu1ktxWSXUwe/jzm7rovCVvDfKnLS+Ncarl53pRY36FL3W4GwjujCVwIg34+oTRb6gzLH2OVUoQmDod12GUHstUA0mIrJ2vPxH+bRHLx79x3uND/Mc9zeoVYudJf3uGHawvir9XJJPK0+Wdb3noLTtBBwkxDW1lClrfJ+k7yG4LcCwwGLKmYkbCL0argYUWp9aoJhHwuUgNDL9TK7Eu3PsjkZbYvrIFDrYlXPpAMaHJW4aDMbz4YhUZB0Y2aXvUF4tD79rfuENoa34PDRVUNXFvALlQAFCxJo1RsJbS8puvG0utTU9Jg+FlrIraL484xHdrd4kJhMDwdzUQF8phmw9vdNstflXadGEbGfo4lcZai2uJJhI+QKCuVsN6rmRIAmTA+cLJYWq4yhreb8DoP4yTlqqfRltoXjLslVzSw3WjdHizx06E2tyuh+1XohV3gxcczvxXuLVSv5WvjuDfNgwRTuWXiEcEpVLa/jh3vfH8AW6G+1ZOT1MI2UDLuom/yze8Hed9Iy+ovyMQWze1lrqYtK1o0rxsbAlQ8g5ZiZNJakBqq0Vc7HNttx+D0ez9udmL8JbjCxPEJ76pZBF42jD37vmXBgEkCEKZ57Um0YK0iIwAy3lE/oEb2RYK7r6am8/0MFcilQocoSeuXbCjpJ6actx1ST8TRH9taFOuS5PpCq3lqHzJ7+WCSx0+Z8KxOoyv3JET1p1o/9ihRwjE59z8keosTUL1JrwYps9U5nYpMMMN/CvHXZ9ADSucOHJF9JJP5/WDq3szZzqGH0ffBaQl6zkcdKV/XIfrwrIHiVDpUNrpqbcgtr6XA0VHeqGhh+1/V97sVFAUTlNfBlIDz/c6YhzTzJ6M2LC9by8tEZwZ2UzF5NCSx9Ry6S6Jvig5CdzT1awfYF0ZsufjP44X09HekCbSCDyMURaB7VexmvzTDBEdg5WV+5yT6vlD9mjZbt4HKGWyQmUjOe1Fu6huPz/U7UzkZ6Jo4nhMFRDWiFMGWmoJtvfzVUpEpud1Z6Hfmwt2ZitCC1eV3uO4Ce6dUSD+jU8JILbg4XqiqvG8PRUyOOlFaP25LQPjDXVAIUZqqL8rDLp6slVveox1DgZOz9WzYcoyRXeqqwHQOZtJRl8LrdrKxxdbycj98mnSkxGJkwsoa72D+JLLzXWHwynPC0+o8sgzKLOQ1anT9EzJF5eK7TtyaN6FTrjdazoxbqMnO1Jx3/6oNfoIcmWrJw+afKlAZD0JVeR6NbZOTAgbbKcQsBLjX9EwqjLccgW2Oo2p/+LuSKcKEgKd8QuBCWmg5MUFZJlNZ27HR9gAFGv/////////////////////////////////////////////gE/8G+e2tfX13bne3t2r7zT324+7vvfe6b2576zrne8++72fe+3mU7vtve3veu95Z71573brvOc769ffN1963Ns68a72+x1NpNNpNpHlNpNE/QaU8FPAjTNEyPQBMTAGqfqT09GRPU01P1NMmmg00wnqeiniBpiaZMTTZJP0Uep6abVMZGU/STwnpTZPRNNPTRP0po0xk00ZT01MDJpQyqemTJhMABNGKe0maJiZMjExMAVP1No9TATVPwTRtU9No0TTT0aU8ATJ6mptommhgp6p+KfqaYm0wg000xPUJjTTJPRMmap5PQmmJgnoJNqNiodQxNM0mmT1MaEZpMNBMAI0yeRqMTTJk000GJk1PGpPTBMTTKeYhonpomyaZA0yMU2KaZpqNMU2mE2kYmTATNJk2mhGhiZMk8RPBT1DKp+pP0T01TzQCniZHqj0NqnjUxNMjTaaR6TKeAUfiNATam0j0YQwibJoJkYZNJP0FPaRpk1PExPVNhGoxiaaYjE1PTJiaPSZDT1Mmj0TBPQASHVPCjyek00DTU2Go9ANNGJkwVPMUxqemUehNG0RimTemkxG0TTaI0ZTYFPyozNBqYpvIk08ammm0mRiYk9NT0ZqGAKemmp4J6JmminmUnpPI2mp6UIppGpkZMTENGptGk9Seyp6eiT1PFHqbJieiT1PKYelNPUejUGm9U9R6jZT9RPI2p6pp4pp+qeaJp6k08RoMJkanlPKek09Mo9TwJ5E8qPCT1PKPBTyjyNT1Hgp6nphNHqeqNSB2GcAJohjsMBIYYCYAIMQGoBypQ4VJgAA7gWAcAEIAHESdwHGB6EZEAwOwgLS46YTgBD+mGbRmvCPjFQNtxolhiLgJLE2jm0ImhDBcuKVrbyHkQZ/cpn4Go8M1DX/qDKR4qAgiQBwhZk86NgEZWVeFQpfcDjfQRG69msuk+Pubet2DcIZjp6UeeTPK823ysH0DS/JLAjGE/JxwiajVvYfKxeKV4c5ClD81Bd+4XwXB4WDbhb566ZI3oyAycsJeswqvnl/Zai++Js1PIhHiSDo+Ig6qowZy70p5JXF+UQquahwUDEKWUp3qfWB4wG8SBuBueZBFPYKOWYyHLlWWai6FjM/tHqYmNrET403pCYX9Xdh6ypBuPrjGKNE1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"
bool InitBlockIndex() {
	// Check whether we're already initialized
	if (pindexGenesisBlock != NULL)
		return true;

	// Use the provided setting for -txindex in the new database
	fTxIndex = GetBoolArg("-txindex", true);
	pblocktree->WriteFlag("txindex", fTxIndex);
	printf("Initializing databases...\n");

	// Only add the genesis block if not reindexing (in which case we reuse the one already on disk)
	if (!fReindex) {
		// Genesis block
		const char* pszStartTopic =
				"NASA: Humans Will Prove ‘We Are Not Alone In The Universe’ Within 20 Years";
		CTransaction txNew;
		txNew.data = vchFromString(GENESIS_MESSAGE);
		txNew.vin.resize(1);
		txNew.vout.resize(1);
		txNew.vin[0].scriptSig = CScript() << 0 << CBigNum(999)
				<< vector<unsigned char>((const unsigned char*) pszStartTopic,
						(const unsigned char*) pszStartTopic
								+ strlen(pszStartTopic));
		txNew.vout[0].nValue = 1024 * COIN;
		txNew.vout[0].scriptPubKey = CScript();
		CBlock block;
		block.vtx.push_back(txNew);
		block.hashPrevBlock = 0;
		block.hashMerkleRoot = block.BuildMerkleTree();
		block.nVersion = 1;
		block.nTime = 1405483400;
		block.nBits = 0x1e0ffff0;
		block.nNonce = 1157535;

		if (fTestNet) {
			block.nTime = 1405483297;
			block.nNonce = 1565196;
		}
		
		if (fCakeNet) {
			block.nTime = 1405483900;
			block.nBits = 0x20008ff0;
			block.nNonce = 214;
		}
		
		//// debug print
		uint256 hash = block.GetHash();
		printf("%s\n", hash.ToString().c_str());
		printf("%s\n", hashGenesisBlock.ToString().c_str());
		printf("%s\n", block.hashMerkleRoot.ToString().c_str());
		assert( block.hashMerkleRoot
						== uint256(
								"0x45eef7a7ed92208bcb532a58c3048bc38a299f9edfd8b48b677cabf4370274c9"));
		block.print();

		//assert(hash == hashGenesisBlock);

		if (true && block.GetHash() != hashGenesisBlock) {
			printf("Searching for genesis block...\n");
			// This will figure out a valid hash and Nonce if you're
			// creating a different genesis block:
			uint256 hashTarget = CBigNum().SetCompact(block.nBits).getuint256();
			uint256 thash;
			char scratchpad[SCRYPT_SCRATCHPAD_SIZE];

			while(true) {
				scrypt_1024_1_1_256_sp(BEGIN(block.nVersion), BEGIN(thash),
						scratchpad);
				if (thash <= hashTarget)
					break;
				if ((block.nNonce & 0xFFF) == 0) {
					printf("nonce %08X: hash = %s (target = %s)\n",
							block.nNonce, thash.ToString().c_str(),
							hashTarget.ToString().c_str());
				}
				++block.nNonce;
				if (block.nNonce == 0) {
					printf("NONCE WRAPPED, incrementing time\n");
					++block.nTime;
				}
			}
			printf("block.nTime = %u \n", block.nTime);
			printf("block.nNonce = %u \n", block.nNonce);
			printf("block.GetHash = %s\n", block.GetHash().ToString().c_str());
		}

		// Start new block file
		try {
			unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK,
					CLIENT_VERSION);
			CDiskBlockPos blockPos;
			CValidationState state;
			if (!FindBlockPos(state, blockPos, nBlockSize + 8, 0, block.nTime))
				return error("LoadBlockIndex() : FindBlockPos failed");
			if (!block.WriteToDisk(blockPos))
				return error(
						"LoadBlockIndex() : writing genesis block to disk failed");
			if (!block.AddToBlockIndex(state, blockPos))
				return error("LoadBlockIndex() : genesis block not accepted");
		} catch (std::runtime_error &e) {
			return error(
					"LoadBlockIndex() : failed to initialize block database: %s",
					e.what());
		}
	}

	return true;
}

void PrintBlockTree() {
	// pre-compute tree structure
	map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
	for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin();
			mi != mapBlockIndex.end(); ++mi) {
		CBlockIndex* pindex = (*mi).second;
		mapNext[pindex->pprev].push_back(pindex);
		// test
		//while (rand() % 3 == 0)
		//    mapNext[pindex->pprev].push_back(pindex);
	}

	vector<pair<int, CBlockIndex*> > vStack;
	vStack.push_back(make_pair(0, pindexGenesisBlock));

	int nPrevCol = 0;
	while (!vStack.empty()) {
		int nCol = vStack.back().first;
		CBlockIndex* pindex = vStack.back().second;
		vStack.pop_back();

		// print split or gap
		if (nCol > nPrevCol) {
			for (int i = 0; i < nCol - 1; i++)
				printf("| ");
			printf("|\\\n");
		} else if (nCol < nPrevCol) {
			for (int i = 0; i < nCol; i++)
				printf("| ");
			printf("|\n");
		}
		nPrevCol = nCol;

		// print columns
		for (int i = 0; i < nCol; i++)
			printf("| ");

		// print item
		CBlock block;
		block.ReadFromDisk(pindex);
		printf("%d (blk%05u.dat:0x%x)  %s  tx %"PRIszu"", pindex->nHeight,
				pindex->GetBlockPos().nFile, pindex->GetBlockPos().nPos,
				DateTimeStrFormat("%Y-%m-%d %H:%M:%S", block.GetBlockTime()).c_str(),
				block.vtx.size());

		PrintWallets(block);

		// put the main time-chain first
		vector<CBlockIndex*>& vNext = mapNext[pindex];
		for (unsigned int i = 0; i < vNext.size(); i++) {
			if (vNext[i]->pnext) {
				swap(vNext[0], vNext[i]);
				break;
			}
		}

		// iterate children
		for (unsigned int i = 0; i < vNext.size(); i++)
			vStack.push_back(make_pair(nCol + i, vNext[i]));
	}
}

bool LoadExternalBlockFile(FILE* fileIn, CDiskBlockPos *dbp) {
	int64 nStart = GetTimeMillis();

	int nLoaded = 0;
	try {
		CBufferedFile blkdat(fileIn, 2 * MAX_BLOCK_SIZE, MAX_BLOCK_SIZE + 8,
				SER_DISK, CLIENT_VERSION);
		uint64 nStartByte = 0;
		if (dbp) {
			// (try to) skip already indexed part
			CBlockFileInfo info;
			if (pblocktree->ReadBlockFileInfo(dbp->nFile, info)) {
				nStartByte = info.nSize;
				blkdat.Seek(info.nSize);
			}
		}
		uint64 nRewind = blkdat.GetPos();
		while (blkdat.good() && !blkdat.eof()) {
			boost::this_thread::interruption_point();

			blkdat.SetPos(nRewind);
			nRewind++; // start one byte further next time, in case of failure
			blkdat.SetLimit(); // remove former limit
			unsigned int nSize = 0;
			try {
				// locate a header
				unsigned char buf[4];
				blkdat.FindByte(pchMessageStart[0]);
				nRewind = blkdat.GetPos() + 1;
				blkdat >> FLATDATA(buf);
				if (memcmp(buf, pchMessageStart, 4))
					continue;
				// read size
				blkdat >> nSize;
				if (nSize < 80 || nSize > MAX_BLOCK_SIZE)
					continue;
			} catch (std::exception &e) {
				// no valid block header found; don't complain
				break;
			}
			try {
				// read block
				uint64 nBlockPos = blkdat.GetPos();
				blkdat.SetLimit(nBlockPos + nSize);
				CBlock block;
				blkdat >> block;
				nRewind = blkdat.GetPos();

				// process block
				if (nBlockPos >= nStartByte) {
					LOCK(cs_main);
					if (dbp)
						dbp->nPos = nBlockPos;
					CValidationState state;
					if (ProcessBlock(state, NULL, &block, dbp))
						nLoaded++;
					if (state.IsError())
						break;
				}
			} catch (std::exception &e) {
				printf("%s() : Deserialize or I/O error caught during load\n",
						__PRETTY_FUNCTION__);
			}
		}
		fclose(fileIn);
	} catch (std::runtime_error &e) {
		AbortNode(_("Error: system error: ") + e.what());
	}
	if (nLoaded > 0)
		printf("Loaded %i blocks from external file in %"PRI64d"ms\n", nLoaded,
				GetTimeMillis() - nStart);
	return nLoaded > 0;
}

//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

extern map<uint256, CAlert> mapAlerts;
extern CCriticalSection cs_mapAlerts;

string GetWarnings(string strFor) {
	int nPriority = 0;
	string strStatusBar;
	string strRPC;

	if (GetBoolArg("-testsafemode"))
		strRPC = "test";

	if (!CLIENT_VERSION_IS_RELEASE)
		strStatusBar =
				_(
						"This is a pre-release test build - use at your own risk - do not use for mining or merchant applications");

	// Misc warnings like out of disk space and clock is wrong
	if (strMiscWarning != "") {
		nPriority = 1000;
		strStatusBar = strMiscWarning;
	}

	// Longer invalid proof-of-work chain
	if (pindexBest
			&& nBestInvalidWork
					> nBestChainWork
							+ (pindexBest->GetBlockWork() * 6).getuint256()) {
		nPriority = 2000;
		strStatusBar =
				strRPC =
						_(
								"Warning: Displayed transactions may not be correct! You may need to upgrade, or other nodes may need to upgrade.");
	}

	// Alerts
	{
		LOCK(cs_mapAlerts);
		BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts) {
			const CAlert& alert = item.second;
			if (alert.AppliesToMe() && alert.nPriority > nPriority) {
				nPriority = alert.nPriority;
				strStatusBar = alert.strStatusBar;
			}
		}
	}

	if (strFor == "statusbar")
		return strStatusBar;
	else if (strFor == "rpc")
		return strRPC;
	assert(!"GetWarnings() : invalid parameter");
	return "error";
}

//////////////////////////////////////////////////////////////////////////////
//
// Messages
//

bool static AlreadyHave(const CInv& inv) {
	switch (inv.type) {
	case MSG_TX: {
		bool txInMap = false;
		{
			LOCK(mempool.cs);
			txInMap = mempool.exists(inv.hash);
		}
		return txInMap || mapOrphanTransactions.count(inv.hash)
				|| pcoinsTip->HaveCoins(inv.hash);
	}
	case MSG_BLOCK:
		return mapBlockIndex.count(inv.hash) || mapOrphanBlocks.count(inv.hash);
	}
   
	// Don't know what it is, just say we already got one
	return true;
}

// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ASCII, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
unsigned char pchMessageStart[4] = { 0xdc, 0xec, 0xec, 0xdc };

void static ProcessGetData(CNode* pfrom) {
	std::deque<CInv>::iterator it = pfrom->vRecvGetData.begin();

	vector<CInv> vNotFound;
    std::vector<CBlock> vMultiBlock;
    uint32_t nMultiBlockBytes = 0;
	while (it != pfrom->vRecvGetData.end()) {
		// Don't bother if send buffer is too full to respond anyway
		if (pfrom->nSendSize >= SendBufferSize())
			break;

		// Don't waste work on slow peers until they catch up on the blocks we
		// give them. 80 bytes is just the size of a block header - obviously
		// the minimum we might return.
		if (pfrom->nBlocksRequested * 80 > pfrom->nSendBytes)
			break;

		const CInv &inv = *it;
		{
			boost::this_thread::interruption_point();
			it++;

			if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK) {
				bool send = true;
				map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(
						inv.hash);
				pfrom->nBlocksRequested++;
				if (mi != mapBlockIndex.end()) {
					// If the requested block is at a height below our last
					// checkpoint, only serve it if it's in the checkpointed chain
					int nHeight = ((*mi).second)->nHeight;
					CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(
							mapBlockIndex);
					if (pcheckpoint && nHeight < pcheckpoint->nHeight) {
						if (!((*mi).second)->IsInMainChain()) {
							printf(
									"ProcessGetData(): ignoring request for old block that isn't in the main chain\n");
							send = false;
						}
					}
				} else {
					send = false;
				}
				if (send) {
					CBlock block;
					block.ReadFromDisk((*mi).second);
					if (inv.type == MSG_BLOCK)
						pfrom->PushMessage("block", block);
					else // MSG_FILTERED_BLOCK)
					{
						LOCK(pfrom->cs_filter);
						if (pfrom->pfilter) {
							CMerkleBlock merkleBlock(block, *pfrom->pfilter);
							pfrom->PushMessage("merkleblock", merkleBlock);
							// CMerkleBlock just contains hashes, so also push any transactions in the block the client did not see
							// This avoids hurting performance by pointlessly requiring a round-trip
							// Note that there is currently no way for a node to request any single transactions we didnt send here -
							// they must either disconnect and retry or request the full block.
							// Thus, the protocol spec specified allows for us to provide duplicate txn here,
							// however we MUST always provide at least what the remote peer needs
							typedef std::pair<unsigned int, uint256> PairType;
							BOOST_FOREACH(PairType& pair, merkleBlock.vMatchedTxn)
								if (!pfrom->setInventoryKnown.count(
										CInv(MSG_TX, pair.second)))
									pfrom->PushMessage("tx",
											block.vtx[pair.first]);
						}
						// else
						// no response
					}

					// Trigger them to send a getblocks request for the next batch of inventory
					if (inv.hash == pfrom->hashContinue) {
						// Bypass PushInventory, this must send even if redundant,
						// and we want it right after the last block so they don't
						// wait for other stuff first.
						vector<CInv> vInv;
						vInv.push_back(CInv(MSG_BLOCK, hashBestChain));
						pfrom->PushMessage("inv", vInv);
						pfrom->hashContinue = 0;
					}
				}
			} else if (inv.IsKnownType()) {
				// Send stream from relay memory
				bool pushed = false;
				{
					LOCK(cs_mapRelay);
					map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
					if (mi != mapRelay.end()) {
						pfrom->PushMessage(inv.GetCommand(), (*mi).second);
						pushed = true;
					}
				}
				if (!pushed && inv.type == MSG_TX) {
					LOCK(mempool.cs);
					if (mempool.exists(inv.hash)) {
						CTransaction tx = mempool.lookup(inv.hash);
						CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
						ss.reserve(1000);
						ss << tx;
						pfrom->PushMessage("tx", ss);
						pushed = true;
					}
				}
				if (!pushed) {
					vNotFound.push_back(inv);
				}
			}

			// Track requests for our stuff.
			Inventory(inv.hash);
			if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK)
				break;		
		}
	}
    if (vMultiBlock.size() > 0)
        pfrom->PushMessage("mblk", vMultiBlock);
	pfrom->vRecvGetData.erase(pfrom->vRecvGetData.begin(), it);

	if (!vNotFound.empty()) {
		// Let the peer know that we didn't find what it asked for, so it doesn't
		// have to wait around forever. Currently only SPV clients actually care
		// about this message: it's needed when they are recursively walking the
		// dependencies of relevant unconfirmed transactions. SPV clients want to
		// do that because they want to know about (and store and rebroadcast and
		// risk analyze) the dependencies of transactions relevant to them, without
		// having to download the entire memory pool.
		pfrom->PushMessage("notfound", vNotFound);
	}
}

bool static ProcessMessage(CNode* pfrom, string strCommand,
		CDataStream& vRecv) {
	RandAddSeedPerfmon();
	if (fDebug)
		printf("received: %s (%"PRIszu" bytes)\n", strCommand.c_str(),
				vRecv.size());
	if (mapArgs.count("-dropmessagestest")
			&& GetRand(atoi(mapArgs["-dropmessagestest"])) == 0) {
		printf("dropmessagestest DROPPING RECV MESSAGE\n");
		return true;
	}

	if (strCommand == "version") {
		// Each connection can only send one version message
		if (pfrom->nVersion != 0) {
			pfrom->Misbehaving(1);
			return false;
		}

		int64 nTime;
		CAddress addrMe;
		CAddress addrFrom;
		uint64 nNonce = 1;
		vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
		if (pfrom->nVersion < MIN_PEER_PROTO_VERSION) {
			// disconnect from peers older than this proto version
			printf("partner %s using obsolete version %i; disconnecting\n",
					pfrom->addr.ToString().c_str(), pfrom->nVersion);
			pfrom->fDisconnect = true;
			return false;
		}

		if (pfrom->nVersion == 10300)
			pfrom->nVersion = 300;
		if (!vRecv.empty())
			vRecv >> addrFrom >> nNonce;
		if (!vRecv.empty()) {
			vRecv >> pfrom->strSubVer;
			pfrom->cleanSubVer = SanitizeString(pfrom->strSubVer);
		}
		if (!vRecv.empty())
			vRecv >> pfrom->nStartingHeight;
		if (!vRecv.empty())
			vRecv >> pfrom->fRelayTxes; // set to true after we get the first filter* message
		else
			pfrom->fRelayTxes = true;

		if (pfrom->fInbound && addrMe.IsRoutable()) {
			pfrom->addrLocal = addrMe;
			SeenLocal(addrMe);
		}

		// Disconnect if we connected to ourself
		if (nNonce == nLocalHostNonce && nNonce > 1) {
			printf("connected to self at %s, disconnecting\n",
					pfrom->addr.ToString().c_str());
			pfrom->fDisconnect = true;
			return true;
		}

		// Be shy and don't send version until we hear
		if (pfrom->fInbound)
			pfrom->PushVersion();

		pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

		AddTimeData(pfrom->addr, nTime);

		// Change version
		pfrom->PushMessage("verack");
		pfrom->ssSend.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));

		if (!pfrom->fInbound) {
			// Advertise our address
			if (!fNoListen && !IsInitialBlockDownload()) {
				CAddress addr = GetLocalAddress(&pfrom->addr);
				if (addr.IsRoutable())
					pfrom->PushAddress(addr);
			}

			// Get recent addresses
			if (pfrom->fOneShot || pfrom->nVersion >= CADDR_TIME_VERSION
					|| addrman.size() < 1000) {
				pfrom->PushMessage("getaddr");
				pfrom->fGetAddr = true;
			}
			addrman.Good(pfrom->addr);
		} else {
			if (((CNetAddr) pfrom->addr) == (CNetAddr) addrFrom) {
				addrman.Add(addrFrom, addrFrom);
				addrman.Good(addrFrom);
			}
		}
		
		// Relay alerts
		{
			LOCK(cs_mapAlerts);
			BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
				item.second.RelayTo(pfrom);
		}

		pfrom->fSuccessfullyConnected = true;

		printf(
				"receive version message: %s: version %d, blocks=%d, us=%s, them=%s, peer=%s\n",
				pfrom->cleanSubVer.c_str(), pfrom->nVersion,
				pfrom->nStartingHeight, addrMe.ToString().c_str(),
				addrFrom.ToString().c_str(), pfrom->addr.ToString().c_str());

		cPeerBlockCounts.input(pfrom->nStartingHeight);
	}

	else if (pfrom->nVersion == 0) {
		// Must have a version message before anything else
		pfrom->Misbehaving(1);
		return false;
	}

	else if (strCommand == "verack") {
		pfrom->SetRecvVersion(min(pfrom->nVersion, PROTOCOL_VERSION));
	}

	else if (strCommand == "addr") {
		vector<CAddress> vAddr;
		vRecv >> vAddr;

		// Don't want addr from older versions unless seeding
		if (pfrom->nVersion < CADDR_TIME_VERSION && addrman.size() > 1000)
			return true;
		if (vAddr.size() > 1000) {
			pfrom->Misbehaving(20);
			return error("message addr size() = %"PRIszu"", vAddr.size());
		}

		// Store the new addresses
		vector<CAddress> vAddrOk;
		int64 nNow = GetAdjustedTime();
		int64 nSince = nNow - 10 * 60;
		BOOST_FOREACH(CAddress& addr, vAddr) {
			boost::this_thread::interruption_point();

			if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
				addr.nTime = nNow - 5 * 24 * 60 * 60;
			pfrom->AddAddressKnown(addr);
			bool fReachable = IsReachable(addr);
			if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10
					&& addr.IsRoutable()) {
				// Relay to a limited number of other nodes
				{
					LOCK(cs_vNodes);
					// Use deterministic randomness to send to the same nodes for 24 hours
					// at a time so the setAddrKnowns of the chosen nodes prevent repeats
					static uint256 hashSalt;
					if (hashSalt == 0)
						hashSalt = GetRandHash();
					uint64 hashAddr = addr.GetHash();
					uint256 hashRand = hashSalt ^ (hashAddr << 32)
							^ ((GetTime() + hashAddr) / (24 * 60 * 60));
					hashRand = Hash(BEGIN(hashRand), END(hashRand));
					multimap<uint256, CNode*> mapMix;
					BOOST_FOREACH(CNode* pnode, vNodes) {
						if (pnode->nVersion < CADDR_TIME_VERSION)
							continue;
						unsigned int nPointer;
						memcpy(&nPointer, &pnode, sizeof(nPointer));
						uint256 hashKey = hashRand ^ nPointer;
						hashKey = Hash(BEGIN(hashKey), END(hashKey));
						mapMix.insert(make_pair(hashKey, pnode));
					}
					int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
					for (multimap<uint256, CNode*>::iterator mi =
							mapMix.begin();
							mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
						((*mi).second)->PushAddress(addr);
				}
			}
			// Do not store addresses outside our network
			if (fReachable)
				vAddrOk.push_back(addr);
		}
		addrman.Add(vAddrOk, pfrom->addr, 2 * 60 * 60);
		if (vAddr.size() < 1000)
			pfrom->fGetAddr = false;
		if (pfrom->fOneShot)
			pfrom->fDisconnect = true;
	}

	else if (strCommand == "inv") {
		vector<CInv> vInv;
		vRecv >> vInv;
		if (vInv.size() > MAX_INV_SZ) {
			pfrom->Misbehaving(20);
			return error("message inv size() = %"PRIszu"", vInv.size());
		}

		// find last block in inv vector
		unsigned int nLastBlock = (unsigned int) (-1);
		for (unsigned int nInv = 0; nInv < vInv.size(); nInv++) {
			if (vInv[vInv.size() - 1 - nInv].type == MSG_BLOCK) {
				nLastBlock = vInv.size() - 1 - nInv;
				break;
			}
		}
		for (unsigned int nInv = 0; nInv < vInv.size(); nInv++) {
			const CInv &inv = vInv[nInv];

			boost::this_thread::interruption_point();
			pfrom->AddInventoryKnown(inv);

			bool fAlreadyHave = AlreadyHave(inv);
			if (fDebug)
				printf("  got inventory: %s  %s\n", inv.ToString().c_str(),
						fAlreadyHave ? "have" : "new");

			if (!fAlreadyHave) {
				if (!fImporting && !fReindex)
					pfrom->AskFor(inv);
			} else if (inv.type == MSG_BLOCK
					&& mapOrphanBlocks.count(inv.hash)) {
				pfrom->PushGetBlocks(pindexBest,
						GetOrphanRoot(mapOrphanBlocks[inv.hash]));
			} else if (nInv == nLastBlock) {
				// In case we are on a very long side-chain, it is possible that we already have
				// the last block in an inv bundle sent in response to getblocks. Try to detect
				// this situation and push another getblocks to continue.
				pfrom->PushGetBlocks(mapBlockIndex[inv.hash], uint256(0));
				if (fDebug)
					printf("force request: %s\n", inv.ToString().c_str());
			}

			// Track requests for our stuff
			Inventory(inv.hash);
		}
	}

	else if (strCommand == "getdata") {
		vector<CInv> vInv;
		vRecv >> vInv;
		if (vInv.size() > MAX_INV_SZ) {
			pfrom->Misbehaving(20);
			return error("message getdata size() = %"PRIszu"", vInv.size());
		}

		if (fDebugNet || (vInv.size() != 1))
			printf("received getdata (%"PRIszu" invsz)\n", vInv.size());

		if ((fDebugNet && vInv.size() > 0) || (vInv.size() == 1))
			printf("received getdata for: %s\n", vInv[0].ToString().c_str());

		pfrom->vRecvGetData.insert(pfrom->vRecvGetData.end(), vInv.begin(),
				vInv.end());
		ProcessGetData(pfrom);
	}

	else if (strCommand == "getblocks") {
		CBlockLocator locator;
		uint256 hashStop;
		vRecv >> locator >> hashStop;

		// Find the last block the caller has in the main chain
		CBlockIndex* pindex = locator.GetBlockIndex();

		// Send the rest of the chain
		if (pindex)
			pindex = pindex->pnext;
		int nLimit = 500;
		printf("getblocks %d to %s limit %d\n", (pindex ? pindex->nHeight : -1),
				hashStop.ToString().c_str(), nLimit);
		for (; pindex; pindex = pindex->pnext) {
			if (pindex->GetBlockHash() == hashStop) {
				printf("  getblocks stopping at %d %s\n", pindex->nHeight,
						pindex->GetBlockHash().ToString().c_str());
				break;
			}
			pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
			if (--nLimit <= 0) {
				// When this block is requested, we'll send an inv that'll make them
				// getblocks the next batch of inventory.
				printf("  getblocks stopping at limit %d %s\n", pindex->nHeight,
						pindex->GetBlockHash().ToString().c_str());
				pfrom->hashContinue = pindex->GetBlockHash();
				break;
			}
		}
	}

	else if (strCommand == "getheaders") {
		CBlockLocator locator;
		uint256 hashStop;
		vRecv >> locator >> hashStop;

		CBlockIndex* pindex = NULL;
		if (locator.IsNull()) {
			// If locator is null, return the hashStop block
			map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(
					hashStop);
			if (mi == mapBlockIndex.end())
				return true;
			pindex = (*mi).second;
		} else {
			// Find the last block the caller has in the main chain
			pindex = locator.GetBlockIndex();
			if (pindex)
				pindex = pindex->pnext;
		}

		// we must use CBlocks, as CBlockHeaders won't include the 0x00 nTx count at the end
		vector<CBlock> vHeaders;
		int nLimit = 2000;
		printf("getheaders %d to %s\n", (pindex ? pindex->nHeight : -1),
				hashStop.ToString().c_str());
		for (; pindex; pindex = pindex->pnext) {
			vHeaders.push_back(pindex->GetBlockHeader());
			if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
				break;
		}
		pfrom->PushMessage("headers", vHeaders);
	}

	else if (strCommand == "tx") {
		vector<uint256> vWorkQueue;
		vector<uint256> vEraseQueue;
		CDataStream vMsg(vRecv);
		CTransaction tx;
		vRecv >> tx;

		CInv inv(MSG_TX, tx.GetHash());
		pfrom->AddInventoryKnown(inv);

		bool fMissingInputs = false;
		CValidationState state;
		if (tx.AcceptToMemoryPool(state, true, true, &fMissingInputs)) {
			RelayTransaction(tx, inv.hash);
			mapAlreadyAskedFor.erase(inv);
			vWorkQueue.push_back(inv.hash);
			vEraseQueue.push_back(inv.hash);

			printf(
					"AcceptToMemoryPool: %s %s : accepted %s (poolsz %"PRIszu")\n",
					pfrom->addr.ToString().c_str(), pfrom->cleanSubVer.c_str(),
					tx.GetHash().ToString().c_str(), mempool.mapTx.size());

			// Recursively process any orphan transactions that depended on this one
			for (unsigned int i = 0; i < vWorkQueue.size(); i++) {
				uint256 hashPrev = vWorkQueue[i];
				for (set<uint256>::iterator mi =
						mapOrphanTransactionsByPrev[hashPrev].begin();
						mi != mapOrphanTransactionsByPrev[hashPrev].end();
						++mi) {
					const uint256& orphanHash = *mi;
					const CTransaction& orphanTx =
							mapOrphanTransactions[orphanHash];
					bool fMissingInputs2 = false;
					// Use a dummy CValidationState so someone can't setup nodes to counter-DoS based on orphan
					// resolution (that is, feeding people an invalid transaction based on LegitTxX in order to get
					// anyone relaying LegitTxX banned)
					CValidationState stateDummy;

					if (tx.AcceptToMemoryPool(stateDummy, true, true,
							&fMissingInputs2)) {
						printf("   accepted orphan tx %s\n",
								orphanHash.ToString().c_str());
						RelayTransaction(orphanTx, orphanHash);
						mapAlreadyAskedFor.erase(CInv(MSG_TX, orphanHash));
						vWorkQueue.push_back(orphanHash);
						vEraseQueue.push_back(orphanHash);
					} else if (!fMissingInputs2) {
						// invalid or too-little-fee orphan
						vEraseQueue.push_back(orphanHash);
						printf("   removed orphan tx %s\n",
								orphanHash.ToString().c_str());
					}
				}
			}

			BOOST_FOREACH(uint256 hash, vEraseQueue)
				EraseOrphanTx(hash);
		} else if (fMissingInputs) {
			AddOrphanTx(tx);

			// DoS prevention: do not allow mapOrphanTransactions to grow unbounded
			unsigned int nEvicted = LimitOrphanTxSize(MAX_ORPHAN_TRANSACTIONS);
			if (nEvicted > 0)
				printf("mapOrphan overflow, removed %u tx\n", nEvicted);
		}
		int nDoS = 0;
		if (state.IsInvalid(nDoS)) {
			printf("%s from %s %s was not accepted into the memory pool\n",
					tx.GetHash().ToString().c_str(),
					pfrom->addr.ToString().c_str(), pfrom->cleanSubVer.c_str());
			if (nDoS > 0)
				pfrom->Misbehaving(nDoS);
		}
	}
	else if (strCommand == "block" && !fImporting && !fReindex) // Ignore blocks received while importing
		{

		CBlock block;
		vRecv >> block;

		printf("received block %s\n", block.GetHash().ToString().c_str());
		// block.print();

		CInv inv(MSG_BLOCK, block.GetHash());

		pfrom->AddInventoryKnown(inv);

		CValidationState state;
		if (ProcessBlock(state, pfrom, &block) || state.CorruptionPossible())
			mapAlreadyAskedFor.erase(inv);
		int nDoS = 0;
		if (state.IsInvalid(nDoS))
			if (nDoS > 0)
				pfrom->Misbehaving(nDoS);

	}
	else if (strCommand == "getaddr") {
		pfrom->vAddrToSend.clear();
		vector<CAddress> vAddr = addrman.GetAddr();
		BOOST_FOREACH(const CAddress &addr, vAddr)
			pfrom->PushAddress(addr);
	}

	else if (strCommand == "mempool") {
		std::vector<uint256> vtxid;
		LOCK2(mempool.cs, pfrom->cs_filter);
		mempool.queryHashes(vtxid);
		vector<CInv> vInv;
		BOOST_FOREACH(uint256& hash, vtxid) {
			CInv inv(MSG_TX, hash);
			if ((pfrom->pfilter
					&& pfrom->pfilter->IsRelevantAndUpdate(mempool.lookup(hash),
							hash)) || (!pfrom->pfilter))
				vInv.push_back(inv);
			if (vInv.size() == MAX_INV_SZ)
				break;
		}
		if (vInv.size() > 0)
			pfrom->PushMessage("inv", vInv);
	}

	else if (strCommand == "ping") {
		if (pfrom->nVersion > BIP0031_VERSION) {
			uint64 nonce = 0;
			vRecv >> nonce;
			// Echo the message back with the nonce. This allows for two useful features:
			//
			// 1) A remote node can quickly check if the connection is operational
			// 2) Remote nodes can measure the latency of the network thread. If this node
			//    is overloaded it won't respond to pings quickly and the remote node can
			//    avoid sending us more work, like chain download requests.
			//
			// The nonce stops the remote getting confused between different pings: without
			// it, if the remote node sends a ping once per second and this node takes 5
			// seconds to respond to each, the 5th ping the remote sends would appear to
			// return very quickly.
			pfrom->PushMessage("pong", nonce);
		}
	}

	else if (strCommand == "alert") {
		CAlert alert;
		vRecv >> alert;

		uint256 alertHash = alert.GetHash();
		if (pfrom->setKnown.count(alertHash) == 0) {
			if (alert.ProcessAlert()) {
				// Relay
				pfrom->setKnown.insert(alertHash);
				{
					LOCK(cs_vNodes);
					BOOST_FOREACH(CNode* pnode, vNodes)
						alert.RelayTo(pnode);
				}
			} else {
				// Small DoS penalty so peers that send us lots of
				// duplicate/expired/invalid-signature/whatever alerts
				// eventually get banned.
				// This isn't a Misbehaving(100) (immediate ban) because the
				// peer might be an older or different implementation with
				// a different signature key, etc.
				pfrom->Misbehaving(10);
			}
		}
	}

	else if (!fBloomFilters
			&& (strCommand == "filterload" || strCommand == "filteradd"
					|| strCommand == "filterclear")) {
		pfrom->CloseSocketDisconnect();
		return error(
				"peer %s attempted to set a bloom filter even though we do not advertise that service",
				pfrom->addr.ToString().c_str());
	}

	else if (strCommand == "filterload") {
		CBloomFilter filter;
		vRecv >> filter;

		if (!filter.IsWithinSizeConstraints())
			// There is no excuse for sending a too-large filter
			pfrom->Misbehaving(100);
		else {
			LOCK(pfrom->cs_filter);
			delete pfrom->pfilter;
			pfrom->pfilter = new CBloomFilter(filter);
			pfrom->pfilter->UpdateEmptyFull();
		}
		pfrom->fRelayTxes = true;
	}

	else if (strCommand == "filteradd") {
		vector<unsigned char> vData;
		vRecv >> vData;

		// Nodes must NEVER send a data item > 520 bytes (the max size for a script data object,
		// and thus, the maximum size any matched object can have) in a filteradd message
		if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE) {
			pfrom->Misbehaving(100);
		} else {
			LOCK(pfrom->cs_filter);
			if (pfrom->pfilter)
				pfrom->pfilter->insert(vData);
			else
				pfrom->Misbehaving(100);
		}
	}

	else if (strCommand == "filterclear") {
		LOCK(pfrom->cs_filter);
		delete pfrom->pfilter;
		pfrom->pfilter = new CBloomFilter();
		pfrom->fRelayTxes = true;
	}
	else
    {

        // Ignore unknown commands for extensibility
    };

	// Update the last seen time for this node's address
	if (pfrom->fNetworkNode)
		if (strCommand == "version" || strCommand == "addr"
				|| strCommand == "inv" || strCommand == "getdata"
				|| strCommand == "ping")
			AddressCurrentlyConnected(pfrom->addr);

	return true;
}

// requires LOCK(cs_vRecvMsg)
bool ProcessMessages(CNode* pfrom) {
	//if (fDebug)
	//    printf("ProcessMessages(%zu messages)\n", pfrom->vRecvMsg.size());

	//
	// Message format
	//  (4) message start
	//  (12) command
	//  (4) size
	//  (4) checksum
	//  (x) data
	//
	bool fOk = true;

	if (!pfrom->vRecvGetData.empty())
		ProcessGetData(pfrom);

	// this maintains the order of responses
	if (!pfrom->vRecvGetData.empty())
		return fOk;

	std::deque<CNetMessage>::iterator it = pfrom->vRecvMsg.begin();
	while (!pfrom->fDisconnect && it != pfrom->vRecvMsg.end()) {
		// Don't bother if send buffer is too full to respond anyway
		if (pfrom->nSendSize >= SendBufferSize())
			break;

		// get next message
		CNetMessage& msg = *it;

		//if (fDebug)
		//    printf("ProcessMessages(message %u msgsz, %zu bytes, complete:%s)\n",
		//            msg.hdr.nMessageSize, msg.vRecv.size(),
		//            msg.complete() ? "Y" : "N");

		// end, if an incomplete message is found
		if (!msg.complete())
			break;

		// at this point, any failure means we can delete the current message
		it++;

		// Scan for message start
		if (memcmp(msg.hdr.pchMessageStart, pchMessageStart,
				sizeof(pchMessageStart)) != 0) {
			printf("\n\nPROCESSMESSAGE: INVALID MESSAGESTART\n\n");
			fOk = false;
			break;
		}

		// Read header
		CMessageHeader& hdr = msg.hdr;
		if (!hdr.IsValid()) {
			printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n",
					hdr.GetCommand().c_str());
			continue;
		}
		string strCommand = hdr.GetCommand();

		// Message size
		unsigned int nMessageSize = hdr.nMessageSize;

		// Checksum
		CDataStream& vRecv = msg.vRecv;
		uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
		unsigned int nChecksum = 0;
		memcpy(&nChecksum, &hash, sizeof(nChecksum));
		if (nChecksum != hdr.nChecksum) {
			printf(
					"ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n",
					strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
			continue;
		}

		// Process message
		bool fRet = false;
		try {
			{
				LOCK(cs_main);
				fRet = ProcessMessage(pfrom, strCommand, vRecv);
			}
			boost::this_thread::interruption_point();
		} catch (std::ios_base::failure& e) {
			if (strstr(e.what(), "end of data")) {
				// Allow exceptions from under-length message on vRecv
				printf(
						"ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n",
						strCommand.c_str(), nMessageSize, e.what());
			} else if (strstr(e.what(), "size too large")) {
				// Allow exceptions from over-long size
				printf(
						"ProcessMessages(%s, %u bytes) : Exception '%s' caught\n",
						strCommand.c_str(), nMessageSize, e.what());
			} else {
				PrintExceptionContinue(&e, "ProcessMessages()");
			}
		} catch (boost::thread_interrupted) {
			throw;
		} catch (std::exception& e) {
			PrintExceptionContinue(&e, "ProcessMessages()");
		} catch (...) {
			PrintExceptionContinue(NULL, "ProcessMessages()");
		}

		if (!fRet)
			printf("ProcessMessage(%s, %u bytes) FAILED\n", strCommand.c_str(),
					nMessageSize);

		break;
	}

	// In case the connection got shut down, its receive buffer was wiped
	if (!pfrom->fDisconnect)
		pfrom->vRecvMsg.erase(pfrom->vRecvMsg.begin(), it);

	return fOk;
}

bool SendMessages(CNode* pto, bool fSendTrickle) {
	TRY_LOCK(cs_main, lockMain);
	if (lockMain) {
		// Don't send anything until we get their version message
		if (pto->nVersion == 0)
			return true;

		// Keep-alive ping. We send a nonce of zero because we don't use it anywhere
		// right now.
		if (pto->nLastSend && GetTime() - pto->nLastSend > 30 * 60
				&& pto->vSendMsg.empty()) {
			uint64 nonce = 0;
			if (pto->nVersion > BIP0031_VERSION)
				pto->PushMessage("ping", nonce);
			else
				pto->PushMessage("ping");
		}

		// Start block sync
		if (pto->fStartSync && !fImporting && !fReindex) {
			pto->fStartSync = false;
			pto->PushGetBlocks(pindexBest, uint256(0));
		}

		// Resend wallet transactions that haven't gotten in a block yet
		// Except during reindex, importing and IBD, when old wallet
		// transactions become unconfirmed and spams other nodes.
		if (!fReindex && !fImporting && !IsInitialBlockDownload()) {
			ResendWalletTransactions();
		}

		// Address refresh broadcast
		static int64 nLastRebroadcast;
		if (!IsInitialBlockDownload()
				&& (GetTime() - nLastRebroadcast > 24 * 60 * 60)) {
			{
				LOCK(cs_vNodes);
				BOOST_FOREACH(CNode* pnode, vNodes) {
					// Periodically clear setAddrKnown to allow refresh broadcasts
					if (nLastRebroadcast)
						pnode->setAddrKnown.clear();

					// Rebroadcast our address
					if (!fNoListen) {
						CAddress addr = GetLocalAddress(&pnode->addr);
						if (addr.IsRoutable())
							pnode->PushAddress(addr);
					}
				}
			}
			nLastRebroadcast = GetTime();
		}

		//
		// Message: addr
		//
		if (fSendTrickle) {
			vector<CAddress> vAddr;
			vAddr.reserve(pto->vAddrToSend.size());
			BOOST_FOREACH(const CAddress& addr, pto->vAddrToSend) {
				// returns true if wasn't already contained in the set
				if (pto->setAddrKnown.insert(addr).second) {
					vAddr.push_back(addr);
					// receiver rejects addr messages larger than 1000
					if (vAddr.size() >= 1000) {
						pto->PushMessage("addr", vAddr);
						vAddr.clear();
					}
				}
			}
			pto->vAddrToSend.clear();
			if (!vAddr.empty())
				pto->PushMessage("addr", vAddr);
		}

		//
		// Message: inventory
		//
		vector<CInv> vInv;
		vector<CInv> vInvWait;
		{
			LOCK(pto->cs_inventory);
			vInv.reserve(pto->vInventoryToSend.size());
			vInvWait.reserve(pto->vInventoryToSend.size());
			BOOST_FOREACH(const CInv& inv, pto->vInventoryToSend) {
				if (pto->setInventoryKnown.count(inv))
					continue;

				// trickle out tx inv to protect privacy
				if (inv.type == MSG_TX && !fSendTrickle) {
					// 1/4 of tx invs blast to all immediately
					static uint256 hashSalt;
					if (hashSalt == 0)
						hashSalt = GetRandHash();
					uint256 hashRand = inv.hash ^ hashSalt;
					hashRand = Hash(BEGIN(hashRand), END(hashRand));
					bool fTrickleWait = ((hashRand & 3) != 0);

					// always trickle our own transactions
					if (!fTrickleWait) {
						CWalletTx wtx;
						if (GetTransaction(inv.hash, wtx))
							if (wtx.fFromMe)
								fTrickleWait = true;
					}

					if (fTrickleWait) {
						vInvWait.push_back(inv);
						continue;
					}
				}

				// returns true if wasn't already contained in the set
				if (pto->setInventoryKnown.insert(inv).second) {
					vInv.push_back(inv);
					if (vInv.size() >= 1000) {
						pto->PushMessage("inv", vInv);
						vInv.clear();
					}
				}
			}
			pto->vInventoryToSend = vInvWait;
		}
		if (!vInv.empty())
			pto->PushMessage("inv", vInv);

		//
		// Message: getdata
		//
		vector<CInv> vGetData;
		int64 nNow = GetTime() * 1000000;
		while (!pto->mapAskFor.empty()
				&& (*pto->mapAskFor.begin()).first <= nNow) {
			const CInv& inv = (*pto->mapAskFor.begin()).second;
			if (!AlreadyHave(inv)) {
				if (fDebugNet)
					printf("sending getdata: %s\n", inv.ToString().c_str());
				vGetData.push_back(inv);
				if (vGetData.size() >= 1000) {
					pto->PushMessage("getdata", vGetData);
					vGetData.clear();
				}
			}
			pto->mapAskFor.erase(pto->mapAskFor.begin());
		}
		if (!vGetData.empty())
			pto->PushMessage("getdata", vGetData);

	}
	return true;
}

//////////////////////////////////////////////////////////////////////////////
//
// SyscoinMiner
//

int static FormatHashBlocks(void* pbuffer, unsigned int len) {
	unsigned char* pdata = (unsigned char*) pbuffer;
	unsigned int blocks = 1 + ((len + 8) / 64);
	unsigned char* pend = pdata + 64 * blocks;
	memset(pdata + len, 0, 64 * blocks - len);
	pdata[len] = 0x80;
	unsigned int bits = len * 8;
	pend[-1] = (bits >> 0) & 0xff;
	pend[-2] = (bits >> 8) & 0xff;
	pend[-3] = (bits >> 16) & 0xff;
	pend[-4] = (bits >> 24) & 0xff;
	return blocks;
}

static const unsigned int pSHA256InitState[8] = { 0x6a09e667, 0xbb67ae85,
		0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

void SHA256Transform(void* pstate, void* pinput, const void* pinit) {
	SHA256_CTX ctx;
	unsigned char data[64];

	SHA256_Init(&ctx);

	for (int i = 0; i < 16; i++)
		((uint32_t*) data)[i] = ByteReverse(((uint32_t*) pinput)[i]);

	for (int i = 0; i < 8; i++)
		ctx.h[i] = ((uint32_t*) pinit)[i];

	SHA256_Update(&ctx, data, sizeof(data));
	for (int i = 0; i < 8; i++)
		((uint32_t*) pstate)[i] = ctx.h[i];
}

// Some explaining would be appreciated
class COrphan {
public:
	CTransaction* ptx;
	set<uint256> setDependsOn;
	double dPriority;
	double dFeePerKb;

	COrphan(CTransaction* ptxIn) {
		ptx = ptxIn;
		dPriority = dFeePerKb = 0;
	}

	void print() const {
		printf("COrphan(hash=%s, dPriority=%.1f, dFeePerKb=%.1f)\n",
				ptx->GetHash().ToString().c_str(), dPriority, dFeePerKb);
		BOOST_FOREACH(uint256 hash, setDependsOn)
			printf("   setDependsOn %s\n", hash.ToString().c_str());
	}
};

uint64 nLastBlockTx = 0;
uint64 nLastBlockSize = 0;

// We want to sort transactions by priority and fee, so:
typedef boost::tuple<double, double, CTransaction*> TxPriority;
class TxPriorityCompare {
	bool byFee;
public:
	TxPriorityCompare(bool _byFee) :
			byFee(_byFee) {
	}
	bool operator()(const TxPriority& a, const TxPriority& b) {
		if (byFee) {
			if (a.get<1>() == b.get<1>())
				return a.get<0>() < b.get<0>();
			return a.get<1>() < b.get<1>();
		} else {
			if (a.get<0>() == b.get<0>())
				return a.get<1>() < b.get<1>();
			return a.get<0>() < b.get<0>();
		}
	}
};

CBlockTemplate* CreateNewBlock(const CScript& scriptPubKeyIn) {
	// Create new block
	auto_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
	if (!pblocktemplate.get())
		return NULL;
	CBlock *pblock = &pblocktemplate->block; // pointer for convenience

	// Create coinbase tx
	CTransaction txNew;
	txNew.vin.resize(1);
	txNew.vin[0].prevout.SetNull();
	txNew.vout.resize(1);
	txNew.vout[0].scriptPubKey = scriptPubKeyIn;

	// Add our coinbase tx as first transaction
	pblock->vtx.push_back(txNew);
	pblocktemplate->vTxFees.push_back(-1); // updated at end
	pblocktemplate->vTxSigOps.push_back(-1); // updated at end

	// Largest block you're willing to create:
	unsigned int nBlockMaxSize = GetArg("-blockmaxsize",
			DEFAULT_BLOCK_MAX_SIZE);
	// Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
	nBlockMaxSize = std::max((unsigned int) 1000,
			std::min((unsigned int) (MAX_BLOCK_SIZE - 1000), nBlockMaxSize));

	// How much of the block should be dedicated to high-priority transactions,
	// included regardless of the fees they pay
	unsigned int nBlockPrioritySize = GetArg("-blockprioritysize",
			DEFAULT_BLOCK_PRIORITY_SIZE);
	nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

	// Minimum block size you want to create; block will be filled with free transactions
	// until there are no more or the block reaches this size:
	unsigned int nBlockMinSize = GetArg("-blockminsize", 0);
	nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

	// Collect memory pool transactions into the block
	int64 nFees = 0;
	{
		LOCK2(cs_main, mempool.cs);
		CBlockIndex* pindexPrev = pindexBest;
		CCoinsViewCache view(*pcoinsTip, true);

		// Priority order to process transactions
		list<COrphan> vOrphan; // list memory doesn't move
		map<uint256, vector<COrphan*> > mapDependers;
		bool fPrintPriority = GetBoolArg("-printpriority");

		// This vector will be sorted into a priority queue:
		vector<TxPriority> vecPriority;
		vecPriority.reserve(mempool.mapTx.size());
		for (map<uint256, CTransaction>::iterator mi = mempool.mapTx.begin();
				mi != mempool.mapTx.end(); ++mi) {
			CTransaction& tx = (*mi).second;
			if (tx.IsCoinBase() || !tx.IsFinal())
				continue;

			COrphan* porphan = NULL;
			double dPriority = 0;
			int64 nTotalIn = 0;
			bool fMissingInputs = false;
			BOOST_FOREACH(const CTxIn& txin, tx.vin) {
				// Read prev transaction
				if (!view.HaveCoins(txin.prevout.hash)) {
					// This should never happen; all transactions in the memory
					// pool should connect to either transactions in the chain
					// or other transactions in the memory pool.
					if (!mempool.mapTx.count(txin.prevout.hash)) {
						printf("ERROR: mempool transaction missing input\n");
						if (fDebug)
							assert("mempool transaction missing input" == 0);
						fMissingInputs = true;
						if (porphan)
							vOrphan.pop_back();
						break;
					}

					// Has to wait for dependencies
					if (!porphan) {
						// Use list for automatic deletion
						vOrphan.push_back(COrphan(&tx));
						porphan = &vOrphan.back();
					}
					mapDependers[txin.prevout.hash].push_back(porphan);
					porphan->setDependsOn.insert(txin.prevout.hash);
					nTotalIn +=
							mempool.mapTx[txin.prevout.hash].vout[txin.prevout.n].nValue;
					continue;
				}
				const CCoins &coins = view.GetCoins(txin.prevout.hash);

				int64 nValueIn = coins.vout[txin.prevout.n].nValue;
				nTotalIn += nValueIn;

				int nConf = pindexPrev->nHeight - coins.nHeight + 1;

				dPriority += (double) nValueIn * nConf;
			}
			if (fMissingInputs)
				continue;

			// Priority is sum(valuein * age) / txsize
			unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK,
					PROTOCOL_VERSION);
			dPriority /= nTxSize;

			// This is a more accurate fee-per-kilobyte than is used by the client code, because the
			// client code rounds up the size to the nearest 1K. That's good, because it gives an
			// incentive to create smaller transactions.
			double dFeePerKb = double(nTotalIn - tx.GetValueOut())
					/ (double(nTxSize) / 1000.0);

			if (porphan) {
				porphan->dPriority = dPriority;
				porphan->dFeePerKb = dFeePerKb;
			} else
				vecPriority.push_back(
						TxPriority(dPriority, dFeePerKb, &(*mi).second));
		}

		uint64 nBlockSize = 1000;
		uint64 nBlockTx = 0;
		int nBlockSigOps = 100;
		bool fSortedByFee = (nBlockPrioritySize <= 0);

		TxPriorityCompare comparer(fSortedByFee);
		std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

		while (!vecPriority.empty()) {
			// Take highest priority transaction off the priority queue:
			double dPriority = vecPriority.front().get<0>();
			double dFeePerKb = vecPriority.front().get<1>();
			CTransaction& tx = *(vecPriority.front().get<2>());

			std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
			vecPriority.pop_back();

			// Size limits
			unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK,
					PROTOCOL_VERSION);
			if (nBlockSize + nTxSize >= nBlockMaxSize)
				continue;

			// Legacy limits on sigOps:
			unsigned int nTxSigOps = tx.GetLegacySigOpCount();
			if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
				continue;

			// Skip free transactions if we're past the minimum block size:
			if (fSortedByFee && (dFeePerKb < CTransaction::nMinTxFee)
					&& (nBlockSize + nTxSize >= nBlockMinSize))
				continue;

			// Prioritize by fee once past the priority size or we run out of high-priority
			// transactions:
			if (!fSortedByFee
					&& ((nBlockSize + nTxSize >= nBlockPrioritySize)
							|| (dPriority < COIN * 1440 / 250))) {
				fSortedByFee = true;
				comparer = TxPriorityCompare(fSortedByFee);
				std::make_heap(vecPriority.begin(), vecPriority.end(),
						comparer);
			}

			if (!tx.HaveInputs(view))
				continue;

			int64 nTxFees = tx.GetValueIn(view) - tx.GetValueOut();

			nTxSigOps += tx.GetP2SHSigOpCount(view);
			if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
				continue;

	        CValidationState state;
			if (!tx.CheckInputs(pindexPrev, state, view, true, SCRIPT_VERIFY_P2SH,
					NULL, false, true, false))
				continue;

			CTxUndo txundo;
			uint256 hash = tx.GetHash();
			tx.UpdateCoins(state, view, txundo, pindexPrev->nHeight + 1, hash);

			// Added
			pblock->vtx.push_back(tx);
			pblocktemplate->vTxFees.push_back(nTxFees);
			pblocktemplate->vTxSigOps.push_back(nTxSigOps);
			nBlockSize += nTxSize;
			++nBlockTx;
			nBlockSigOps += nTxSigOps;
			nFees += nTxFees;

			if (fPrintPriority) {
				printf("priority %.1f feeperkb %.1f txid %s\n", dPriority,
						dFeePerKb, tx.GetHash().ToString().c_str());
			}

			// Add transactions that depend on this one to the priority queue
			if (mapDependers.count(hash)) {
				BOOST_FOREACH(COrphan* porphan, mapDependers[hash]) {
					if (!porphan->setDependsOn.empty()) {
						porphan->setDependsOn.erase(hash);
						if (porphan->setDependsOn.empty()) {
							vecPriority.push_back(
									TxPriority(porphan->dPriority,
											porphan->dFeePerKb, porphan->ptx));
							std::push_heap(vecPriority.begin(),
									vecPriority.end(), comparer);
						}
					}
				}
			}
		}

		nLastBlockTx = nBlockTx;
		nLastBlockSize = nBlockSize;
		printf("CreateNewBlock(): total size %"PRI64u"\n", nBlockSize);

		pblock->vtx[0].vout[0].nValue = GetBlockValue(pindexPrev->nHeight+1, nFees, 0);
		pblocktemplate->vTxFees[0] = -nFees;

		// Fill in header
		//pblock->vtx[0].vout[0].nValue += pindexPrev->nHeight < 1 ? GetFeeAssign() : 0;
		pblock->hashPrevBlock = pindexPrev->GetBlockHash();
		pblock->UpdateTime(pindexPrev);
		pblock->nBits = GetNextWorkRequired(pindexPrev, pblock);
		pblock->nNonce = 0;
		pblock->vtx[0].vin[0].scriptSig = CScript() << OP_0 << OP_0;
		pblocktemplate->vTxSigOps[0] = pblock->vtx[0].GetLegacySigOpCount();

		CBlockIndex indexDummy(*pblock);
		indexDummy.pprev = pindexPrev;
		indexDummy.nHeight = pindexPrev->nHeight + 1;
		CCoinsViewCache viewNew(*pcoinsTip, true);
		CValidationState state;
		if (!pblock->ConnectBlock(state, &indexDummy, viewNew, true))
			throw std::runtime_error("CreateNewBlock() : ConnectBlock failed");
	}

	return pblocktemplate.release();
}

CBlockTemplate* CreateNewBlockWithKey(CReserveKey& reservekey) {
	CPubKey pubkey;
	if (!reservekey.GetReservedKey(pubkey))
		return NULL;

	CScript scriptPubKey = CScript() << pubkey << OP_CHECKSIG;
	return CreateNewBlock(scriptPubKey);
}

void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev,
		unsigned int& nExtraNonce) {
	// Update nExtraNonce
	static uint256 hashPrevBlock;
	if (hashPrevBlock != pblock->hashPrevBlock) {
		nExtraNonce = 0;
		hashPrevBlock = pblock->hashPrevBlock;
	}
	++nExtraNonce;
	unsigned int nHeight = pindexPrev->nHeight + 1; // Height first in coinbase required for block.version=2
	
	pblock->vtx[0].vin[0].scriptSig = (CScript() << nHeight
			<< CBigNum(nExtraNonce)) + COINBASE_FLAGS;
	assert(pblock->vtx[0].vin[0].scriptSig.size() <= 100);

	pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}

void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata,
		char* phash1) {
	//
	// Pre-build hash buffers
	//
	struct {
		struct unnamed2 {
			int nVersion;
			uint256 hashPrevBlock;
			uint256 hashMerkleRoot;
			unsigned int nTime;
			unsigned int nBits;
			unsigned int nNonce;
		} block;
		unsigned char pchPadding0[64];
		uint256 hash1;
		unsigned char pchPadding1[64];
	} tmp;
	memset(&tmp, 0, sizeof(tmp));

	tmp.block.nVersion = pblock->nVersion;
	tmp.block.hashPrevBlock = pblock->hashPrevBlock;
	tmp.block.hashMerkleRoot = pblock->hashMerkleRoot;
	tmp.block.nTime = pblock->nTime;
	tmp.block.nBits = pblock->nBits;
	tmp.block.nNonce = pblock->nNonce;

	FormatHashBlocks(&tmp.block, sizeof(tmp.block));
	FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

	// Byte swap all the input buffer
	for (unsigned int i = 0; i < sizeof(tmp) / 4; i++)
		((unsigned int*) &tmp)[i] = ByteReverse(((unsigned int*) &tmp)[i]);

	// Precalc the first half of the first hash, which stays constant
	SHA256Transform(pmidstate, &tmp.block, pSHA256InitState);

	memcpy(pdata, &tmp.block, 128);
	memcpy(phash1, &tmp.hash1, 64);
}

bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey) {
	uint256 hash = pblock->GetPoWHash();
	uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

	CAuxPow *auxpow = pblock->auxpow.get();

	if (auxpow != NULL) {
		if (!auxpow->Check(pblock->GetHash(), pblock->GetChainID()))
			return error("AUX POW is not valid");

		if (auxpow->GetParentBlockHash() > hashTarget)
			return error("AUX POW parent hash %s is not under target %s",
					auxpow->GetParentBlockHash().GetHex().c_str(),
					hashTarget.GetHex().c_str());

		//// debug print
		printf("SyscoinMiner:\n");
		printf(
				"AUX proof-of-work found  \n     our hash: %s   \n  parent hash: %s  \n       target: %s\n",
				hash.GetHex().c_str(),
				auxpow->GetParentBlockHash().GetHex().c_str(),
				hashTarget.GetHex().c_str());

	} else {
		if (hash > hashTarget)
			return false;

		//// debug print
		printf("SyscoinMiner:\n");
		printf("proof-of-work found  \n  hash: %s  \ntarget: %s\n",
				hash.GetHex().c_str(), hashTarget.GetHex().c_str());
	}

	//// debug print
	pblock->print();
	printf("generated %s\n",
			FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());

	// Found a solution
	{
		LOCK(cs_main);
		if (pblock->hashPrevBlock != hashBestChain)
			return error("SyscoinMiner : generated block is stale");

		// Remove key from key pool
		reservekey.KeepKey();

		// Track how many getdata requests this block gets
		{
			LOCK(wallet.cs_wallet);
			wallet.mapRequestCount[pblock->GetHash()] = 0;
		}

		// Process this block the same as if we had received it from another node
		CValidationState state;
		if (!ProcessBlock(state, NULL, pblock))
			return error("SyscoinMiner : ProcessBlock, block not accepted");
	}

	return true;
}

std::string CBlockIndex::ToString() const {
	return strprintf(
			"CBlockIndex(pprev=%p, pnext=%p, nHeight=%d, merkle=%s, hashBlock=%s)",
			pprev, pnext, nHeight,
			hashMerkleRoot.ToString().substr(0, 10).c_str(),
			GetBlockHash().ToString().c_str());
}

std::string CDiskBlockIndex::ToString() const {
	std::string str = "CDiskBlockIndex(";
	str += CBlockIndex::ToString();
	str +=
			strprintf(
					"\n                hashBlock=%s, hashPrev=%s, hashParentBlock=%s)",
					GetBlockHash().ToString().c_str(),
					hashPrev.ToString().c_str(),
					(auxpow.get() != NULL) ? auxpow->GetParentBlockHash().ToString().substr(0,20).c_str() : "-");
	return str;
}

CBlockHeader CBlockIndex::GetBlockHeader() const {
	CBlockHeader block;

	if (nVersion & BLOCK_VERSION_AUXPOW) {
		CDiskBlockIndex diskblockindex;
		// auxpow is not in memory, load CDiskBlockHeader
		// from database to get it

		pblocktree->ReadDiskBlockIndex(*phashBlock, diskblockindex);
		block.auxpow = diskblockindex.auxpow;
	}

	block.nVersion = nVersion;
	if (pprev)
		block.hashPrevBlock = pprev->GetBlockHash();
	block.hashMerkleRoot = hashMerkleRoot;
	block.nTime = nTime;
	block.nBits = nBits;
	block.nNonce = nNonce;
	return block;
}

void static ScryptMiner(CWallet *pwallet) {
	printf("SyscoinscryptMiner started\n");
	SetThreadPriority(THREAD_PRIORITY_LOWEST);
	RenameThread("syscoin-miner");

	// Each thread has its own key and counter
	CReserveKey reservekey(pwallet);
	unsigned int nExtraNonce = 0;

	try {
		while(true) {
			while (vNodes.empty())
				MilliSleep(1000);

			//
			// Create new block
			//
			unsigned int nTransactionsUpdatedLast = nTransactionsUpdated;
			CBlockIndex* pindexPrev = pindexBest;

			auto_ptr<CBlockTemplate> pblocktemplate(
					CreateNewBlockWithKey(reservekey));
			if (!pblocktemplate.get())
				return;
			CBlock *pblock = &pblocktemplate->block;
			IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

			printf(
					"Running ScryptMiner with %"PRIszu" transactions in block (%u bytes)\n",
					pblock->vtx.size(),
					::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

			//
			// Pre-build hash buffers
			//
			char pmidstatebuf[32 + 16];
			char* pmidstate = alignup<16>(pmidstatebuf);
			char pdatabuf[128 + 16];
			char* pdata = alignup<16>(pdatabuf);
			char phash1buf[64 + 16];
			char* phash1 = alignup<16>(phash1buf);

			FormatHashBuffers(pblock, pmidstate, pdata, phash1);

			unsigned int& nBlockTime = *(unsigned int*) (pdata + 64 + 4);
			unsigned int& nBlockBits = *(unsigned int*) (pdata + 64 + 8);
			//unsigned int& nBlockNonce = *(unsigned int*)(pdata + 64 + 12);

			//
			// Search
			//
			int64 nStart = GetTime();
			uint256 hashTarget =
					CBigNum().SetCompact(pblock->nBits).getuint256();
			while(true) {
				unsigned int nHashesDone = 0;

				uint256 thash;
				char scratchpad[SCRYPT_SCRATCHPAD_SIZE];
				while(true) {
					scrypt_1024_1_1_256_sp_generic(BEGIN(pblock->nVersion),
							BEGIN(thash), scratchpad);

					if (thash <= hashTarget) {
						// Found a solution
						SetThreadPriority(THREAD_PRIORITY_NORMAL);
						CheckWork(pblock, *pwallet, reservekey);
						SetThreadPriority(THREAD_PRIORITY_LOWEST);
						break;
					}
					pblock->nNonce += 1;
					nHashesDone += 1;
					if ((pblock->nNonce & 0xFF) == 0)
						break;
				}

				// Meter hashes/sec
				static int64 nHashCounter;
				if (nHPSTimerStart == 0) {
					nHPSTimerStart = GetTimeMillis();
					nHashCounter = 0;
				} else
					nHashCounter += nHashesDone;
				if (GetTimeMillis() - nHPSTimerStart > 4000) {
					static CCriticalSection cs;
					{
						LOCK(cs);
						if (GetTimeMillis() - nHPSTimerStart > 4000) {
							dHashesPerSec = 1000.0 * nHashCounter
									/ (GetTimeMillis() - nHPSTimerStart);
							nHPSTimerStart = GetTimeMillis();
							nHashCounter = 0;
							static int64 nLogTime;
							if (GetTime() - nLogTime > 30 * 60) {
								nLogTime = GetTime();
								printf("hashmeter %6.0f khash/s\n",
										dHashesPerSec / 1000.0);
							}
						}
					}
				}

				// Check for stop or if block needs to be rebuilt
				boost::this_thread::interruption_point();
				if (vNodes.empty())
					break;
				if (pblock->nNonce >= 0xffff0000)
					break;
				if (nTransactionsUpdated != nTransactionsUpdatedLast
						&& GetTime() - nStart > 60)
					break;
				if (pindexPrev != pindexBest)
					break;

				// Update nTime every few seconds
				pblock->UpdateTime(pindexPrev);
				nBlockTime = ByteReverse(pblock->nTime);
				if (fTestNet || fCakeNet) {
					// Changing pblock->nTime can change work required on testnet:
					nBlockBits = ByteReverse(pblock->nBits);
					hashTarget =
							CBigNum().SetCompact(pblock->nBits).getuint256();
				}
			}
		}
	} catch (boost::thread_interrupted) {
		printf("ScryptMiner terminated\n");
		throw;
	}
}

void GenerateBitcoins(bool fGenerate, CWallet* pwallet) {
	static boost::thread_group* minerThreads = NULL;

	int nThreads = GetArg("-genproclimit", -1);
	if (nThreads < 0)
		nThreads = boost::thread::hardware_concurrency();

	if (minerThreads != NULL) {
		minerThreads->interrupt_all();
		delete minerThreads;
		minerThreads = NULL;
	}

	if (nThreads == 0 || !fGenerate)
		return;

	minerThreads = new boost::thread_group();
	for (int i = 0; i < nThreads; i++)
		minerThreads->create_thread(boost::bind(&ScryptMiner, pwallet));
}

// Amount compression:
// * If the amount is 0, output 0
// * first, divide the amount (in base units) by the largest power of 10 possible; call the exponent e (e is max 9)
// * if e<9, the last digit of the resulting number cannot be 0; store it as d, and drop it (divide by 10)
//   * call the result n
//   * output 1 + 10*(9*n + d - 1) + e
// * if e==9, we only know the resulting number is not zero, so output 1 + 10*(n - 1) + 9
// (this is decodable, as d is in [1-9] and e is in [0-9])

uint64 CTxOutCompressor::CompressAmount(uint64 n) {
	if (n == 0)
		return 0;
	int e = 0;
	while (((n % 10) == 0) && e < 9) {
		n /= 10;
		e++;
	}
	if (e < 9) {
		int d = (n % 10);
		assert(d >= 1 && d <= 9);
		n /= 10;
		return 1 + (n * 9 + d - 1) * 10 + e;
	} else {
		return 1 + (n - 1) * 10 + 9;
	}
}

uint64 CTxOutCompressor::DecompressAmount(uint64 x) {
	// x = 0  OR  x = 1+10*(9*n + d - 1) + e  OR  x = 1+10*(n - 1) + 9
	if (x == 0)
		return 0;
	x--;
	// x = 10*(9*n + d - 1) + e
	int e = x % 10;
	x /= 10;
	uint64 n = 0;
	if (e < 9) {
		// x = 9*n + d - 1
		int d = (x % 9) + 1;
		x /= 9;
		// x = n
		n = x * 10 + d;
	} else {
		n = x + 1;
	}
	while (e) {
		n *= 10;
		e--;
	}
	return n;
}

class CMainCleanup {
public:
	CMainCleanup() {
	}
	~CMainCleanup() {
		// block headers
		std::map<uint256, CBlockIndex*>::iterator it1 = mapBlockIndex.begin();
		for (; it1 != mapBlockIndex.end(); it1++)
			delete (*it1).second;
		mapBlockIndex.clear();

		// orphan blocks
		std::map<uint256, CBlock*>::iterator it2 = mapOrphanBlocks.begin();
		for (; it2 != mapOrphanBlocks.end(); it2++)
			delete (*it2).second;
		mapOrphanBlocks.clear();

		// orphan transactions
		mapOrphanTransactions.clear();
	}
} instance_of_cmaincleanup;
