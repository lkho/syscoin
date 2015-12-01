#include "escrow.h"
#include "init.h"
#include "txdb.h"
#include "util.h"
#include "auxpow.h"
#include "script.h"
#include "main.h"
#include "messagecrypter.h"
#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include <boost/algorithm/hex.hpp>
#include <boost/xpressive/xpressive_dynamic.hpp>
#include <boost/lexical_cast.hpp>
using namespace std;
using namespace json_spirit;

template<typename T> void ConvertTo(Value& value, bool fAllowNull = false);

extern bool ExistsInMempool(std::vector<unsigned char> vchNameOrRand, opcodetype type);
extern bool HasReachedMainNetForkB2();
extern CEscrowDB *pescrowdb;
extern COfferDB *pofferdb;
extern CAliasDB *paliasdb;
extern uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo,
        unsigned int nIn, int nHashType);

CScript RemoveEscrowScriptPrefix(const CScript& scriptIn);
bool DecodeEscrowScript(const CScript& script, int& op,
        std::vector<std::vector<unsigned char> > &vvch,
        CScript::const_iterator& pc);
extern bool Solver(const CKeyStore& keystore, const CScript& scriptPubKey,
        uint256 hash, int nHashType, CScript& scriptSigRet,
        txnouttype& whichTypeRet);
extern bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey,
        const CTransaction& txTo, unsigned int nIn, unsigned int flags,
        int nHashType);


void PutToEscrowList(std::vector<CEscrow> &escrowList, CEscrow& index) {
	int i = escrowList.size() - 1;
	BOOST_REVERSE_FOREACH(CEscrow &o, escrowList) {
        if(index.nHeight != 0 && o.nHeight == index.nHeight) {
        	escrowList[i] = index;
            return;
        }
        else if(o.txHash != 0 && o.txHash == index.txHash) {
        	escrowList[i] = index;
            return;
        }
        i--;
	}
    escrowList.push_back(index);
}
bool IsEscrowOp(int op) {
    return op == OP_ESCROW_ACTIVATE
        || op == OP_ESCROW_RELEASE
        || op == OP_ESCROW_REFUND
		|| op == OP_ESCROW_COMPLETE;
}
// 0.05% fee on escrow value for arbiter
int64 GetEscrowArbiterFee(int64 escrowValue) {

	int64 nFee = escrowValue*0.005;
	
	// Round up to CENT
	nFee += CENT - 1;
	nFee = (nFee / CENT) * CENT;
	return nFee;
}
int64 GetEscrowNetworkFee(opcodetype seed, unsigned int nHeight) {

	int64 nFee = 0;
	int64 nRate = 0;
	const vector<unsigned char> &vchCurrency = vchFromString("USD");
	vector<string> rateList;
	int precision;
	if(getCurrencyToSYSFromAlias(vchCurrency, nRate, nHeight, rateList, precision) != "")
		{
		if(seed==OP_ESCROW_ACTIVATE) 
		{
			nFee = 150 * COIN;
		}
		else if(seed==OP_ESCROW_RELEASE) 
		{
			nFee = 100 * COIN;
		} 
		else if(seed==OP_ESCROW_REFUND) 
		{
			nFee = 25 * COIN;
		}
		else if(seed==OP_ESCROW_COMPLETE)
		{
			nFee = 25 * COIN;
		}
	}
	else
	{
		// 10 pips USD, 10k pips = $1USD
		nFee = nRate/1000;
	}
	// Round up to CENT
	nFee += CENT - 1;
	nFee = (nFee / CENT) * CENT;
	return nFee;
}


// Increase expiration to 36000 gradually starting at block 24000.
// Use for validation purposes and pass the chain height.
int GetEscrowExpirationDepth() {
    return 525600;
}

// For display purposes, pass the name height.
int GetEscrowDisplayExpirationDepth() {
    return GetEscrowExpirationDepth();
}

bool IsMyEscrow(const CTransaction& tx, const CTxOut& txout) {
    const CScript& scriptPubKey = RemoveEscrowScriptPrefix(txout.scriptPubKey);
    CScript scriptSig;
    txnouttype whichTypeRet;
    if (!Solver(*pwalletMain, scriptPubKey, 0, 0, scriptSig, whichTypeRet))
        return false;
    return true;
}

string escrowFromOp(int op) {
    switch (op) {
    case OP_ESCROW_ACTIVATE:
        return "escrowactivate";
    case OP_ESCROW_RELEASE:
        return "escrowrelease";
    case OP_ESCROW_REFUND:
        return "escrowrefund";
	case OP_ESCROW_COMPLETE:
		return "escrowcomplete";
    default:
        return "<unknown escrow op>";
    }
}

bool CEscrow::UnserializeFromTx(const CTransaction &tx) {
    try {
        CDataStream dsEscrow(vchFromString(DecodeBase64(stringFromVch(tx.data))), SER_NETWORK, PROTOCOL_VERSION);
        dsEscrow >> *this;
    } catch (std::exception &e) {
        return false;
    }
    return true;
}

string CEscrow::SerializeToString() {
    // serialize escrow object
    CDataStream dsEscrow(SER_NETWORK, PROTOCOL_VERSION);
    dsEscrow << *this;
    vector<unsigned char> vchData(dsEscrow.begin(), dsEscrow.end());
    return EncodeBase64(vchData.data(), vchData.size());
}

//TODO implement
bool CEscrowDB::ScanEscrows(const std::vector<unsigned char>& vchEscrow, unsigned int nMax,
        std::vector<std::pair<std::vector<unsigned char>, CEscrow> >& escrowScan) {

    leveldb::Iterator *pcursor = pescrowdb->NewIterator();

    CDataStream ssKeySet(SER_DISK, CLIENT_VERSION);
    ssKeySet << make_pair(string("escrowi"), vchEscrow);
    string sType;
    pcursor->Seek(ssKeySet.str());

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
            leveldb::Slice slKey = pcursor->key();
            CDataStream ssKey(slKey.data(), slKey.data() + slKey.size(), SER_DISK, CLIENT_VERSION);

            ssKey >> sType;
            if(sType == "escrowi") {
                vector<unsigned char> vchEscrow;
                ssKey >> vchEscrow;
                leveldb::Slice slValue = pcursor->value();
                CDataStream ssValue(slValue.data(), slValue.data() + slValue.size(), SER_DISK, CLIENT_VERSION);
                vector<CEscrow> vtxPos;
                ssValue >> vtxPos;
                CEscrow txPos;
                if (!vtxPos.empty())
                    txPos = vtxPos.back();
                escrowScan.push_back(make_pair(vchEscrow, txPos));
            }
            if (escrowScan.size() >= nMax)
                break;

            pcursor->Next();
        } catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    delete pcursor;
    return true;
}

/**
 * [CEscrowDB::ReconstructEscrowIndex description]
 * @param  pindexRescan [description]
 * @return              [description]
 */
bool CEscrowDB::ReconstructEscrowIndex(CBlockIndex *pindexRescan) {
    CBlockIndex* pindex = pindexRescan;
	if(!HasReachedMainNetForkB2())
		return true;
    {
    TRY_LOCK(pwalletMain->cs_wallet, cs_trylock);
    while (pindex) {

        int nHeight = pindex->nHeight;
        CBlock block;
        block.ReadFromDisk(pindex);
        uint256 txblkhash;

        BOOST_FOREACH(CTransaction& tx, block.vtx) {

            if (tx.nVersion != SYSCOIN_TX_VERSION)
                continue;

            vector<vector<unsigned char> > vvchArgs;
            int op, nOut;

            // decode the escrow op, params, height
            bool o = DecodeEscrowTx(tx, op, nOut, vvchArgs, -1);
            if (!o || !IsEscrowOp(op)) continue;

            vector<unsigned char> vchEscrow = vvchArgs[0];

            // get the transaction
            if(!GetTransaction(tx.GetHash(), tx, txblkhash, true))
                continue;

            // attempt to read escrow from txn
            CEscrow txEscrow;
            if(!txEscrow.UnserializeFromTx(tx))
                return error("ReconstructEscrowIndex() : failed to unserialize escrow from tx");

            // save serialized escrow
            CEscrow serializedEscrow = txEscrow;

            // read escrow from DB if it exists
            vector<CEscrow> vtxPos;
            if (ExistsEscrow(vchEscrow)) {
                if (!ReadEscrow(vchEscrow, vtxPos))
                    return error("ReconstructEscrowIndex() : failed to read escrow from DB");
            }

            txEscrow.txHash = tx.GetHash();
            txEscrow.nHeight = nHeight;
            // txn-specific values to escrow object
            txEscrow.vchRand = vvchArgs[0];
            PutToEscrowList(vtxPos, txEscrow);

            if (!WriteEscrow(vchEscrow, vtxPos))
                return error("ReconstructEscrowIndex() : failed to write to escrow DB");

          
            printf( "RECONSTRUCT ESCROW: op=%s escrow=%s hash=%s height=%d\n",
                    escrowFromOp(op).c_str(),
                    stringFromVch(vvchArgs[0]).c_str(),
                    tx.GetHash().ToString().c_str(),
                    nHeight);
        }
        pindex = pindex->pnext;
        
    }
	Flush();
    }
    return true;
}



int64 GetEscrowNetFee(const CTransaction& tx) {
    int64 nFee = 0;
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        if (out.scriptPubKey.size() == 1 && out.scriptPubKey[0] == OP_RETURN)
            nFee += out.nValue;
    }
    return nFee;
}

int GetEscrowHeight(vector<unsigned char> vchEscrow) {
    vector<CEscrow> vtxPos;
    if (pescrowdb->ExistsEscrow(vchEscrow)) {
        if (!pescrowdb->ReadEscrow(vchEscrow, vtxPos))
            return error("GetEscrowHeight() : failed to read from escrow DB");
        if (vtxPos.empty()) return -1;
        CEscrow& txPos = vtxPos.back();
        return txPos.nHeight;
    }
    return -1;
}


int IndexOfEscrowOutput(const CTransaction& tx) {
    vector<vector<unsigned char> > vvch;
    int op, nOut;
    if (!DecodeEscrowTx(tx, op, nOut, vvch, -1))
        throw runtime_error("IndexOfEscrowOutput() : escrow output not found");
    return nOut;
}

bool GetNameOfEscrowTx(const CTransaction& tx, vector<unsigned char>& escrow) {
    if (tx.nVersion != SYSCOIN_TX_VERSION)
        return false;
    vector<vector<unsigned char> > vvchArgs;
    int op, nOut;
    if (!DecodeEscrowTx(tx, op, nOut, vvchArgs, -1))
        return error("GetNameOfEscrowTx() : could not decode a syscoin tx");

    switch (op) {
        case OP_ESCROW_ACTIVATE:
        case OP_ESCROW_RELEASE:
        case OP_ESCROW_REFUND:
		case OP_ESCROW_COMPLETE:
            escrow = vvchArgs[0];
            return true;
    }
    return false;
}

bool GetValueOfEscrowTx(const CTransaction& tx, vector<unsigned char>& value) {
    vector<vector<unsigned char> > vvch;
    int op, nOut;

    if (!DecodeEscrowTx(tx, op, nOut, vvch, -1))
        return false;

    switch (op) {
    case OP_ESCROW_ACTIVATE:
    case OP_ESCROW_RELEASE:
    case OP_ESCROW_REFUND:
	case OP_ESCROW_COMPLETE:
        value = vvch[1];
        return true;
    default:
        return false;
    }
}

bool IsEscrowMine(const CTransaction& tx) {
    if (tx.nVersion != SYSCOIN_TX_VERSION)
        return false;

    vector<vector<unsigned char> > vvch;
    int op, nOut;

    bool good = DecodeEscrowTx(tx, op, nOut, vvch, -1);
    if (!good) 
        return false;
    
    if(!IsEscrowOp(op))
        return false;

    const CTxOut& txout = tx.vout[nOut];
    if (IsMyEscrow(tx, txout)) {
        printf("IsEscrowMine() : found my transaction %s nout %d\n",
                tx.GetHash().GetHex().c_str(), nOut);
        return true;
    }
    return false;
}

bool IsEscrowMine(const CTransaction& tx, const CTxOut& txout) {
    if (tx.nVersion != SYSCOIN_TX_VERSION)
        return false;

    vector<vector<unsigned char> > vvch;
    int op, nOut;

	if (!DecodeEscrowScript(txout.scriptPubKey, op, vvch))
		return false;
    
    if(!IsEscrowOp(op))
        return false;

    if (IsMyEscrow(tx, txout)) {
        printf("IsEscrowMine() : found my transaction %s value %d\n",
                tx.GetHash().GetHex().c_str(), (int) txout.nValue);
        return true;
    }
    return false;
}

bool GetValueOfEscrowTxHash(const uint256 &txHash,
        vector<unsigned char>& vchValue, uint256& hash, int& nHeight) {
    nHeight = GetTxHashHeight(txHash);
    CTransaction tx;
    uint256 blockHash;
    if (!GetTransaction(txHash, tx, blockHash, true))
        return error("GetValueOfEscrowTxHash() : could not read tx from disk");
    if (!GetValueOfEscrowTx(tx, vchValue))
        return error("GetValueOfEscrowTxHash() : could not decode value from tx");
    hash = tx.GetHash();
    return true;
}

bool GetValueOfEscrow(CEscrowDB& dbEscrow, const vector<unsigned char> &vchEscrow,
        vector<unsigned char>& vchValue, int& nHeight) {
    vector<CEscrow> vtxPos;
    if (!pescrowdb->ReadEscrow(vchEscrow, vtxPos) || vtxPos.empty())
        return false;

    CEscrow& txPos = vtxPos.back();
    nHeight = txPos.nHeight;
    vchValue = txPos.vchRand;
    return true;
}

bool GetTxOfEscrow(CEscrowDB& dbEscrow, const vector<unsigned char> &vchEscrow,
        CEscrow& txPos, CTransaction& tx) {
    vector<CEscrow> vtxPos;
    if (!pescrowdb->ReadEscrow(vchEscrow, vtxPos) || vtxPos.empty())
        return false;
    txPos = vtxPos.back();
    int nHeight = txPos.nHeight;
    if (nHeight + GetEscrowExpirationDepth()
            < pindexBest->nHeight) {
        string escrow = stringFromVch(vchEscrow);
        printf("GetTxOfEscrow(%s) : expired", escrow.c_str());
        return false;
    }

    uint256 hashBlock;
    if (!GetTransaction(txPos.txHash, tx, hashBlock, true))
        return error("GetTxOfEscrow() : could not read tx from disk");

    return true;
}

bool DecodeEscrowTx(const CTransaction& tx, int& op, int& nOut,
        vector<vector<unsigned char> >& vvch, int nHeight) {
    bool found = false;


    // Strict check - bug disallowed
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        vector<vector<unsigned char> > vvchRead;
        if (DecodeEscrowScript(out.scriptPubKey, op, vvchRead)) {
            nOut = i; found = true; vvch = vvchRead;
            break;
        }
    }
	if (!found) vvch.clear();
    return found;
}

bool GetValueOfEscrowTx(const CCoins& tx, vector<unsigned char>& value) {
    vector<vector<unsigned char> > vvch;

    int op, nOut;

    if (!DecodeEscrowTx(tx, op, nOut, vvch, -1))
        return false;

    switch (op) {
    case OP_ESCROW_ACTIVATE:
    case OP_ESCROW_RELEASE:
    case OP_ESCROW_REFUND:
	case OP_ESCROW_COMPLETE:
        value = vvch[1];
        return true;
    default:
        return false;
    }
}

bool DecodeEscrowTx(const CCoins& tx, int& op, int& nOut,
        vector<vector<unsigned char> >& vvch, int nHeight) {
    bool found = false;


    // Strict check - bug disallowed
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        vector<vector<unsigned char> > vvchRead;
        if (DecodeEscrowScript(out.scriptPubKey, op, vvchRead)) {
            nOut = i; found = true; vvch = vvchRead;
            break;
        }
    }
    if (!found)
        vvch.clear();
    return found;
}

bool DecodeEscrowScript(const CScript& script, int& op,
        vector<vector<unsigned char> > &vvch) {
    CScript::const_iterator pc = script.begin();
    return DecodeEscrowScript(script, op, vvch, pc);
}

bool DecodeEscrowScript(const CScript& script, int& op,
        vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) {
    opcodetype opcode;
	if (!script.GetOp(pc, opcode)) return false;
	if (opcode < OP_1 || opcode > OP_16) return false;
    op = CScript::DecodeOP_N(opcode);
    for (;;) {
        vector<unsigned char> vch;
        if (!script.GetOp(pc, opcode, vch))
            return false;

        if (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP)
            break;
        if (!(opcode >= 0 && opcode <= OP_PUSHDATA4))
            return false;
        vvch.push_back(vch);
    }

    // move the pc to after any DROP or NOP
    while (opcode == OP_DROP || opcode == OP_2DROP || opcode == OP_NOP) {
        if (!script.GetOp(pc, opcode))
            break;
    }
	
    pc--;

    if ((op == OP_ESCROW_ACTIVATE && vvch.size() == 2)
        || (op == OP_ESCROW_RELEASE && vvch.size() == 2)
        || (op == OP_ESCROW_REFUND && vvch.size() == 2)
		|| (op == OP_ESCROW_COMPLETE && vvch.size() == 2))
        return true;

    return false;
}


bool SignEscrowSignature(const CTransaction& txFrom, CTransaction& txTo,
        unsigned int nIn, int nHashType = SIGHASH_ALL) {
    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CTxOut& txout = txFrom.vout[txin.prevout.n];
    // Leave out the signature from the hash, since a signature can't sign itself.
    // The checksig op will also drop the signatures from its hash.
    const CScript& scriptPubKey = RemoveEscrowScriptPrefix(txout.scriptPubKey);
    uint256 hash = SignatureHash(txout.scriptPubKey, txTo, nIn,
            nHashType);
    txnouttype whichTypeRet;

    if (!Solver(*pwalletMain, scriptPubKey, hash, nHashType, txin.scriptSig,
            whichTypeRet))
        return false;

    // Test the solution
    if (!VerifyScript(txin.scriptSig, txout.scriptPubKey, txTo, nIn, 0, 0))
        return false;

    return true;
}

bool CreateEscrowTransactionWithMultiInputTx(
        const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxCertIn, CWalletTx& wtxEscrowIn,
        int nTxCertOut, int nTxEscrowOut, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet,
        const string& txData) {
    int64 nValue = 0;
    BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend) {
        if (nValue < 0)
            return false;
        nValue += s.second;
    }
    if (vecSend.empty() || nValue < 0)
        return false;

    wtxNew.BindWallet(pwalletMain);

    nFeeRet = nTransactionFee;
    while(true) {
        wtxNew.vin.clear();
        wtxNew.vout.clear();
        wtxNew.fFromMe = true;
        wtxNew.data = vchFromString(txData);

        int64 nTotalValue = nValue + nFeeRet;
        printf("CreateEscrowTransactionWithInputTx: total value = %d\n",
                (int) nTotalValue);
        double dPriority = 0;

        // vouts to the payees
        BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
            wtxNew.vout.push_back(CTxOut(s.second, s.first));

        int64 nWtxCertinCredit = wtxCertIn.vout[nTxCertOut].nValue;
		int64 nWtxEscrowinCredit = wtxEscrowIn.vout[nTxEscrowOut].nValue;

        // Choose coins to use
        set<pair<const CWalletTx*, unsigned int> > setCoins;
        int64 nValueIn = 0;
        printf( "CreateEscrowTransactionWithInputTx: SelectCoins(%s), nTotalValue = %s, nWtxinCredit = %s\n",
                FormatMoney(nTotalValue - nWtxCertinCredit - nWtxEscrowinCredit).c_str(),
                FormatMoney(nTotalValue).c_str(),
                FormatMoney(nWtxCertinCredit+nWtxEscrowinCredit).c_str());
        if ((nTotalValue - nWtxCertinCredit - nWtxEscrowinCredit) > 0) {
            if (!pwalletMain->SelectCoins(nTotalValue - nWtxCertinCredit - nWtxEscrowinCredit,
                    setCoins, nValueIn))
                return false;
        }

        printf( "CreateEscrowTransactionWithInputTx: selected %d tx outs, nValueIn = %s\n",
                (int) setCoins.size(), FormatMoney(nValueIn).c_str());

        vector<pair<const CWalletTx*, unsigned int> > vecCoins(
                setCoins.begin(), setCoins.end());

        BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
            int64 nCredit = coin.first->vout[coin.second].nValue;
            dPriority += (double) nCredit
                    * coin.first->GetDepthInMainChain();
        }

        // Input tx always at first position
        vecCoins.insert(vecCoins.begin(), make_pair(&wtxCertIn, nTxCertOut));
		vecCoins.insert(vecCoins.begin(), make_pair(&wtxEscrowIn, nTxEscrowOut));

        nValueIn += nWtxCertinCredit;
		nValueIn += nWtxEscrowinCredit;
        dPriority += (double) nWtxCertinCredit * wtxCertIn.GetDepthInMainChain();
		dPriority += (double) nWtxEscrowinCredit * wtxEscrowIn.GetDepthInMainChain();

        // Fill a vout back to self with any change
        int64 nChange = nValueIn - nTotalValue;
        if (nChange >= CENT) {
            // Note: We use a new key here to keep it from being obvious which side is the change.
            //  The drawback is that by not reusing a previous key, the change may be lost if a
            //  backup is restored, if the backup doesn't have the new private key for the change.
            //  If we reused the old key, it would be possible to add code to look for and
            //  rediscover unknown transactions that were written with keys of ours to recover
            //  post-backup change.

            // Reserve a new key pair from key pool
            CPubKey pubkey;
            assert(reservekey.GetReservedKey(pubkey));

            // -------------- Fill a vout to ourself, using same address type as the payment
            // Now sending always to hash160 (GetBitcoinAddressHash160 will return hash160, even if pubkey is used)
            CScript scriptChange;
            if (Hash160(vecSend[0].first) != 0)
                scriptChange.SetDestination(pubkey.GetID());
            else
                scriptChange << pubkey << OP_CHECKSIG;

            // Insert change txn at random position:
            vector<CTxOut>::iterator position = wtxNew.vout.begin()
                    + GetRandInt(wtxNew.vout.size());
            wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
        } else
            reservekey.ReturnKey();

        // Fill vin
        BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins)
            wtxNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second));

        // Sign
        int nIn = 0;
        BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
            if (coin.first == &wtxEscrowIn
                    && coin.second == (unsigned int) nTxEscrowOut) {
                if (!SignEscrowSignature(*coin.first, wtxNew, nIn++))
                    throw runtime_error("could not sign escrow coin output");
            }
            if (coin.first == &wtxCertIn
                    && coin.second == (unsigned int) nTxCertOut) {
                if (!SignCertSignature(*coin.first, wtxNew, nIn++))
                    throw runtime_error("could not sign cert coin output");
            }
			else {
                if (!SignSignature(*pwalletMain, *coin.first, wtxNew, nIn++))
                    return false;
            }
        }

        // Limit size
        unsigned int nBytes = ::GetSerializeSize(*(CTransaction*) &wtxNew,
                SER_NETWORK, PROTOCOL_VERSION);
        if (nBytes >= MAX_BLOCK_SIZE_GEN / 5)
            return false;
        dPriority /= nBytes;

        // Check that enough fee is included
        int64 nPayFee = nTransactionFee * (1 + (int64) nBytes / 1000);
        bool fAllowFree = CTransaction::AllowFree(dPriority);
        int64 nMinFee = wtxNew.GetMinFee(1, fAllowFree);
        if (nFeeRet < max(nPayFee, nMinFee)) {
            nFeeRet = max(nPayFee, nMinFee);
            printf( "CreateEscrowTransactionWithInputTx: re-iterating (nFreeRet = %s)\n",
                    FormatMoney(nFeeRet).c_str());
            continue;
        }

        // Fill vtxPrev by copying from previous transactions vtxPrev
        wtxNew.AddSupportingTransactions();
        wtxNew.fTimeReceivedIsTxTime = true;

        break;
    }
    

    printf("CreateEscrowTransactionWithInputTx succeeded:\n%s",
            wtxNew.ToString().c_str());
    return true;
}
bool CreateEscrowTransactionWithInputTx(
        const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxIn,
        int nTxOut, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet,
        const string& txData) {
    int64 nValue = 0;
    BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend) {
        if (nValue < 0)
            return false;
        nValue += s.second;
    }
    if (vecSend.empty() || nValue < 0)
        return false;

    wtxNew.BindWallet(pwalletMain);

    nFeeRet = nTransactionFee;
    while(true) {
        wtxNew.vin.clear();
        wtxNew.vout.clear();
        wtxNew.fFromMe = true;
        wtxNew.data = vchFromString(txData);

        int64 nTotalValue = nValue + nFeeRet;
        printf("CreateEscrowTransactionWithInputTx: total value = %d\n",
                (int) nTotalValue);
        double dPriority = 0;

        // vouts to the payees
        BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
            wtxNew.vout.push_back(CTxOut(s.second, s.first));

        int64 nWtxinCredit = wtxIn.vout[nTxOut].nValue;

        // Choose coins to use
        set<pair<const CWalletTx*, unsigned int> > setCoins;
        int64 nValueIn = 0;
        printf( "CreateEscrowTransactionWithInputTx: SelectCoins(%s), nTotalValue = %s, nWtxinCredit = %s\n",
                FormatMoney(nTotalValue - nWtxinCredit).c_str(),
                FormatMoney(nTotalValue).c_str(),
                FormatMoney(nWtxinCredit).c_str());
        if (nTotalValue - nWtxinCredit > 0) {
            if (!pwalletMain->SelectCoins(nTotalValue - nWtxinCredit,
                    setCoins, nValueIn))
                return false;
        }

        printf( "CreateEscrowTransactionWithInputTx: selected %d tx outs, nValueIn = %s\n",
                (int) setCoins.size(), FormatMoney(nValueIn).c_str());

        vector<pair<const CWalletTx*, unsigned int> > vecCoins(
                setCoins.begin(), setCoins.end());

        BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
            int64 nCredit = coin.first->vout[coin.second].nValue;
            dPriority += (double) nCredit
                    * coin.first->GetDepthInMainChain();
        }

        // Input tx always at first position
        vecCoins.insert(vecCoins.begin(), make_pair(&wtxIn, nTxOut));

        nValueIn += nWtxinCredit;
        dPriority += (double) nWtxinCredit * wtxIn.GetDepthInMainChain();

        // Fill a vout back to self with any change
        int64 nChange = nValueIn - nTotalValue;
        if (nChange >= CENT) {
            // Note: We use a new key here to keep it from being obvious which side is the change.
            //  The drawback is that by not reusing a previous key, the change may be lost if a
            //  backup is restored, if the backup doesn't have the new private key for the change.
            //  If we reused the old key, it would be possible to add code to look for and
            //  rediscover unknown transactions that were written with keys of ours to recover
            //  post-backup change.

            // Reserve a new key pair from key pool
            CPubKey pubkey;
            assert(reservekey.GetReservedKey(pubkey));

            // -------------- Fill a vout to ourself, using same address type as the payment
            // Now sending always to hash160 (GetBitcoinAddressHash160 will return hash160, even if pubkey is used)
            CScript scriptChange;
            if (Hash160(vecSend[0].first) != 0)
                scriptChange.SetDestination(pubkey.GetID());
            else
                scriptChange << pubkey << OP_CHECKSIG;

            // Insert change txn at random position:
            vector<CTxOut>::iterator position = wtxNew.vout.begin()
                    + GetRandInt(wtxNew.vout.size());
            wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
        } else
            reservekey.ReturnKey();

        // Fill vin
        BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins)
            wtxNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second));

        // Sign
        int nIn = 0;
        BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
            if (coin.first == &wtxIn
                    && coin.second == (unsigned int) nTxOut) {
                if (!SignEscrowSignature(*coin.first, wtxNew, nIn++))
                    throw runtime_error("could not sign escrow coin output");
            } else {
                if (!SignSignature(*pwalletMain, *coin.first, wtxNew, nIn++))
                    return false;
            }
        }

        // Limit size
        unsigned int nBytes = ::GetSerializeSize(*(CTransaction*) &wtxNew,
                SER_NETWORK, PROTOCOL_VERSION);
        if (nBytes >= MAX_BLOCK_SIZE_GEN / 5)
            return false;
        dPriority /= nBytes;

        // Check that enough fee is included
        int64 nPayFee = nTransactionFee * (1 + (int64) nBytes / 1000);
        bool fAllowFree = CTransaction::AllowFree(dPriority);
        int64 nMinFee = wtxNew.GetMinFee(1, fAllowFree);
        if (nFeeRet < max(nPayFee, nMinFee)) {
            nFeeRet = max(nPayFee, nMinFee);
            printf( "CreateEscrowTransactionWithInputTx: re-iterating (nFreeRet = %s)\n",
                    FormatMoney(nFeeRet).c_str());
            continue;
        }

        // Fill vtxPrev by copying from previous transactions vtxPrev
        wtxNew.AddSupportingTransactions();
        wtxNew.fTimeReceivedIsTxTime = true;

        break;
    }
    

    printf("CreateEscrowTransactionWithInputTx succeeded:\n%s",
            wtxNew.ToString().c_str());
    return true;
}
void EraseEscrow(CWalletTx& wtx)
{
	 UnspendInputs(wtx);
	 wtx.RemoveFromMemoryPool();
	 pwalletMain->EraseFromWallet(wtx.GetHash());
}
string SendEscrowMoneyWithMultiInputTx(vector<pair<CScript, int64> > &vecSend, int64 nValue,
        int64 nNetFee, CWalletTx& wtxCertIn, CWalletTx& wtxEscrowIn, CWalletTx& wtxNew, bool fAskFee,
        const string& txData) {
    int nTxCertOut = IndexOfCertOutput(wtxCertIn);
	int nTxEscrowOut = IndexOfEscrowOutput(wtxEscrowIn);
    CReserveKey reservekey(pwalletMain);
    int64 nFeeRequired;

    if (nNetFee) {
        CScript scriptFee;
        scriptFee << OP_RETURN;
        vecSend.push_back(make_pair(scriptFee, nNetFee));
    }

    if (!CreateEscrowTransactionWithMultiInputTx(vecSend, wtxCertIn, wtxEscrowIn, nTxCertOut, nTxEscrowOut, wtxNew,
            reservekey, nFeeRequired, txData)) {
        string strError;
        if (nValue + nFeeRequired > pwalletMain->GetBalance())
            strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds "),
                            FormatMoney(nFeeRequired).c_str());
        else
            strError = _("Error: Transaction creation failed  ");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }

#ifdef GUI
    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired))
    return "ABORTED";
#else
    if (fAskFee && !true)
        return "ABORTED";
#endif

    if (!pwalletMain->CommitTransaction(wtxNew, reservekey))
	{
        return _(
                "Error: The transaction was rejected.");
	}
    return "";
}
// nTxOut is the output from wtxIn that we should grab
string SendEscrowMoneyWithInputTx(CScript scriptPubKey, int64 nValue,
        int64 nNetFee, CWalletTx& wtxIn, CWalletTx& wtxNew, bool fAskFee,
        const string& txData) {
    int nTxOut = IndexOfEscrowOutput(wtxIn);
    CReserveKey reservekey(pwalletMain);
    int64 nFeeRequired;
    vector<pair<CScript, int64> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));

    if (nNetFee) {
        CScript scriptFee;
        scriptFee << OP_RETURN;
        vecSend.push_back(make_pair(scriptFee, nNetFee));
    }

    if (!CreateEscrowTransactionWithInputTx(vecSend, wtxIn, nTxOut, wtxNew,
            reservekey, nFeeRequired, txData)) {
        string strError;
        if (nValue + nFeeRequired > pwalletMain->GetBalance())
            strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds "),
                            FormatMoney(nFeeRequired).c_str());
        else
            strError = _("Error: Transaction creation failed  ");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }

#ifdef GUI
    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired))
    return "ABORTED";
#else
    if (fAskFee && !true)
        return "ABORTED";
#endif

    if (!pwalletMain->CommitTransaction(wtxNew, reservekey))
	{
        return _(
                "Error: The transaction was rejected.");
	}
    return "";
}
// nTxOut is the output from wtxIn that we should grab
string SendEscrowMoneyWithInputTx(vector<pair<CScript, int64> > &vecSend, int64 nValue,
        int64 nNetFee, CWalletTx& wtxIn, CWalletTx& wtxNew, bool fAskFee,
        const string& txData) {
    int nTxOut = IndexOfEscrowOutput(wtxIn);
    CReserveKey reservekey(pwalletMain);
    int64 nFeeRequired;

    if (nNetFee) {
        CScript scriptFee;
        scriptFee << OP_RETURN;
        vecSend.push_back(make_pair(scriptFee, nNetFee));
    }

    if (!CreateEscrowTransactionWithInputTx(vecSend, wtxIn, nTxOut, wtxNew,
            reservekey, nFeeRequired, txData)) {
        string strError;
        if (nValue + nFeeRequired > pwalletMain->GetBalance())
            strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds "),
                            FormatMoney(nFeeRequired).c_str());
        else
            strError = _("Error: Transaction creation failed  ");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }

#ifdef GUI
    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired))
    return "ABORTED";
#else
    if (fAskFee && !true)
        return "ABORTED";
#endif

    if (!pwalletMain->CommitTransaction(wtxNew, reservekey))
	{
        return _(
                "Error: The transaction was rejected.");
	}
    return "";
}

bool GetEscrowAddress(const CTransaction& tx, std::string& strAddress) {
    int op, nOut = 0;
    vector<vector<unsigned char> > vvch;
    if (!DecodeEscrowTx(tx, op, nOut, vvch, -1))
        return error("GetEscrowAddress() : could not decode escrow tx.");

    const CTxOut& txout = tx.vout[nOut];

    const CScript& scriptPubKey = RemoveEscrowScriptPrefix(txout.scriptPubKey);
	CTxDestination dest;
	ExtractDestination(scriptPubKey, dest);
	strAddress = CBitcoinAddress(dest).ToString();
    return true;
}

bool GetEscrowAddress(const CDiskTxPos& txPos, std::string& strAddress) {
    CTransaction tx;
    if (!tx.ReadFromDisk(txPos))
        return error("GetEscrowAddress() : could not read tx from disk");
    return GetEscrowAddress(tx, strAddress);
}

CScript RemoveEscrowScriptPrefix(const CScript& scriptIn) {
    int op;
    vector<vector<unsigned char> > vvch;
    CScript::const_iterator pc = scriptIn.begin();

    if (!DecodeEscrowScript(scriptIn, op, vvch, pc))
	{
        throw runtime_error("RemoveEscrowScriptPrefix() : could not decode escrow script");
	}
	
    return CScript(pc, scriptIn.end());
}

bool CheckEscrowInputs(CBlockIndex *pindexBlock, const CTransaction &tx,
        CValidationState &state, CCoinsViewCache &inputs, bool fBlock, bool fMiner,
        bool fJustCheck) {

    if (!tx.IsCoinBase()) {
        printf("*** %d %d %s %s %s %s\n", pindexBlock->nHeight,
                pindexBest->nHeight, tx.GetHash().ToString().c_str(),
                fBlock ? "BLOCK" : "", fMiner ? "MINER" : "",
                fJustCheck ? "JUSTCHECK" : "");

        bool found = false;
        const COutPoint *prevOutput = NULL;
        const CCoins *prevCoins = NULL;

        int prevOp;
        vector<vector<unsigned char> > vvchPrevArgs;
		vvchPrevArgs.clear();
        // Strict check - bug disallowed
		for (int i = 0; i < (int) tx.vin.size(); i++) {
			vector<vector<unsigned char> > vvch;
			prevOutput = &tx.vin[i].prevout;
			prevCoins = &inputs.GetCoins(prevOutput->hash);
			if(DecodeEscrowScript(prevCoins->vout[prevOutput->n].scriptPubKey, prevOp, vvch))
			{
				vvchPrevArgs = vvch;
				found = true;
				break;
			}
			if(!found)vvchPrevArgs.clear();
			
		}
		
        // Make sure escrow outputs are not spent by a regular transaction, or the escrow would be lost
        if (tx.nVersion != SYSCOIN_TX_VERSION) {
            if (found)
                return error(
                        "CheckEscrowInputs() : a non-syscoin transaction with a syscoin input");
			printf("CheckEscrowInputs() : non-syscoin transaction\n");
            return true;
        }
        vector<vector<unsigned char> > vvchArgs;
        int op, nOut;
        bool good = DecodeEscrowTx(tx, op, nOut, vvchArgs, -1);
        if (!good)
            return error("CheckEscrowInputs() : could not decode a syscoin tx");
        int nDepth;
        int64 nNetFee;
        // unserialize escrow object from txn, check for valid
        CEscrow theEscrow;
        theEscrow.UnserializeFromTx(tx);
        if (theEscrow.IsNull())
            return error("CheckEscrowInputs() : null escrow object");
		if(theEscrow.vchRand.size() > 20)
		{
			return error("escrow rand too big");
		}
        if (vvchArgs[0].size() > MAX_NAME_LENGTH)
            return error("escrow tx GUID too big");
		if (vvchArgs[1].size() > 20)
			return error("escrow tx rand too big");
        switch (op) {
        case OP_ESCROW_ACTIVATE:
			if (fBlock && !fJustCheck) {

					// check for enough fees
				nNetFee = GetEscrowNetFee(tx);
				if (nNetFee < GetEscrowNetworkFee(OP_ESCROW_ACTIVATE, theEscrow.nHeight))
					return error(
							"CheckEscrowInputs() : OP_ESCROW_ACTIVATE got tx %s with fee too low %lu",
							tx.GetHash().GetHex().c_str(),
							(long unsigned int) nNetFee);		
			}
            break;

        case OP_ESCROW_RELEASE:
			if (fBlock && !fJustCheck) {
				// check for enough fees
				nNetFee = GetEscrowNetFee(tx);
				if (nNetFee < GetEscrowNetworkFee(OP_ESCROW_RELEASE, theEscrow.nHeight))
					return error(
							"CheckEscrowInputs() : OP_ESCROW_RELEASE got tx %s with fee too low %lu",
							tx.GetHash().GetHex().c_str(),
							(long unsigned int) nNetFee);
			}
            break;
        case OP_ESCROW_REFUND:

            if (fBlock && !fJustCheck) {		
                // check for enough fees
                int64 expectedFee = GetEscrowNetworkFee(OP_ESCROW_REFUND, theEscrow.nHeight);
                nNetFee = GetEscrowNetFee(tx);
                if (nNetFee < expectedFee)
                    return error(
                            "CheckEscrowInputs() : OP_ESCROW_REFUND got tx %s with fee too low %lu",
                            tx.GetHash().GetHex().c_str(),
                            (long unsigned int) nNetFee);

            }

            break;
        case OP_ESCROW_COMPLETE:
            if (fBlock && !fJustCheck) {
                // check for enough fees
                int64 expectedFee = GetEscrowNetworkFee(OP_ESCROW_COMPLETE, theEscrow.nHeight);
                nNetFee = GetEscrowNetFee(tx);
                if (nNetFee < expectedFee)
                    return error(
                            "CheckEscrowInputs() : OP_ESCROW_COMPLETE got tx %s with fee too low %lu",
                            tx.GetHash().GetHex().c_str(),
                            (long unsigned int) nNetFee);

            }

            break;
        default:
            return error( "CheckEscrowInputs() : escrow transaction has unknown op");
        }



        // these ifs are problably total bullshit except for the escrownew
        if (fBlock || (!fBlock && !fMiner && !fJustCheck)) {
			// save serialized escrow for later use
			CEscrow serializedEscrow = theEscrow;

			// if not an escrownew, load the escrow data from the DB
			vector<CEscrow> vtxPos;
			if (pescrowdb->ExistsEscrow(vvchArgs[0]) && !fJustCheck) {
				if (!pescrowdb->ReadEscrow(vvchArgs[0], vtxPos))
					return error(
							"CheckEscrowInputs() : failed to read from escrow DB");
			}
            if (!fMiner && !fJustCheck && pindexBlock->nHeight != pindexBest->nHeight) {
                int nHeight = pindexBlock->nHeight;
				// make sure escrow settings don't change (besides rawTx) outside of activation
				if(op != OP_ESCROW_ACTIVATE) 
				{
					bool escrowChanged = false;
					// make sure we have found this offer in the dbescrowhist
					if(!vtxPos.empty())
					{
						// these are the only settings allowed to change outside of activate
						serializedEscrow.rawTx = vtxPos.back().rawTx;
						serializedEscrow.nHeight = vtxPos.back().nHeight;
						serializedEscrow.txHash = vtxPos.back().txHash;
						serializedEscrow.vchOfferAcceptLink = vtxPos.back().vchOfferAcceptLink;
						if(serializedEscrow != vtxPos.back())
							escrowChanged = true;
					}
					if(fDebug && escrowChanged)
					{
						printf("CheckEscrowInputs(): Escrow object changed outside of activate, not allowed!\n");
						return true;
					}
				}
				

                // set the escrow's txn-dependent values
				theEscrow.txHash = tx.GetHash();
				theEscrow.nHeight = nHeight;
                theEscrow.vchRand = vvchArgs[0];
				PutToEscrowList(vtxPos, theEscrow);
				{
				TRY_LOCK(cs_main, cs_trymain);
                // write escrow  
                if (!pescrowdb->WriteEscrow(vvchArgs[0], vtxPos))
                    return error( "CheckEscrowInputs() : failed to write to escrow DB");

              			
                // debug
				if(fDebug)
					printf( "CONNECTED ESCROW: op=%s escrow=%s hash=%s height=%d\n",
                        escrowFromOp(op).c_str(),
                        stringFromVch(vvchArgs[0]).c_str(),
                        tx.GetHash().ToString().c_str(),
                        nHeight);
				}
            }
            
        }
    }
    return true;
}

bool ExtractEscrowAddress(const CScript& script, string& address) {
    if (script.size() == 1 && script[0] == OP_RETURN) {
        address = string("network fee");
        return true;
    }
    vector<vector<unsigned char> > vvch;
    int op;
    if (!DecodeEscrowScript(script, op, vvch))
        return false;

    string strOp = escrowFromOp(op);
    string strEscrow;

    strEscrow = stringFromVch(vvch[0]);

    address = strOp + ": " + strEscrow;
    return true;
}

void rescanforescrows(CBlockIndex *pindexRescan) {
    printf("Scanning blockchain for escrows to create fast index...\n");
    pescrowdb->ReconstructEscrowIndex(pindexRescan);
}


Value getescrowfees(const Array& params, bool fHelp) {
    if (fHelp || 0 != params.size())
        throw runtime_error(
                "getescrowfees\n"
                        "get current service fees for escrow transactions\n");
    Object oRes;
    oRes.push_back(Pair("height", nBestHeight ));
    oRes.push_back(Pair("activate_fee", ValueFromAmount(GetEscrowNetworkFee(OP_ESCROW_ACTIVATE, nBestHeight) )));
    oRes.push_back(Pair("release_fee", ValueFromAmount(GetEscrowNetworkFee(OP_ESCROW_RELEASE, nBestHeight) )));
    oRes.push_back(Pair("refund_fee", ValueFromAmount(GetEscrowNetworkFee(OP_ESCROW_REFUND, nBestHeight) )));
	oRes.push_back(Pair("complete_fee", ValueFromAmount(GetEscrowNetworkFee(OP_ESCROW_COMPLETE, nBestHeight) )));
    return oRes;

}

Value escrownew(const Array& params, bool fHelp) {
    if (fHelp || params.size() != 4 )
        throw runtime_error(
		"escrownew <offer> <quantity> <message> <arbiter alias>\n"
                        "<offer> GUID of offer that this escrow is managing.\n"
                        "<quantity> Quantity of items to buy of offer.\n"
						"<message> Delivery details to seller.\n"
						"<arbiter alias> Alias of Arbiter.\n"
                        + HelpRequiringPassphrase());
	if(!HasReachedMainNetForkB2())
		throw runtime_error("Please wait until B2 hardfork starts in before executing this command.");
	vector<unsigned char> vchOffer = vchFromValue(params[0]);
	string strArbiter = params[3].get_str();
	CBitcoinAddress arbiterAddress = CBitcoinAddress(strArbiter);
	if (!arbiterAddress.IsValid())
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
				"Invalid arbiter syscoin address");
	if (!arbiterAddress.isAlias)
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
				"Arbiter must be a valid alias");
	if(IsMine(*pwalletMain, arbiterAddress.Get()))
			throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
				"Arbiter alias must not be yours");
	// check for alias existence in DB
	vector<CAliasIndex> vtxPos;
	if (!paliasdb->ReadAlias(vchFromString(arbiterAddress.aliasName), vtxPos))
		throw JSONRPCError(RPC_WALLET_ERROR,
				"failed to read alias from alias DB");
	if (vtxPos.size() < 1)
		throw JSONRPCError(RPC_WALLET_ERROR, "no result returned");
	CAliasIndex xferAlias = vtxPos.back();
	std::vector<unsigned char> vchArbiterPubKey = xferAlias.vchPubKey;

	vector<unsigned char> vchMessage = vchFromValue(params[2]);
	unsigned int nQty = 1;
	if(atof(params[1].get_str().c_str()) < 0)
		throw runtime_error("invalid quantity value, must be greator than 0");

	try {
		nQty = boost::lexical_cast<unsigned int>(params[1].get_str());
	} catch (std::exception &e) {
		throw runtime_error("invalid quantity value. Quantity must be less than 4294967296.");
	}

    if (vchMessage.size() <= 0)
        vchMessage = vchFromString("ESCROW");
    if (vchMessage.size() > MAX_VALUE_LENGTH)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offeraccept message data cannot exceed 1023 bytes!");
	COffer theOffer;
	CTransaction txOffer;
	if (!GetTxOfOffer(*pofferdb, vchOffer, theOffer, txOffer))
		throw runtime_error("could not find an offer with this identifier");

	if (ExistsInMempool(theOffer.vchRand, OP_OFFER_REFUND) || ExistsInMempool(theOffer.vchRand, OP_OFFER_ACTIVATE) || ExistsInMempool(theOffer.vchRand, OP_OFFER_UPDATE)) {
		throw runtime_error("there are pending operations or refunds on that offer");
	}
	
    // gather inputs
    uint64 rand = GetRand((uint64) -1);
    vector<unsigned char> vchRand = CBigNum(rand).getvch();
    vector<unsigned char> vchEscrow = vchFromValue(HexStr(vchRand));

    // this is a syscoin transaction
    CWalletTx wtx;
    wtx.nVersion = SYSCOIN_TX_VERSION;

	EnsureWalletIsUnlocked();
    //create escrowactivate txn keys
    CPubKey newDefaultKey;
    pwalletMain->GetKeyFromPool(newDefaultKey, false);
    CScript scriptPubKey,scriptPubKeyOrig,scriptPubKeySeller,scriptSeller, scriptPubKeyArbiter, scriptArbiter;

	std::vector<unsigned char> vchSellerKeyByte;
    boost::algorithm::unhex(theOffer.vchPubKey.begin(), theOffer.vchPubKey.end(), std::back_inserter(vchSellerKeyByte));
	CPubKey SellerPubKey(vchSellerKeyByte);
	CBitcoinAddress selleraddy(SellerPubKey.GetID());


	std::vector<unsigned char> vchArbiterKeyByte;
    boost::algorithm::unhex(vchArbiterPubKey.begin(), vchArbiterPubKey.end(), std::back_inserter(vchArbiterKeyByte));
	CPubKey ArbiterPubKey(vchArbiterKeyByte);
	CBitcoinAddress arbaddy(ArbiterPubKey.GetID());


	// calculate network fees
	int64 nNetFee = GetEscrowNetworkFee(OP_ESCROW_ACTIVATE, nBestHeight);
	std::vector<unsigned char> vchBuyerKey(newDefaultKey.begin(), newDefaultKey.end());
	string strBuyerKey = HexStr(vchBuyerKey);

	scriptArbiter.SetDestination(ArbiterPubKey.GetID());
	scriptSeller.SetDestination(SellerPubKey.GetID());
	scriptPubKeySeller << CScript::EncodeOP_N(OP_ESCROW_ACTIVATE) << vchEscrow
			<< vchRand << OP_2DROP << OP_DROP;
	scriptPubKeySeller += scriptSeller;
	scriptPubKeyArbiter << CScript::EncodeOP_N(OP_ESCROW_ACTIVATE) << vchEscrow
			<< vchRand << OP_2DROP << OP_DROP;
	scriptPubKeyArbiter += scriptArbiter;

	Array arrayParams;
	Array arrayOfKeys;

	// standard 2 of 3 multisig
	arrayParams.push_back(2);
	arrayOfKeys.push_back(stringFromVch(vchArbiterPubKey));
	arrayOfKeys.push_back(stringFromVch(theOffer.vchPubKey));
	arrayOfKeys.push_back(strBuyerKey);
	arrayParams.push_back(arrayOfKeys);
	Value resCreate = tableRPC.execute("createmultisig", arrayParams);
	if (resCreate.type() != obj_type)
		throw runtime_error("Could not create escrow transaction: Invalid response from createescrow!");
	Object& o = resCreate.get_obj();
	string redeemScript_str = "";
	const Value& redeemScript_value = find_value(o, "redeemScript");
	if (redeemScript_value.type() == str_type)
	{
		redeemScript_str = redeemScript_value.get_str();
		vector<unsigned char> rsData(ParseHex(redeemScript_str));
		scriptPubKey = CScript(rsData.begin(), rsData.end());
	}
	// send to escrow address
	scriptPubKeyOrig.SetDestination(scriptPubKey.GetID());

	int precision = 2;
	int64 nPricePerUnit = convertCurrencyCodeToSyscoin(theOffer.sCurrencyCode, theOffer.GetPrice(), nBestHeight, precision);
	int64 nTotal = nPricePerUnit*nQty;

	int64 nEscrowFee = GetEscrowArbiterFee(nTotal);
	int64 nAmountWithEscrowFee = nTotal+nEscrowFee;

	// send to seller/arbiter so they can track the escrow through GUI
	CWalletTx escrowWtx;
	string strError = pwalletMain->SendMoney(scriptPubKeyOrig, nAmountWithEscrowFee, escrowWtx,
				false);
	if (strError != "")
	{
		throw JSONRPCError(RPC_WALLET_ERROR, strError);
	}
    vector< pair<CScript, int64> > vecSend;
	vecSend.push_back(make_pair(scriptPubKeySeller, MIN_AMOUNT));
	CScript scriptFee;
	scriptFee << OP_RETURN;
	vecSend.push_back(make_pair(scriptFee, nNetFee));
    vector< pair<CScript, int64> > vecSend1;
	vecSend1.push_back(make_pair(scriptPubKeyArbiter, MIN_AMOUNT));
	vecSend1.push_back(make_pair(scriptFee, nNetFee));
    // build escrow object
    CEscrow newEscrow;
    newEscrow.vchRand = vchEscrow;
	newEscrow.vchBuyerKey = vchFromString(strBuyerKey);
	newEscrow.seller = theOffer.aliasName;
	newEscrow.arbiter = strArbiter;
	newEscrow.vchArbiterKey = vchArbiterPubKey;
	newEscrow.vchRedeemScript = vchFromString(redeemScript_str);
	newEscrow.vchOffer = vchOffer;
	newEscrow.vchSellerKey = theOffer.vchPubKey;
	newEscrow.vchPaymentMessage = vchMessage;
	newEscrow.nQty = nQty;
	newEscrow.escrowInputTxHash = escrowWtx.GetHash();
	newEscrow.nPricePerUnit = nPricePerUnit;
    string bdata = newEscrow.SerializeToString();
	// send the tranasction
	strError = pwalletMain->SendMoney(vecSend, MIN_AMOUNT, wtx,
				false, bdata);
	if (strError != "")
	{
		throw JSONRPCError(RPC_WALLET_ERROR, strError);
	}
	strError = pwalletMain->SendMoney(vecSend1, MIN_AMOUNT, wtx,
				false, bdata);
	if (strError != "")
	{
		throw JSONRPCError(RPC_WALLET_ERROR, strError);
	}	
	vector<Value> res;
	res.push_back(wtx.GetHash().GetHex());
	res.push_back(HexStr(vchRand));
	return res;
}
Value escrowrelease(const Array& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
		"escrowrelease <escrow guid>\n"
                        "Releases escrow funds to seller, seller needs to sign the output transaction and send to the network.\n"
                        + HelpRequiringPassphrase());
	if(!HasReachedMainNetForkB2())
		throw runtime_error("Please wait until B2 hardfork starts in before executing this command.");
    // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);

     	// check for existing escrow 's
	if (ExistsInMempool(vchEscrow, OP_ESCROW_ACTIVATE) || ExistsInMempool(vchEscrow, OP_ESCROW_RELEASE) || ExistsInMempool(vchEscrow, OP_ESCROW_REFUND) || ExistsInMempool(vchEscrow, OP_ESCROW_COMPLETE)) {
		throw runtime_error("there are pending operations on that escrow");
	}

    // this is a syscoin transaction
    CWalletTx wtx;
    wtx.nVersion = SYSCOIN_TX_VERSION;

	EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	CEscrow escrow;
    if (!GetTxOfEscrow(*pescrowdb, vchEscrow, 
		escrow, tx))
        throw runtime_error("could not find a escrow with this key");

    vector<vector<unsigned char> > vvch;
    int op, nOut;
    if (!DecodeEscrowTx(tx, op, nOut, vvch, -1) 
    	|| !IsEscrowOp(op) 
    	|| (op != OP_ESCROW_ACTIVATE))
        throw runtime_error("Release can only happen on an activated escrow address");

    // unserialize escrow object from txn
    CEscrow theEscrow;
    if(!theEscrow.UnserializeFromTx(tx))
        throw runtime_error("cannot unserialize escrow from txn");
    CTransaction fundingTx;
	uint256 blockHash;
	if (!GetTransaction(escrow.escrowInputTxHash, fundingTx, blockHash, true))
		throw JSONRPCError(RPC_WALLET_ERROR, "failed to escrow transaction");

	std::vector<unsigned char> vchArbiterKeyByte;
    boost::algorithm::unhex(escrow.vchArbiterKey.begin(), escrow.vchArbiterKey.end(), std::back_inserter(vchArbiterKeyByte));
	CPubKey arbiterKey(vchArbiterKeyByte);
	CBitcoinAddress arbiterAddress(arbiterKey.GetID());
	if(!arbiterAddress.IsValid())
		throw runtime_error("Arbiter address is invalid!");

	std::vector<unsigned char> vchBuyerKeyByte;
    boost::algorithm::unhex(escrow.vchBuyerKey.begin(), escrow.vchBuyerKey.end(), std::back_inserter(vchBuyerKeyByte));
	CPubKey buyerKey(vchBuyerKeyByte);
	CBitcoinAddress buyerAddress(buyerKey.GetID());
	if(!buyerAddress.IsValid())
		throw runtime_error("Buyer address is invalid!");

	
	std::vector<unsigned char> vchSellerKeyByte;
    boost::algorithm::unhex(escrow.vchSellerKey.begin(), escrow.vchSellerKey.end(), std::back_inserter(vchSellerKeyByte));
	CPubKey sellerKey(vchSellerKeyByte);
	CBitcoinAddress sellerAddress(sellerKey.GetID());
	if(!sellerAddress.IsValid())
		throw runtime_error("Seller address is invalid!");
	int nOutMultiSig = 0;
	int64 nExpectedAmount = escrow.nPricePerUnit*escrow.nQty;
	int64 nEscrowFee = GetEscrowArbiterFee(nExpectedAmount);
	int64 nExpectedAmountWithEscrowFee = nExpectedAmount+nEscrowFee;
	for(unsigned int i=0;i<fundingTx.vout.size();i++)
	{
		if(fundingTx.vout[i].nValue == nExpectedAmountWithEscrowFee)
		{
			nOutMultiSig = i;
			break;
		}
	} 
	int64 nAmount = fundingTx.vout[nOutMultiSig].nValue;
	string strEscrowScriptPubKey = HexStr(fundingTx.vout[nOutMultiSig].scriptPubKey.begin(), fundingTx.vout[nOutMultiSig].scriptPubKey.end());
	if(nAmount != nExpectedAmountWithEscrowFee)
		throw runtime_error("Expected amount of escrow does not match what is held in escrow!");

	string strPrivateKey ;
	bool arbiterSigning = false;
	// who is initiating release arbiter or buyer?
	try
	{
		arbiterSigning = true;
		// try arbiter
		CKeyID keyID;
		if (!arbiterAddress.GetKeyID(keyID))
			throw JSONRPCError(RPC_TYPE_ERROR, "Arbiter address does not refer to a key");
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			throw JSONRPCError(RPC_WALLET_ERROR, "Private key for arbiter address " + arbiterAddress.ToString() + " is not known");
		strPrivateKey = CBitcoinSecret(vchSecret).ToString();
	}
	catch(...)
	{
		arbiterSigning = false;
		// otherwise try buyer
		CKeyID keyID;
		if (!buyerAddress.GetKeyID(keyID))
			throw JSONRPCError(RPC_TYPE_ERROR, "Buyer or Arbiter address does not refer to a key");
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			throw JSONRPCError(RPC_WALLET_ERROR, "Buyer or Arbiter private keys not known");
		strPrivateKey = CBitcoinSecret(vchSecret).ToString();
	}

	// create a raw tx that sends escrow amount to seller and collateral to buyer
    // inputs buyer txHash
	Array arrayCreateParams;
	Array createTxInputsArray;
	Object createTxInputObject;
	Object createAddressObject;
	createTxInputObject.push_back(Pair("txid", escrow.escrowInputTxHash.ToString()));
	createTxInputObject.push_back(Pair("vout", nOutMultiSig));
	createTxInputsArray.push_back(createTxInputObject);
	if(arbiterSigning)
	{
		createAddressObject.push_back(Pair(sellerAddress.ToString(), ValueFromAmount(nExpectedAmount)));
		createAddressObject.push_back(Pair(arbiterAddress.ToString(), ValueFromAmount(nEscrowFee)));
	}
	else
	{
		createAddressObject.push_back(Pair(sellerAddress.ToString(), ValueFromAmount(nExpectedAmount)));
		createAddressObject.push_back(Pair(buyerAddress.ToString(), ValueFromAmount(nEscrowFee)));
	}

	arrayCreateParams.push_back(createTxInputsArray);
	arrayCreateParams.push_back(createAddressObject);
	Value resCreate = tableRPC.execute("createrawtransaction", arrayCreateParams);
	if (resCreate.type() != str_type)
		throw runtime_error("Could not create escrow transaction: Invalid response from createrawtransaction!");
	string createEscrowSpendingTx = resCreate.get_str();

	// Buyer/Arbiter signs it
	Array arraySignParams;
	Array arraySignInputs;
	Array arrayPrivateKeys;

	Object signObject;
	signObject.push_back(Pair("txid", escrow.escrowInputTxHash.ToString()));
	signObject.push_back(Pair("vout", nOutMultiSig));
	signObject.push_back(Pair("scriptPubKey", strEscrowScriptPubKey));
	signObject.push_back(Pair("redeemScript", stringFromVch(escrow.vchRedeemScript)));
	arraySignParams.push_back(createEscrowSpendingTx);
	arraySignInputs.push_back(signObject);
	arraySignParams.push_back(arraySignInputs);
	arrayPrivateKeys.push_back(strPrivateKey);
	arraySignParams.push_back(arrayPrivateKeys);
	Value res = tableRPC.execute("signrawtransaction", arraySignParams);
	if (res.type() != obj_type)
		throw runtime_error("Could not sign escrow transaction: Invalid response from signrawtransaction!");
	
	Object& o = res.get_obj();
	string hex_str = "";

	const Value& hex_value = find_value(o, "hex");
	if (hex_value.type() == str_type)
		hex_str = hex_value.get_str();
	const Value& complete_value = find_value(o, "complete");
	bool bComplete = false;
	if (complete_value.type() == bool_type)
		bComplete = complete_value.get_bool();

	if(bComplete)
		throw runtime_error("This is not a multisignature escrow!");

	escrow.rawTx = vchFromString(hex_str);
	string bdata = escrow.SerializeToString();
	CScript scriptFee;
	scriptFee << OP_RETURN;

    CScript scriptPubKey, scriptPubKeySeller;
	scriptPubKeySeller.SetDestination(sellerKey.GetID());
    scriptPubKey << CScript::EncodeOP_N(OP_ESCROW_RELEASE) << vchEscrow << escrow.vchOffer << OP_2DROP << OP_DROP;
    scriptPubKey += scriptPubKeySeller;

	vector< pair<CScript, int64> > vecSend;
	vecSend.push_back(make_pair(scriptPubKey, MIN_AMOUNT));

	int64 nNetFee = GetEscrowNetworkFee(OP_ESCROW_RELEASE, nBestHeight);
	vecSend.push_back(make_pair(scriptFee, nNetFee));

	// send the tranasction
	string strError = pwalletMain->SendMoney(vecSend, MIN_AMOUNT, wtx,
				false, bdata);
	if (strError != "")
	{
		throw JSONRPCError(RPC_WALLET_ERROR, strError);
	}
	return wtx.GetHash().GetHex();
}
Value escrowclaimrelease(const Array& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
		"escrowclaimrelease <escrow guid>\n"
                        "Claim escrow funds released from buyer or arbiter using escrowrelease.\n"
                        + HelpRequiringPassphrase());
	if(!HasReachedMainNetForkB2())
		throw runtime_error("Please wait until B2 hardfork starts in before executing this command.");
    // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);

      	// check for existing escrow 's
	if (ExistsInMempool(vchEscrow, OP_ESCROW_ACTIVATE) || ExistsInMempool(vchEscrow, OP_ESCROW_RELEASE) || ExistsInMempool(vchEscrow, OP_ESCROW_REFUND) || ExistsInMempool(vchEscrow, OP_ESCROW_COMPLETE)) {
		throw runtime_error("there are pending operations on that escrow");
	}

	EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	CEscrow escrow;
    if (!GetTxOfEscrow(*pescrowdb, vchEscrow, 
		escrow, tx))
        throw runtime_error("could not find a escrow with this key");
  
	CTransaction fundingTx;
	uint256 blockHash;
	if (!GetTransaction(escrow.escrowInputTxHash, fundingTx, blockHash, true))
		throw JSONRPCError(RPC_WALLET_ERROR, "failed to read escrow transaction");

 	int nOutMultiSig = 0;
	int64 nExpectedAmount = escrow.nPricePerUnit*escrow.nQty;
	int64 nEscrowFee = GetEscrowArbiterFee(nExpectedAmount);
	int64 nExpectedAmountWithEscrowFee = nExpectedAmount+nEscrowFee;
	for(unsigned int i=0;i<fundingTx.vout.size();i++)
	{
		if(fundingTx.vout[i].nValue == nExpectedAmountWithEscrowFee)
		{
			nOutMultiSig = i;
			break;
		}
	} 
	int64 nAmount = fundingTx.vout[nOutMultiSig].nValue;
	string strEscrowScriptPubKey = HexStr(fundingTx.vout[nOutMultiSig].scriptPubKey.begin(), fundingTx.vout[nOutMultiSig].scriptPubKey.end());
	if(nAmount != nExpectedAmountWithEscrowFee)
		throw runtime_error("Expected amount of escrow does not match what is held in escrow!");

	// decode rawTx and check it pays enough and it pays to buyer/seller appropriately
	// check that right amount is going to be sent to seller
	bool foundSellerPayment = false;
	Array arrayDecodeParams;
	arrayDecodeParams.push_back(stringFromVch(escrow.rawTx));
	Value decodeRes = tableRPC.execute("decoderawtransaction", arrayDecodeParams);
	if (decodeRes.type() != obj_type)
		throw runtime_error("Could not decode escrow transaction: Invalid response from decoderawtransaction!");
	Object& decodeo = decodeRes.get_obj();
	const Value& vout_value = find_value(decodeo, "vout");
	if (vout_value.type() != array_type)
		throw runtime_error("Could not decode escrow transaction: Can't find vout's from transaction!");	
	Array vouts = vout_value.get_array();
	BOOST_FOREACH(Value& vout, vouts)
	{					
		Object voutObj = vout.get_obj();					
		Value voutValue = find_value(voutObj, "value");
		if(voutValue.type() != real_type)
			throw runtime_error("Could not decode escrow transaction: Invalid vout value!");
		int64 iVout = AmountFromValue(voutValue);
		Value scriptPubKeyValue = find_value(voutObj, "scriptPubKey");
		if(scriptPubKeyValue.type() != obj_type)
			throw runtime_error("Could not decode escrow transaction: Invalid scriptPubKey object!");
		Object scriptPubKeyValueObj = scriptPubKeyValue.get_obj();	
		Value addressesValue = find_value(scriptPubKeyValueObj, "addresses");
		if(addressesValue.type() != array_type)
			throw runtime_error("Could not decode escrow transaction: Invalid addresses object!");

		Array addresses = addressesValue.get_array();
		BOOST_FOREACH(Value& address, addresses)
		{
			if(address.type() != str_type)
				throw runtime_error("Could not decode escrow transaction: Invalid address object!");
			string strAddress = address.get_str();
			CBitcoinAddress payoutAddress(strAddress);
			if(IsMine(*pwalletMain, payoutAddress.Get()))
			{
				if(!foundSellerPayment)
				{
					if(iVout == nExpectedAmount)
					{
						foundSellerPayment = true;
						break;
					}
				}
			}
		}
	}


	CKeyID keyID;
	std::vector<unsigned char> vchSellerKeyByte;
    boost::algorithm::unhex(escrow.vchSellerKey.begin(), escrow.vchSellerKey.end(), std::back_inserter(vchSellerKeyByte));
	CPubKey sellerKey(vchSellerKeyByte);
	CBitcoinAddress sellerAddress(sellerKey.GetID());
	if(!sellerAddress.IsValid())
		throw runtime_error("Seller address is invalid!");

	if (!sellerAddress.GetKeyID(keyID))
		throw JSONRPCError(RPC_TYPE_ERROR, "Seller address does not refer to a key");
	CKey vchSecret;
	if (!pwalletMain->GetKey(keyID, vchSecret))
		throw JSONRPCError(RPC_WALLET_ERROR, "Private key for seller address " + sellerAddress.ToString() + " is not known");
	string strPrivateKey = CBitcoinSecret(vchSecret).ToString();
	if(!foundSellerPayment)
		throw runtime_error("Expected payment amount from escrow does not match what was expected by the seller!");	

    // Seller signs it
	Array arraySignParams;
	Array arraySignInputs;
	Array arrayPrivateKeys;
	Object signObject;
	signObject.push_back(Pair("txid", escrow.escrowInputTxHash.ToString()));
	signObject.push_back(Pair("vout", nOutMultiSig));
	signObject.push_back(Pair("scriptPubKey", strEscrowScriptPubKey));
	signObject.push_back(Pair("redeemScript", stringFromVch(escrow.vchRedeemScript)));
	arraySignParams.push_back(stringFromVch(escrow.rawTx));
	arraySignInputs.push_back(signObject);
	arraySignParams.push_back(arraySignInputs);
	arrayPrivateKeys.push_back(strPrivateKey);
	arraySignParams.push_back(arrayPrivateKeys);
	Value res = tableRPC.execute("signrawtransaction", arraySignParams);
	if (res.type() != obj_type)
		throw runtime_error("Could not sign escrow transaction: Invalid response from signrawtransaction!");
	
	Object& o = res.get_obj();
	string hex_str = "";

	const Value& hex_value = find_value(o, "hex");
	if (hex_value.type() == str_type)
		hex_str = hex_value.get_str();

	const Value& complete_value = find_value(o, "complete");
	bool bComplete = false;
	if (complete_value.type() == bool_type)
		bComplete = complete_value.get_bool();

	if(!bComplete)
		throw runtime_error("Could not sign escrow transaction. It is showing as incomplete, you may not allowed to complete this request at this time.");

	// broadcast the payment transaction
	Array arraySendParams;
	arraySendParams.push_back(hex_str);
	res = tableRPC.execute("sendrawtransaction", arraySendParams);
	if (res.type() != str_type)
		throw runtime_error("Could not send escrow transaction: Invalid response from sendrawtransaction!");


	Array arrayAcceptParams;
	arrayAcceptParams.push_back(stringFromVch(vchEscrow));
	res = tableRPC.execute("escrowcomplete", arrayAcceptParams);
	if (res.type() != str_type)
		throw runtime_error("Could not complete escrow: Invalid response from escrowofferaccept!");

	return res.get_str();

	
	
}
Value escrowcomplete(const Array& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
		"escrowcomplete <escrow guid>\n"
                         "Accepts an offer that's in escrow, to complete the escrow process.\n"
                        + HelpRequiringPassphrase());
	if(!HasReachedMainNetForkB2())
		throw runtime_error("Please wait until B2 hardfork starts in before executing this command.");
    // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);

      	// check for existing escrow 's
	if (ExistsInMempool(vchEscrow, OP_ESCROW_ACTIVATE) || ExistsInMempool(vchEscrow, OP_ESCROW_RELEASE) || ExistsInMempool(vchEscrow, OP_ESCROW_REFUND) || ExistsInMempool(vchEscrow, OP_ESCROW_COMPLETE)) {
		throw runtime_error("there are pending operations on that escrow");
	}

	EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	CWalletTx wtx;
    wtx.nVersion = SYSCOIN_TX_VERSION;

	CEscrow escrow;
    if (!GetTxOfEscrow(*pescrowdb, vchEscrow, 
		escrow, tx))
        throw runtime_error("could not find a escrow with this key");
	uint256 hash, blockHash;
	
	bool foundEscrowRelease = false;
	
	BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet) {
		// get txn hash, read txn index
		vector<vector<unsigned char> > vvch;
		int op, nOut;
		hash = item.second.GetHash();
		if (!GetTransaction(hash, tx, blockHash, true))
			continue;
		// skip non-syscoin txns
		if (tx.nVersion != SYSCOIN_TX_VERSION)
			continue;
		
		if (!DecodeEscrowTx(tx, op, nOut, vvch, -1) 
    		|| !IsEscrowOp(op) 
			|| vvch[0] != escrow.vchRand
    		|| op != OP_ESCROW_RELEASE)
			continue;
		foundEscrowRelease = true;
		break;
	}

    if (!foundEscrowRelease)
        throw runtime_error("Can only complete an escrow that has been released to you and is not complete already");


	std::vector<unsigned char> vchBuyerKeyByte;
    boost::algorithm::unhex(escrow.vchBuyerKey.begin(), escrow.vchBuyerKey.end(), std::back_inserter(vchBuyerKeyByte));
	CPubKey buyerKey(vchBuyerKeyByte);
	CBitcoinAddress buyerAddress(buyerKey.GetID());
	if(!buyerAddress.IsValid())
		throw runtime_error("Buyer address is invalid!");

	Array acceptParams;
	acceptParams.push_back(stringFromVch(escrow.vchOffer));
	acceptParams.push_back(static_cast<ostringstream*>( &(ostringstream() << escrow.nQty) )->str());
	acceptParams.push_back(stringFromVch(escrow.vchBuyerKey));
	acceptParams.push_back(stringFromVch(escrow.vchPaymentMessage));
	acceptParams.push_back(buyerAddress.ToString());
	acceptParams.push_back("");
	acceptParams.push_back(tx.GetHash().GetHex());

	Value res = tableRPC.execute("offeraccept", acceptParams);
	if (res.type() != array_type)
		throw runtime_error("Could not complete escrow transaction: Invalid response from offeraccept!");

	Array arr = res.get_array();
	string acceptTxHashStr = arr[0].get_str();
	uint256 acceptTxHash(acceptTxHashStr);
	string acceptGUID = arr[1].get_str();
	CWalletTx wtxAcceptIn;
	if (!pwalletMain->GetTransaction(acceptTxHash, wtxAcceptIn)) 
		throw runtime_error("offer accept is not in your wallet");


	escrow.vchOfferAcceptLink = vchFromString(acceptGUID);
  	CPubKey newDefaultKey;
	pwalletMain->GetKeyFromPool(newDefaultKey, false); 
	std::vector<unsigned char> vchPubKey(newDefaultKey.begin(), newDefaultKey.end());
	escrow.rawTx.clear();
	string bdata = escrow.SerializeToString();

    CScript scriptPubKey,scriptPubKeyOrig;
	scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());
    scriptPubKey << CScript::EncodeOP_N(OP_ESCROW_COMPLETE) << vchEscrow << escrow.vchOffer << OP_2DROP << OP_DROP;
    scriptPubKey += scriptPubKeyOrig;

	vector< pair<CScript, int64> > vecSend;
	vecSend.push_back(make_pair(scriptPubKey, MIN_AMOUNT));

	int64 nNetFee = GetEscrowNetworkFee(OP_ESCROW_COMPLETE, nBestHeight);
	CScript scriptFee;
	scriptFee << OP_RETURN;
	vecSend.push_back(make_pair(scriptFee, nNetFee));

	// send the tranasction
	string strError = pwalletMain->SendMoney(vecSend, MIN_AMOUNT, wtx,
				false, bdata);

	if (strError != "")
	{
		throw JSONRPCError(RPC_WALLET_ERROR, strError);
	}
	return wtx.GetHash().GetHex();
}
Value escrowrefund(const Array& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
		"escrowrefund <escrow guid>\n"
                         "Refunds escrow funds back to buyer, buyer needs to sign the output transaction and send to the network.\n"
                        + HelpRequiringPassphrase());
	if(!HasReachedMainNetForkB2())
		throw runtime_error("Please wait until B2 hardfork starts in before executing this command.");
    // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);

     	// check for existing escrow 's
	if (ExistsInMempool(vchEscrow, OP_ESCROW_ACTIVATE) || ExistsInMempool(vchEscrow, OP_ESCROW_RELEASE) || ExistsInMempool(vchEscrow, OP_ESCROW_REFUND) || ExistsInMempool(vchEscrow, OP_ESCROW_COMPLETE)) {
		throw runtime_error("there are pending operations on that escrow");
	}

    // this is a syscoin transaction
    CWalletTx wtx;
    wtx.nVersion = SYSCOIN_TX_VERSION;

	EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	CEscrow escrow;
    if (!GetTxOfEscrow(*pescrowdb, vchEscrow, 
		escrow, tx))
        throw runtime_error("could not find a escrow with this key");

    vector<vector<unsigned char> > vvch;
    int op, nOut;
    if (!DecodeEscrowTx(tx, op, nOut, vvch, -1) 
    	|| !IsEscrowOp(op) 
    	|| (op != OP_ESCROW_ACTIVATE))
        throw runtime_error("Refund can only happen on an activated escrow address");

    // unserialize escrow object from txn
    CEscrow theEscrow;
    if(!theEscrow.UnserializeFromTx(tx))
        throw runtime_error("cannot unserialize escrow from txn");
    CTransaction fundingTx;
	uint256 blockHash;
	if (!GetTransaction(escrow.escrowInputTxHash, fundingTx, blockHash, true))
		throw JSONRPCError(RPC_WALLET_ERROR, "failed to escrow transaction");

	std::vector<unsigned char> vchArbiterKeyByte;
    boost::algorithm::unhex(escrow.vchArbiterKey.begin(), escrow.vchArbiterKey.end(), std::back_inserter(vchArbiterKeyByte));
	CPubKey arbiterKey(vchArbiterKeyByte);
	CBitcoinAddress arbiterAddress(arbiterKey.GetID());
	if(!arbiterAddress.IsValid())
		throw runtime_error("Arbiter address is invalid!");

	std::vector<unsigned char> vchBuyerKeyByte;
    boost::algorithm::unhex(escrow.vchBuyerKey.begin(), escrow.vchBuyerKey.end(), std::back_inserter(vchBuyerKeyByte));
	CPubKey buyerKey(vchBuyerKeyByte);
	CBitcoinAddress buyerAddress(buyerKey.GetID());
	if(!buyerAddress.IsValid())
		throw runtime_error("Buyer address is invalid!");

	
	std::vector<unsigned char> vchSellerKeyByte;
    boost::algorithm::unhex(escrow.vchSellerKey.begin(), escrow.vchSellerKey.end(), std::back_inserter(vchSellerKeyByte));
	CPubKey sellerKey(vchSellerKeyByte);
	CBitcoinAddress sellerAddress(sellerKey.GetID());
	if(!sellerAddress.IsValid())
		throw runtime_error("Seller address is invalid!");
	int nOutMultiSig = 0;
	int64 nExpectedAmount = escrow.nPricePerUnit*escrow.nQty;
	int64 nEscrowFee = GetEscrowArbiterFee(nExpectedAmount);
	int64 nExpectedAmountWithEscrowFee = nExpectedAmount+nEscrowFee;
	for(unsigned int i=0;i<fundingTx.vout.size();i++)
	{
		if(fundingTx.vout[i].nValue == nExpectedAmountWithEscrowFee)
		{
			nOutMultiSig = i;
			break;
		}
	} 
	int64 nAmount = fundingTx.vout[nOutMultiSig].nValue;
	string strEscrowScriptPubKey = HexStr(fundingTx.vout[nOutMultiSig].scriptPubKey.begin(), fundingTx.vout[nOutMultiSig].scriptPubKey.end());
	if(nAmount != nExpectedAmountWithEscrowFee)
		throw runtime_error("Expected amount of escrow does not match what is held in escrow!");
	string strPrivateKey ;
	bool arbiterSigning = false;
	// who is initiating release arbiter or seller?
	try
	{
		arbiterSigning = true;
		// try arbiter
		CKeyID keyID;
		if (!arbiterAddress.GetKeyID(keyID))
			throw JSONRPCError(RPC_TYPE_ERROR, "Arbiter address does not refer to a key");
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			throw JSONRPCError(RPC_WALLET_ERROR, "Private key for arbiter address " + arbiterAddress.ToString() + " is not known");
		strPrivateKey = CBitcoinSecret(vchSecret).ToString();
	}
	catch(...)
	{
		arbiterSigning = false;
		// otherwise try seller
		CKeyID keyID;
		if (!sellerAddress.GetKeyID(keyID))
			throw JSONRPCError(RPC_TYPE_ERROR, "Seller or Arbiter address does not refer to a key");
		CKey vchSecret;
		if (!pwalletMain->GetKey(keyID, vchSecret))
			throw JSONRPCError(RPC_WALLET_ERROR, "Seller or Arbiter private keys not known");
		strPrivateKey = CBitcoinSecret(vchSecret).ToString();
	}
	// refunds buyer from escrow
	Array arrayCreateParams;
	Array createTxInputsArray;
	Object createTxInputObject;
	Object createAddressObject;
	createTxInputObject.push_back(Pair("txid", escrow.escrowInputTxHash.ToString()));
	createTxInputObject.push_back(Pair("vout", nOutMultiSig));
	createTxInputsArray.push_back(createTxInputObject);
	if(arbiterSigning)
	{
		createAddressObject.push_back(Pair(buyerAddress.ToString(), ValueFromAmount(nExpectedAmount)));
		createAddressObject.push_back(Pair(arbiterAddress.ToString(), ValueFromAmount(nEscrowFee)));
	}
	else
	{
		createAddressObject.push_back(Pair(buyerAddress.ToString(), ValueFromAmount(nExpectedAmountWithEscrowFee)));
	}	
	arrayCreateParams.push_back(createTxInputsArray);
	arrayCreateParams.push_back(createAddressObject);
	Value resCreate = tableRPC.execute("createrawtransaction", arrayCreateParams);
	if (resCreate.type() != str_type)
		throw runtime_error("Could not create escrow transaction: Invalid response from createrawtransaction!");
	string createEscrowSpendingTx = resCreate.get_str();

	// Buyer/Arbiter signs it
	Array arraySignParams;
	Array arraySignInputs;
	Array arrayPrivateKeys;

	Object signObject;
	signObject.push_back(Pair("txid", escrow.escrowInputTxHash.ToString()));
	signObject.push_back(Pair("vout", nOutMultiSig));
	signObject.push_back(Pair("scriptPubKey", strEscrowScriptPubKey));
	signObject.push_back(Pair("redeemScript", stringFromVch(escrow.vchRedeemScript)));
	arraySignParams.push_back(createEscrowSpendingTx);
	arraySignInputs.push_back(signObject);
	arraySignParams.push_back(arraySignInputs);
	arrayPrivateKeys.push_back(strPrivateKey);
	arraySignParams.push_back(arrayPrivateKeys);
	Value res = tableRPC.execute("signrawtransaction", arraySignParams);
	if (res.type() != obj_type)
		throw runtime_error("Could not sign escrow transaction: Invalid response from signrawtransaction!");
	
	Object& o = res.get_obj();
	string hex_str = "";

	const Value& hex_value = find_value(o, "hex");
	if (hex_value.type() == str_type)
		hex_str = hex_value.get_str();
	const Value& complete_value = find_value(o, "complete");
	bool bComplete = false;
	if (complete_value.type() == bool_type)
		bComplete = complete_value.get_bool();

	if(bComplete)
		throw runtime_error("This is not a multisignature escrow!");



	escrow.rawTx = vchFromString(hex_str);
	string bdata = escrow.SerializeToString();
	CScript scriptFee;
	scriptFee << OP_RETURN;

    CScript scriptPubKey, scriptPubKeyBuyer;
	scriptPubKeyBuyer.SetDestination(buyerKey.GetID());
    scriptPubKey << CScript::EncodeOP_N(OP_ESCROW_REFUND) << vchEscrow << escrow.vchOffer << OP_2DROP << OP_DROP;
    scriptPubKey += scriptPubKeyBuyer;

	vector< pair<CScript, int64> > vecSend;
	vecSend.push_back(make_pair(scriptPubKey, MIN_AMOUNT));

	int64 nNetFee = GetEscrowNetworkFee(OP_ESCROW_REFUND, nBestHeight);
	vecSend.push_back(make_pair(scriptFee, nNetFee));

	// send the tranasction
	string strError = pwalletMain->SendMoney(vecSend, MIN_AMOUNT, wtx,
				false, bdata);
	if (strError != "")
	{
		throw JSONRPCError(RPC_WALLET_ERROR, strError);
	}
	return wtx.GetHash().GetHex();
}
Value escrowclaimrefund(const Array& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
		"escrowclaimrefund <escrow guid>\n"
                        "Claim escrow funds released from seller or arbiter using escrowrefund.\n"
                        + HelpRequiringPassphrase());
	if(!HasReachedMainNetForkB2())
		throw runtime_error("Please wait until B2 hardfork starts in before executing this command.");
    // gather & validate inputs
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);

      	// check for existing escrow 's
	if (ExistsInMempool(vchEscrow, OP_ESCROW_ACTIVATE) || ExistsInMempool(vchEscrow, OP_ESCROW_RELEASE) || ExistsInMempool(vchEscrow, OP_ESCROW_REFUND) || ExistsInMempool(vchEscrow, OP_ESCROW_COMPLETE) ) {
		throw runtime_error("there are pending operations on that escrow");
	}

	EnsureWalletIsUnlocked();

    // look for a transaction with this key
    CTransaction tx;
	CEscrow escrow;
    if (!GetTxOfEscrow(*pescrowdb, vchEscrow, 
		escrow, tx))
        throw runtime_error("could not find a escrow with this key");

	CTransaction fundingTx;
	uint256 blockHash;
	if (!GetTransaction(escrow.escrowInputTxHash, fundingTx, blockHash, true))
		throw JSONRPCError(RPC_WALLET_ERROR, "failed to read escrow transaction");

 	int nOutMultiSig = 0;
	int64 nExpectedAmount = escrow.nPricePerUnit*escrow.nQty;
	// 0.5% escrow fee
	int64 nEscrowFee = GetEscrowArbiterFee(nExpectedAmount);
	int64 nExpectedAmountWithEscrowFee = nExpectedAmount+nEscrowFee;
	for(unsigned int i=0;i<fundingTx.vout.size();i++)
	{
		if(fundingTx.vout[i].nValue == nExpectedAmountWithEscrowFee)
		{
			nOutMultiSig = i;
			break;
		}
	} 
	int64 nAmount = fundingTx.vout[nOutMultiSig].nValue;
	string strEscrowScriptPubKey = HexStr(fundingTx.vout[nOutMultiSig].scriptPubKey.begin(), fundingTx.vout[nOutMultiSig].scriptPubKey.end());
	if(nAmount != nExpectedAmountWithEscrowFee)
		throw runtime_error("Expected amount of escrow does not match what is held in escrow!");
	// decode rawTx and check it pays enough and it pays to buyer appropriately
	// check that right amount is going to be sent to buyer
	bool foundBuyerPayment = false;
	Array arrayDecodeParams;

	arrayDecodeParams.push_back(stringFromVch(escrow.rawTx));
	Value decodeRes = tableRPC.execute("decoderawtransaction", arrayDecodeParams);
	if (decodeRes.type() != obj_type)
		throw runtime_error("Could not decode escrow transaction: Invalid response from decoderawtransaction!");
	Object& decodeo = decodeRes.get_obj();
	const Value& vout_value = find_value(decodeo, "vout");
	if (vout_value.type() != array_type)
		throw runtime_error("Could not decode escrow transaction: Can't find vout's from transaction!");	
	Array vouts = vout_value.get_array();
	BOOST_FOREACH(Value& vout, vouts)
	{					
		Object voutObj = vout.get_obj();					
		Value voutValue = find_value(voutObj, "value");
		if(voutValue.type() != real_type)
			throw runtime_error("Could not decode escrow transaction: Invalid vout value!");
		int64 iVout = AmountFromValue(voutValue);
		Value scriptPubKeyValue = find_value(voutObj, "scriptPubKey");
		if(scriptPubKeyValue.type() != obj_type)
			throw runtime_error("Could not decode escrow transaction: Invalid scriptPubKey object!");
		Object scriptPubKeyValueObj = scriptPubKeyValue.get_obj();	
		Value addressesValue = find_value(scriptPubKeyValueObj, "addresses");
		if(addressesValue.type() != array_type)
			throw runtime_error("Could not decode escrow transaction: Invalid addresses object!");

		Array addresses = addressesValue.get_array();
		BOOST_FOREACH(Value& address, addresses)
		{
			if(address.type() != str_type)
				throw runtime_error("Could not decode escrow transaction: Invalid address object!");
			string strAddress = address.get_str();
			CBitcoinAddress payoutAddress(strAddress);
			if(IsMine(*pwalletMain, payoutAddress.Get()))
			{
				if(!foundBuyerPayment)
				{
					if(iVout == nExpectedAmountWithEscrowFee || iVout == nExpectedAmount)
					{
						foundBuyerPayment = true;
						break;
					}
				}
			}
		}
	}

	// get buyer's private key for signing
	CKeyID keyID;
	std::vector<unsigned char> vchBuyerKeyByte;
    boost::algorithm::unhex(escrow.vchBuyerKey.begin(), escrow.vchBuyerKey.end(), std::back_inserter(vchBuyerKeyByte));
	CPubKey buyerKey(vchBuyerKeyByte);
	CBitcoinAddress buyerAddress(buyerKey.GetID());
	if(!buyerAddress.IsValid())
		throw runtime_error("Buyer address is invalid!");

	if (!buyerAddress.GetKeyID(keyID))
		throw JSONRPCError(RPC_TYPE_ERROR, "Buyer address does not refer to a key");
	CKey vchSecret;
	if (!pwalletMain->GetKey(keyID, vchSecret))
		throw JSONRPCError(RPC_WALLET_ERROR, "Private key for buyer address " + buyerAddress.ToString() + " is not known");
	string strPrivateKey = CBitcoinSecret(vchSecret).ToString();
	if(!foundBuyerPayment)
		throw runtime_error("Expected payment amount from escrow does not match what was expected by the buyer!");

    // Seller signs it
	Array arraySignParams;
	Array arraySignInputs;
	Array arrayPrivateKeys;
	Object signObject;
	signObject.push_back(Pair("txid", escrow.escrowInputTxHash.ToString()));
	signObject.push_back(Pair("vout", nOutMultiSig));
	signObject.push_back(Pair("scriptPubKey", strEscrowScriptPubKey));
	signObject.push_back(Pair("redeemScript", stringFromVch(escrow.vchRedeemScript)));
	arraySignParams.push_back(stringFromVch(escrow.rawTx));
	arraySignInputs.push_back(signObject);
	arraySignParams.push_back(arraySignInputs);
	arrayPrivateKeys.push_back(strPrivateKey);
	arraySignParams.push_back(arrayPrivateKeys);
	Value res = tableRPC.execute("signrawtransaction", arraySignParams);
	if (res.type() != obj_type)
		throw runtime_error("Could not sign escrow transaction: Invalid response from signrawtransaction!");
	
	Object& o = res.get_obj();
	string hex_str = "";

	const Value& hex_value = find_value(o, "hex");
	if (hex_value.type() == str_type)
		hex_str = hex_value.get_str();
	printf("after signing final %s\n", hex_str.c_str());
	const Value& complete_value = find_value(o, "complete");
	bool bComplete = false;
	if (complete_value.type() == bool_type)
		bComplete = complete_value.get_bool();

	if(!bComplete)
		throw runtime_error("Could not sign escrow transaction. It is showing as incomplete, you may not allowed to complete this request at this time.");

	// broadcast the payment transaction
	Array arraySendParams;
	arraySendParams.push_back(hex_str);
    return tableRPC.execute("sendrawtransaction", arraySendParams);
}

Value escrowinfo(const Array& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("escrowinfo <guid>\n"
                "Show stored values of a single escrow and its .\n");

    vector<unsigned char> vchEscrow = vchFromValue(params[0]);

    // look for a transaction with this key, also returns
    // an escrow object if it is found
    CTransaction tx;

	vector<CEscrow> vtxPos;

	int expired = 0;
	int expires_in = 0;
	int expired_block = 0;
    Object oEscrow;
    vector<unsigned char> vchValue;

	if (!pescrowdb->ReadEscrow(vchEscrow, vtxPos) || vtxPos.empty())
		  throw JSONRPCError(RPC_WALLET_ERROR, "failed to read from escrow DB");
	CEscrow ca = vtxPos.back();
	
	
    string sHeight = strprintf("%llu", ca.nHeight);
    oEscrow.push_back(Pair("escrow", stringFromVch(vchEscrow)));
	string sTime;
	CBlockIndex *pindex = FindBlockByHeight(ca.nHeight);
	if (pindex) {
		sTime = strprintf("%llu", pindex->nTime);
	}
	oEscrow.push_back(Pair("time", sTime));
	oEscrow.push_back(Pair("seller", ca.seller));
	oEscrow.push_back(Pair("arbiter", ca.arbiter));
	oEscrow.push_back(Pair("buyerkey", stringFromVch(ca.vchBuyerKey)));
	oEscrow.push_back(Pair("offer", stringFromVch(ca.vchOffer)));
	oEscrow.push_back(Pair("offeracceptlink", stringFromVch(ca.vchOfferAcceptLink)));

	string sTotal = strprintf("%llu SYS", (ca.nPricePerUnit/COIN)*ca.nQty);
	oEscrow.push_back(Pair("total", sTotal));
    oEscrow.push_back(Pair("txid", ca.txHash.GetHex()));
    oEscrow.push_back(Pair("height", sHeight));
	
    return oEscrow;
}

Value escrowlist(const Array& params, bool fHelp) {
    if (fHelp || 1 < params.size())
        throw runtime_error("escrowlist [<escrow>]\n"
                "list my own escrows");
	vector<unsigned char> vchName;

	if (params.size() == 1)
		vchName = vchFromValue(params[0]);
    vector<unsigned char> vchNameUniq;
    if (params.size() == 1)
        vchNameUniq = vchFromValue(params[0]);

    Array oRes;
    map< vector<unsigned char>, int > vNamesI;
    map< vector<unsigned char>, Object > vNamesO;

    uint256 blockHash;
    uint256 hash;
    CTransaction tx, dbtx;

    vector<unsigned char> vchValue;
    int nHeight;

    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet)
    {
		int expired = 0;
        // get txn hash, read txn index
        hash = item.second.GetHash();
		if (!GetTransaction(hash, tx, blockHash, true))
			continue;
        // skip non-syscoin txns
        if (tx.nVersion != SYSCOIN_TX_VERSION)
            continue;
		// decode txn, skip non-alias txns
		// get the txn height
		nHeight = GetTxHashHeight(hash);

		// get the txn escrow name
		if (!GetNameOfEscrowTx(tx, vchName))
			continue;
		vector<CEscrow> vtxPos;
		if (!pescrowdb->ReadEscrow(vchName, vtxPos) || vtxPos.empty())
			continue;
		CEscrow escrow = vtxPos.back();
		// skip this escrow if it doesn't match the given filter value
		if (vchNameUniq.size() > 0 && vchNameUniq != vchName)
			continue;
		// get last active name only
		if (vNamesI.find(vchName) != vNamesI.end() && (escrow.nHeight < vNamesI[vchName] || vNamesI[vchName] < 0))
			continue;

		if (!GetTransaction(escrow.txHash, tx, blockHash, true))
			continue;
		vector<vector<unsigned char> > vvch;
		int op, nOut;
		if (!DecodeEscrowTx(tx, op, nOut, vvch, -1) || !IsEscrowOp(op))
			continue;

        // build the output object
        Object oName;
        oName.push_back(Pair("escrow", stringFromVch(vchName)));
		string sTime;
		CBlockIndex *pindex = FindBlockByHeight(escrow.nHeight);
		if (pindex) {
			sTime = strprintf("%llu", pindex->nTime);
		}
		oName.push_back(Pair("time", sTime));
		oName.push_back(Pair("seller", escrow.seller));
		oName.push_back(Pair("arbiter", escrow.arbiter));
		oName.push_back(Pair("buyerkey", stringFromVch(escrow.vchBuyerKey)));
		oName.push_back(Pair("offer", stringFromVch(escrow.vchOffer)));
		oName.push_back(Pair("offeraccept", stringFromVch(escrow.vchOfferAcceptLink)));

		string sTotal = strprintf("%llu SYS", (escrow.nPricePerUnit/COIN)*escrow.nQty);
		oName.push_back(Pair("total", sTotal));
		if(nHeight + GetEscrowDisplayExpirationDepth() - pindexBest->nHeight <= 0)
		{
			expired = 1;
		}  
		string status = "unknown";
		if(op == OP_ESCROW_ACTIVATE)
			status = "inescrow";
		else if(op == OP_ESCROW_RELEASE)
			status = "escrowreleased";
		else if(op == OP_ESCROW_REFUND)
			status = "escrowrefunded";
		else if(op == OP_ESCROW_COMPLETE)
			status = "complete";
		oName.push_back(Pair("status", status));

		oName.push_back(Pair("expired", expired));
 
		vNamesI[vchName] = nHeight;
		vNamesO[vchName] = oName;	
    
	}
    BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, Object)& item, vNamesO)
        oRes.push_back(item.second);
    return oRes;
}


Value escrowhistory(const Array& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("escrowhistory <escrow>\n"
                "List all stored values of an escrow.\n");

    Array oRes;
    vector<unsigned char> vchEscrow = vchFromValue(params[0]);
    string escrow = stringFromVch(vchEscrow);

    {
        vector<CEscrow> vtxPos;
        if (!pescrowdb->ReadEscrow(vchEscrow, vtxPos) || vtxPos.empty())
            throw JSONRPCError(RPC_WALLET_ERROR,
                    "failed to read from escrow DB");

        CEscrow txPos2;
        uint256 txHash;
        uint256 blockHash;
        BOOST_FOREACH(txPos2, vtxPos) {
            txHash = txPos2.txHash;
			CTransaction tx;
			if (!GetTransaction(txHash, tx, blockHash, true)) {
				error("could not read txpos");
				continue;
			}
			int expired = 0;
            Object oEscrow;
            int nHeight;
            uint256 hash;
           
			oEscrow.push_back(Pair("escrow", escrow));
			string sTime;
			CBlockIndex *pindex = FindBlockByHeight(txPos2.nHeight);
			if (pindex) {
				sTime = strprintf("%llu", pindex->nTime);
			}
			oEscrow.push_back(Pair("time", sTime));
			oEscrow.push_back(Pair("txid", tx.GetHash().GetHex()));
			oEscrow.push_back(Pair("seller", txPos2.seller));
			oEscrow.push_back(Pair("arbiter", txPos2.arbiter));
			oEscrow.push_back(Pair("buyerkey", stringFromVch(txPos2.vchBuyerKey)));
			oEscrow.push_back(Pair("offer", stringFromVch(txPos2.vchOffer)));
			oEscrow.push_back(Pair("offeracceptlink", stringFromVch(txPos2.vchOfferAcceptLink)));

			string sTotal = strprintf("%llu SYS", (txPos2.nPricePerUnit/COIN)*txPos2.nQty);
			oEscrow.push_back(Pair("total", sTotal));
			if(nHeight + GetEscrowDisplayExpirationDepth() - pindexBest->nHeight <= 0)
			{
				expired = 1;
			}  

			oEscrow.push_back(Pair("expired", expired));
			oRes.push_back(oEscrow);
        }
        
    }
    return oRes;
}

Value escrowfilter(const Array& params, bool fHelp) {
    if (fHelp || params.size() > 5)
        throw runtime_error(
                "escrowfilter [[[[[search string] maxage=36000] from=0] nb=0] stat]\n"
                        "scan and filter escrows\n"
                        "[search string] : Find arbiter or seller via alias name or an escrow GUID, empty means all escrows\n"
                        "[maxage] : look in last [maxage] blocks\n"
                        "[from] : show results from number [from]\n"
                        "[nb] : show [nb] results, 0 means all\n"
                        "[stats] : show some stats instead of results\n"
                        "escrowfilter \"\" 5 # list Escrows updated in last 5 blocks\n");

    string strSearch;
    int nFrom = 0;
    int nNb = 0;
    int nMaxAge = GetEscrowExpirationDepth();
    bool fStat = false;
    int nCountFrom = 0;
    int nCountNb = 0;

    if (params.size() > 0)
        strSearch = params[0].get_str();

    if (params.size() > 1)
        nMaxAge = params[1].get_int();

    if (params.size() > 2)
        nFrom = params[2].get_int();

    if (params.size() > 3)
        nNb = params[3].get_int();

    if (params.size() > 4)
        fStat = (params[4].get_str() == "stat" ? true : false);

    //CEscrowDB dbEscrow("r");
    Array oRes;

    vector<unsigned char> vchEscrow;
    vector<pair<vector<unsigned char>, CEscrow> > escrowScan;
    if (!pescrowdb->ScanEscrows(vchEscrow, 100000000, escrowScan))
        throw JSONRPCError(RPC_WALLET_ERROR, "scan failed");

    pair<vector<unsigned char>, CEscrow> pairScan;
    BOOST_FOREACH(pairScan, escrowScan) {
		CEscrow txEscrow = pairScan.second;
		string escrow = stringFromVch(txEscrow.vchRand);
		string offer = stringFromVch(txEscrow.vchOffer);
        if (strSearch != "" && strSearch != escrow && strSearch != txEscrow.arbiter && strSearch != txEscrow.seller)
            continue;

        
        int nHeight = txEscrow.nHeight;

        // max age
        if (nMaxAge != 0 && pindexBest->nHeight - nHeight >= nMaxAge)
            continue;
        // from limits
        nCountFrom++;
        if (nCountFrom < nFrom + 1)
            continue;
        CTransaction tx;
        uint256 blockHash;
		if (!GetTransaction(txEscrow.txHash, tx, blockHash, true))
			continue;

		int expired = 0;

        Object oEscrow;
        oEscrow.push_back(Pair("escrow", escrow));
		if(nHeight + GetEscrowDisplayExpirationDepth() - pindexBest->nHeight <= 0)
		{
			expired = 1;
		} 
		string sTime;
		CBlockIndex *pindex = FindBlockByHeight(txEscrow.nHeight);
		if (pindex) {
			sTime = strprintf("%llu", pindex->nTime);
		}
		oEscrow.push_back(Pair("time", sTime));
		oEscrow.push_back(Pair("expired", expired));
		oEscrow.push_back(Pair("seller", txEscrow.seller));
		oEscrow.push_back(Pair("arbiter", txEscrow.arbiter));
		oEscrow.push_back(Pair("buyerkey", stringFromVch(txEscrow.vchBuyerKey)));
		oEscrow.push_back(Pair("offer", stringFromVch(txEscrow.vchOffer)));
		oEscrow.push_back(Pair("offeracceptlink", stringFromVch(txEscrow.vchOfferAcceptLink)));

		string sTotal = strprintf("%llu SYS", (txEscrow.nPricePerUnit/COIN)*txEscrow.nQty);
		oEscrow.push_back(Pair("total", sTotal));
        oRes.push_back(oEscrow);

        nCountNb++;
        // nb limits
        if (nNb > 0 && nCountNb >= nNb)
            break;
    }

    if (fStat) {
        Object oStat;
        oStat.push_back(Pair("blocks", (int) nBestHeight));
        oStat.push_back(Pair("count", (int) oRes.size()));
        //oStat.push_back(Pair("sha256sum", SHA256(oRes), true));
        return oStat;
    }

    return oRes;
}

Value escrowscan(const Array& params, bool fHelp) {
    if (fHelp || 2 > params.size())
        throw runtime_error(
                "escrowscan [<start-escrow>] [<max-returned>]\n"
                        "scan all escrows, starting at start-escrow and returning a maximum number of entries (default 500)\n");

    vector<unsigned char> vchEscrow;
    int nMax = 500;
    if (params.size() > 0) {
        vchEscrow = vchFromValue(params[0]);
    }

    if (params.size() > 1) {
        Value vMax = params[1];
        ConvertTo<double>(vMax);
        nMax = (int) vMax.get_real();
    }

    //CEscrowDB dbEscrow("r");
    Array oRes;

    vector<pair<vector<unsigned char>, CEscrow> > escrowScan;
    if (!pescrowdb->ScanEscrows(vchEscrow, nMax, escrowScan))
        throw JSONRPCError(RPC_WALLET_ERROR, "scan failed");

    pair<vector<unsigned char>, CEscrow> pairScan;
    BOOST_FOREACH(pairScan, escrowScan) {
        Object oEscrow;
        string escrow = stringFromVch(pairScan.first);
        oEscrow.push_back(Pair("escrow", escrow));
        CTransaction tx;
        CEscrow txEscrow = pairScan.second;
        uint256 blockHash;
		int expired = 0;
        int nHeight = txEscrow.nHeight;
        
		if (!GetTransaction(txEscrow.txHash, tx, blockHash, true))
			continue;


		if(nHeight + GetEscrowDisplayExpirationDepth() - pindexBest->nHeight <= 0)
		{
			expired = 1;
		}  
		string sTime;
		CBlockIndex *pindex = FindBlockByHeight(txEscrow.nHeight);
		if (pindex) {
			sTime = strprintf("%llu", pindex->nTime);
		}
		oEscrow.push_back(Pair("time", sTime));
		oEscrow.push_back(Pair("seller", txEscrow.seller));
		oEscrow.push_back(Pair("arbiter", txEscrow.arbiter));
		oEscrow.push_back(Pair("buyerkey", stringFromVch(txEscrow.vchBuyerKey)));
		oEscrow.push_back(Pair("offer", stringFromVch(txEscrow.vchOffer)));
		oEscrow.push_back(Pair("offeracceptlink", stringFromVch(txEscrow.vchOfferAcceptLink)));
		string sTotal = strprintf("%ll SYS", (txEscrow.nPricePerUnit/COIN)*txEscrow.nQty);
		oEscrow.push_back(Pair("total", sTotal));
		oEscrow.push_back(Pair("expired", expired));
			
		oRes.push_back(oEscrow);
    }

    return oRes;
}



