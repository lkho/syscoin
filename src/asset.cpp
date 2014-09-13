#include "asset.h"
#include "init.h"
#include "txdb.h"
#include "util.h"
#include "auxpow.h"
#include "script.h"
#include "main.h"

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"

#include <boost/xpressive/xpressive_dynamic.hpp>

using namespace std;
using namespace json_spirit;

template<typename T> void ConvertTo(Value& value, bool fAllowNull = false);

std::map<std::vector<unsigned char>, uint256> mapMyAssets;
std::map<std::vector<unsigned char>, std::set<uint256> > mapAssetPending;
std::list<CAssetFee> lstAssetFees;

#ifdef GUI
extern std::map<uint160, std::vector<unsigned char> > mapMyAssetHashes;
#endif

extern CAssetDB *passetdb;

extern uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo,
        unsigned int nIn, int nHashType);

CScript RemoveAssetScriptPrefix(const CScript& scriptIn);
bool DecodeAssetScript(const CScript& script, int& op,
        std::vector<std::vector<unsigned char> > &vvch,
        CScript::const_iterator& pc);

extern bool Solver(const CKeyStore& keystore, const CScript& scriptPubKey,
        uint256 hash, int nHashType, CScript& scriptSigRet,
        txnouttype& whichTypeRet);
extern bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey,
        const CTransaction& txTo, unsigned int nIn, unsigned int flags,
        int nHashType);

bool IsAssetOp(int op) {
    return op == OP_ASSET;
}

// 10080 blocks = 1 week
// certificate issuer expiration time is ~ 6 months or 26 weeks
// expiration blocks is 262080 (final)
// expiration starts at 87360, increases by 1 per block starting at
// block 174721 until block 349440
int64 GetAssetNetworkFee(int seed, int nHeight) {
    if (fCakeNet) return CENT;
    int64 nRes = 48 * COIN;
    int64 nDif = 34 * COIN;
    if(seed==2) {
        nRes = 175;
        nDif = 111;
    } else if(seed==4) {
        nRes = 10;
        nDif = 8;
    }
    int nTargetHeight = 130080;
    if(nHeight>nTargetHeight) return nRes - nDif;
    else return nRes - ( (nHeight/nTargetHeight) * nDif );
}

// Increase expiration to 36000 gradually starting at block 24000.
// Use for validation purposes and pass the chain height.
int GetAssetExpirationDepth(int nHeight) {
    if (nHeight < 174720) return 87360;
    if (nHeight < 349440) return nHeight - 87360;
    return 262080;
}

// For display purposes, pass the name height.
int GetAssetDisplayExpirationDepth(int nHeight) {
    return GetAssetExpirationDepth(nHeight);
}

bool IsMyAsset(const CTransaction& tx, const CTxOut& txout) {
    const CScript& scriptPubKey = RemoveAssetScriptPrefix(txout.scriptPubKey);
    CScript scriptSig;
    txnouttype whichTypeRet;
    if (!Solver(*pwalletMain, scriptPubKey, 0, 0, scriptSig, whichTypeRet))
        return false;
    return true;
}

string assetFromOp(int op) {
    switch (op) {
    case OP_ASSET:
        return "asset";
    case XOP_ASSET_NEW:
        return "assetnew";
    case XOP_ASSET_ACTIVATE:
        return "assetactivate";
    case XOP_ASSET_SEND:
        return "assetsend";
    default:
        return "<unknown asset op>";
    }
}

bool CAsset::UnserializeFromTx(const CTransaction &tx) {
    try {
        CDataStream dsAsset(vchFromString(DecodeBase64(stringFromVch(tx.data))), SER_NETWORK, PROTOCOL_VERSION);
        dsAsset >> *this;
    } catch (std::exception &e) {
        return false;
    }
    return true;
}

void CAsset::SerializeToTx(CTransaction &tx) {
    vector<unsigned char> vchData = vchFromString(SerializeToString());
    tx.data = vchData;
}

string CAsset::SerializeToString() {
    CDataStream dsAsset(SER_NETWORK, PROTOCOL_VERSION);
    dsAsset << *this;
    vector<unsigned char> vchData(dsAsset.begin(), dsAsset.end());
    return EncodeBase64(vchData.data(), vchData.size());
}

//TODO implement
bool CAssetDB::ScanAssets(const std::vector<unsigned char>& vchAsset, unsigned int nMax,
        std::vector<std::pair<std::vector<unsigned char>, CAsset> >& assetScan) {

    leveldb::Iterator *pcursor = passetdb->NewIterator();

    CDataStream ssKeySet(SER_DISK, CLIENT_VERSION);
    ssKeySet << make_pair(string("asseti"), vchAsset);
    string sType;
    pcursor->Seek(ssKeySet.str());

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
            leveldb::Slice slKey = pcursor->key();
            CDataStream ssKey(slKey.data(), slKey.data() + slKey.size(), SER_DISK, CLIENT_VERSION);

            ssKey >> sType;
            if(sType == "asseti") {
                vector<unsigned char> vchAsset;
                ssKey >> vchAsset;
                leveldb::Slice slValue = pcursor->value();
                CDataStream ssValue(slValue.data(), slValue.data() + slValue.size(), SER_DISK, CLIENT_VERSION);
                vector<CAsset> vtxPos;
                ssValue >> vtxPos;
                CAsset txPos;
                if (!vtxPos.empty())
                    txPos = vtxPos.back();
                assetScan.push_back(make_pair(vchAsset, txPos));
            }
            if (assetScan.size() >= nMax)
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
 * [CAssetDB::ReconstructAssetIndex description]
 * @param  pindexRescan [description]
 * @return              [description]
 */
bool CAssetDB::ReconstructAssetIndex(CBlockIndex *pindexRescan) {
    CBlockIndex* pindex = pindexRescan;

    {
    LOCK(pwalletMain->cs_wallet);
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

            // decode the asset op, params, height
            bool o = DecodeAssetTx(tx, op, nOut, vvchArgs, nHeight);
            if (!o || !IsAssetOp(op)) continue;

            vector<unsigned char> vchAsset = vvchArgs[0];

            // get the transaction
            if(!GetTransaction(tx.GetHash(), tx, txblkhash, true))
                continue;

            // attempt to read asset from txn
            CAsset txAsset, serializedAsset;
            if(!txAsset.UnserializeFromTx(tx))
                return error("ReconstructAssetIndex() : failed to unserialize asset from tx");
            serializedAsset = txAsset;

            // skip news - todo CB readdress - why skip?
            if (txAsset.nOp == XOP_ASSET_NEW) continue;

            // read asset from DB if it exists
            vector<CAsset> vtxPos;
            if (ExistsAsset(vchAsset)) {
                if (!ReadAsset(vchAsset, vtxPos))
                    return error("ReconstructAssetIndex() : failed to read asset from DB");
                if(vtxPos.size()!=0) {
                    txAsset.nHeight = nHeight;
                    txAsset.GetAssetFromList(vtxPos);
                }
            }

            // insert asset fees to regenerate list, write asset to master index
            int64 nTheFee = GetAssetNetFee(tx);
            InsertAssetFee(pindex, tx.GetHash(), txAsset.nOp, nTheFee);

            // asset only visible after NEW?
            if(txAsset.nOp != XOP_ASSET_NEW) {
                // txn-specific values to asset object

                if(txAsset.nOp == XOP_ASSET_ACTIVATE
                	|| (txAsset.nOp == XOP_ASSET_SEND && IsAssetMine(tx))) {

                    if(txAsset.nOp == XOP_ASSET_SEND) {
                    	if(txAsset.isChange) txAsset.nQty = serializedAsset.nQty;
                    	else txAsset.nQty += serializedAsset.nQty;
                    }
                    else
                    	txAsset.nQty = serializedAsset.nQty;

                    txAsset.vchRand = vvchArgs[0];
                    txAsset.txHash = tx.GetHash();
                    txAsset.nHeight = nHeight;
                    txAsset.nTime = pindex->nTime;

                    txAsset.PutToAssetList(vtxPos);

                    if (!WriteAsset(vchAsset, vtxPos))
                        return error("ReconstructAssetIndex() : failed to write to asset DB");
                }
            }

            printf( "RECONSTRUCT ASSET: op=%s asset=%s symbol=%s title=%s hash=%s height=%d fees=%llu\n",
                    assetFromOp(txAsset.nOp).c_str(),
                    stringFromVch(vvchArgs[0]).c_str(),
                    stringFromVch(txAsset.vchSymbol).c_str(),
                    stringFromVch(txAsset.vchTitle).c_str(),
                    tx.GetHash().ToString().c_str(),
                    nHeight,
                    nTheFee);
        }
        pindex = pindex->pnext;
        Flush();
    }
    }
    return true;
}

// get the depth of transaction txnindex relative to block at index pIndexBlock, looking
// up to maxdepth. Return relative depth if found, or -1 if not found and maxdepth reached.
int CheckAssetTransactionAtRelativeDepth(CBlockIndex* pindexBlock,
        const CCoins *txindex, int maxDepth) {
    for (CBlockIndex* pindex = pindexBlock;
            pindex /*&& pindexBlock->nHeight - pindex->nHeight < maxDepth */;
            pindex = pindex->pprev)
        if (pindex->nHeight == (int) txindex->nHeight)
            return pindexBlock->nHeight - pindex->nHeight;
    return -1;
}

int GetAssetTxHashHeight(const uint256 txHash) {
    CDiskTxPos postx;
    pblocktree->ReadTxIndex(txHash, postx);
    return postx.nPos;
}

uint64 GetAssetFeeSubsidy(unsigned int nHeight) {
    unsigned int h12 = 360 * 12;
    unsigned int nTargetTime = 0;
    unsigned int nTarget1hrTime = 0;
    unsigned int blk1hrht = nHeight - 1;
    unsigned int blk12hrht = nHeight - 1;
    bool bFound = false;
    uint64 hr1 = 1, hr12 = 1;

    BOOST_FOREACH(CAssetFee &nmFee, lstAssetFees) {
        if(nmFee.nHeight <= nHeight)
            bFound = true;
        if(bFound) {
            if(nTargetTime==0) {
                hr1 = hr12 = 0;
                nTargetTime = nmFee.nTime - h12;
                nTarget1hrTime = nmFee.nTime - (h12/12);
            }
            if(nmFee.nTime > nTargetTime) {
                hr12 += nmFee.nFee;
                blk12hrht = nmFee.nHeight;
                if(nmFee.nTime > nTarget1hrTime) {
                    hr1 += nmFee.nFee;
                    blk1hrht = nmFee.nHeight;
                }
            }
        }
    }
    hr12 /= (nHeight - blk12hrht) + 1;
    hr1 /= (nHeight - blk1hrht) + 1;
    uint64 nSubsidyOut = hr1 > hr12 ? hr1 : hr12;
    return nSubsidyOut;
}

bool InsertAssetFee(CBlockIndex *pindex, uint256 hash, int nOp, uint64 nValue) {
    unsigned int h12 = 3600 * 12;
    list<CAssetFee> txnDup;
    CAssetFee oFee;
    oFee.nTime = pindex->nTime;
    oFee.nHeight = pindex->nHeight;
    oFee.nOp = nOp;
    oFee.nFee = nValue;
    bool bFound = false;

    unsigned int tHeight =
            pindex->nHeight - 2880 < 0 ? 0 : pindex->nHeight - 2880;

    while (true) {
        if (lstAssetFees.size() > 0
                && (lstAssetFees.back().nTime + h12 < pindex->nTime
                        || lstAssetFees.back().nHeight < tHeight))
            lstAssetFees.pop_back();
        else
            break;
    }
    BOOST_FOREACH(CAssetFee &nmFee, lstAssetFees) {
        if (oFee.hash == nmFee.hash
                && oFee.nHeight == nmFee.nHeight) {
            bFound = true;
            break;
        }
    }
    if (!bFound)
        lstAssetFees.push_front(oFee);

    return true;
}

int64 GetAssetNetFee(const CTransaction& tx) {
    int64 nFee = 0;
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        if (out.scriptPubKey.size() == 1 && out.scriptPubKey[0] == OP_RETURN)
            nFee += out.nValue;
    }
    return nFee;
}

// TODO CB I think we need to change this to a uint64
int GetAssetHeight(vector<unsigned char> vchAsset) {
    vector<CAsset> vtxPos;
    if (passetdb->ExistsAsset(vchAsset)) {
        if (!passetdb->ReadAsset(vchAsset, vtxPos))
            return error("GetAssetHeight() : failed to read from asset DB");
        if (vtxPos.empty()) return -1;
        CAsset& txPos = vtxPos.back();
        return txPos.nHeight;
    }
    return -1;
}

// Check that the last entry in asset history matches the given tx pos
bool CheckAssetTxPos(const vector<CAsset> &vtxPos, const int txPos) {
    if (vtxPos.empty()) return false;
    CAsset asset;
    asset.nHeight = txPos;
    return asset.GetAssetFromList(vtxPos);
}

int IndexOfAssetOutput(const CTransaction& tx) {
    vector<vector<unsigned char> > vvch;
    int op, nOut;
    if (!DecodeAssetTx(tx, op, nOut, vvch, -1))
        throw runtime_error("IndexOfAssetOutput() : asset output not found");
    return nOut;
}

bool GetNameOfAssetTx(const CTransaction& tx, vector<unsigned char>& asset) {
    if (tx.nVersion != SYSCOIN_TX_VERSION)
        return false;

    vector<vector<unsigned char> > vvchArgs;
    int op, nOut;
    if (!DecodeAssetTx(tx, op, nOut, vvchArgs, -1))
        return error("GetNameOfAssetTx() : could not decode asset tx");

	asset = vvchArgs[0];
	return true;
}

//TODO come back here check to see how / where this is used
bool IsConflictedAssetTx(CBlockTreeDB& txdb, const CTransaction& tx, vector<unsigned char>& asset) {
    if (tx.nVersion != SYSCOIN_TX_VERSION)
        return false;
    vector<vector<unsigned char> > vvchArgs;
    int op, nOut, nPrevHeight;
    if (!DecodeAssetTx(tx, op, nOut, vvchArgs, pindexBest->nHeight))
        return error("IsConflictedAssetTx() : could not decode asset tx");

    switch (op) {
    case OP_ASSET:
        nPrevHeight = GetAssetHeight(vvchArgs[0]);
        asset = vvchArgs[0];
        if (nPrevHeight >= 0
                && pindexBest->nHeight - nPrevHeight
                        < GetAssetExpirationDepth(pindexBest->nHeight))
            return true;
    }
    return false;
}

bool GetValueOfAssetTx(const CTransaction& tx, vector<unsigned char>& value) {
    vector<vector<unsigned char> > vvch;
    int op, nOut;

    if (!DecodeAssetTx(tx, op, nOut, vvch, -1))
        return false;

    if(!IsAssetOp(op)) return false;

    // get the asset so we can get the extended op code
    CAsset txAsset;
    if(!txAsset.UnserializeFromTx(tx))
        return error("GetValueOfAssetTx() : failed to unserialize asset from tx");

    switch (txAsset.nOp) {
        case XOP_ASSET_NEW:
            return false;

        case XOP_ASSET_ACTIVATE:
        case XOP_ASSET_SEND:
            value = vvch[vvch.size()-1];
            return true;
        
        default:
            return false;
    }
}

bool IsAssetMine(const CTransaction& tx) {
    if (tx.nVersion != SYSCOIN_TX_VERSION)
        return false;

    vector<vector<unsigned char> > vvch;
    int op, nOut;

    bool good = DecodeAssetTx(tx, op, nOut, vvch, -1);
    if (!good) return false;
    
    if(!IsAssetOp(op)) return false;

    const CTxOut& txout = tx.vout[nOut];
    if (IsMyAsset(tx, txout)) {
        printf("IsAssetMine() : found my transaction %s nout %d\n",
                tx.GetHash().GetHex().c_str(), nOut);
        return true;
    }
    return false;
}

bool IsAssetMine(const CTransaction& tx, const CTxOut& txout, bool ignore_assetnew) {
    if (tx.nVersion != SYSCOIN_TX_VERSION)
        return false;

    vector<vector<unsigned char> > vvch;
    int op, nOut;

    bool good = DecodeAssetTx(tx, op, nOut, vvch, -1);
    if (!good) {
        error( "IsAssetMine() : no output out script in asset tx %s\n",
                tx.ToString().c_str());
        return false;
    }
    if(!IsAssetOp(op))
        return false;
    
    // get the asset so we can get the extended op code
    CAsset txAsset;
    if(!txAsset.UnserializeFromTx(tx))
        return error("GetValueOfAssetTx() : failed to unserialize asset from tx");

    if (ignore_assetnew && txAsset.nOp == XOP_ASSET_NEW)
        return false;

    if (IsMyAsset(tx, txout)) {
        printf("IsAssetMine() : found my transaction %s value %d\n",
                tx.GetHash().GetHex().c_str(), (int) txout.nValue);
        return true;
    }
    return false;
}

bool GetValueOfAssetTxHash(const uint256 &txHash, vector<unsigned char>& vchValue, uint256& hash, int& nHeight) {
    nHeight = GetAssetTxHashHeight(txHash);
    CTransaction tx;
    uint256 blockHash;
    if (!GetTransaction(txHash, tx, blockHash, true))
        return error("GetValueOfAssetTxHash() : could not read tx from disk");
    if (!GetValueOfAssetTx(tx, vchValue))
        return error("GetValueOfAssetTxHash() : could not decode value from tx");
    hash = tx.GetHash();
    return true;
}

bool GetValueOfAsset(CAssetDB& dbAsset, const vector<unsigned char> &vchAsset, vector<unsigned char>& vchValue, int& nHeight) {
    vector<CAsset> vtxPos;
    if (!passetdb->ReadAsset(vchAsset, vtxPos) || vtxPos.empty())
        return false;
    CAsset& txPos = vtxPos.back();
    nHeight = txPos.nHeight;
    vchValue = txPos.vchRand;
    return true;
}

bool GetTxOfAsset(CAssetDB& dbAsset, const vector<unsigned char> &vchAsset, CTransaction& tx) {
    vector<CAsset> vtxPos;
    if (!passetdb->ReadAsset(vchAsset, vtxPos) || vtxPos.empty())
        return false;
    CAsset& txPos = vtxPos.back();
    //int nHeight = txPos.nHeight;
    uint256 hashBlock;
    if (!GetTransaction(txPos.txHash, tx, hashBlock, true))
        return error("GetTxOfAsset() : could not read tx from disk");
    return true;
}

bool DecodeAssetTx(const CTransaction& tx, int& op, int& nOut, vector<vector<unsigned char> >& vvch, int nHeight) {
    bool found = false;
    if (nHeight < 0)
        nHeight = pindexBest->nHeight;
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        vector<vector<unsigned char> > vvchRead;
        if (DecodeAssetScript(out.scriptPubKey, op, vvchRead)) {
            nOut = i; found = true; vvch = vvchRead;
            break;
        }
    }
    if (!found) vvch.clear();
    return found && IsAssetOp(op);
}

bool GetValueOfAssetTx(const CCoins& tx, vector<unsigned char>& value) {
    vector<vector<unsigned char> > vvch;

    int op, nOut;

    if (!DecodeAssetTx(tx, op, nOut, vvch, -1))
        return false;

    if(!IsAssetOp(op)) return false;

    // value of transaction is always last param
    // transactions with 2 or 3 params have values
    if(vvch.size() != 1) {
        value = vvch[vvch.size()-1];
        return true;
    } 
    else 
        return false;
}

bool DecodeAssetTx(const CCoins& tx, int& op, int& nOut, vector<vector<unsigned char> >& vvch, int nHeight) {
    bool found = false;
//
//    if (nHeight < 0)
//        nHeight = pindexBest->nHeight;

    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        vector<vector<unsigned char> > vvchRead;
        if (DecodeAssetScript(out.scriptPubKey, op, vvchRead)) {
            nOut = i; found = true; vvch = vvchRead;
            break;
        }
    }
    if (!found) vvch.clear();
    return found;
}

bool DecodeAssetScript(const CScript& script, int& op,
        vector<vector<unsigned char> > &vvch) {
    CScript::const_iterator pc = script.begin();
    return DecodeAssetScript(script, op, vvch, pc);
}

bool DecodeAssetScript(const CScript& script, int& op, vector<vector<unsigned char> > &vvch, CScript::const_iterator& pc) {
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
    if (op == OP_ASSET && vvch.size() >= 1 && vvch.size() <= 3)
        return true;
    return false;
}

bool SignAssetSignature(const CTransaction& txFrom, CTransaction& txTo, unsigned int nIn, int nHashType = SIGHASH_ALL, CScript scriptPrereq = CScript()) {
    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    // Leave out the signature from the hash, since a signature can't sign itself.
    // The checksig op will also drop the signatures from its hash.
    const CScript& scriptPubKey = RemoveAssetScriptPrefix(txout.scriptPubKey);
    uint256 hash = SignatureHash(scriptPrereq + txout.scriptPubKey, txTo, nIn, nHashType);
    txnouttype whichTypeRet;

    // verify our signature
    if (!Solver(*pwalletMain, scriptPubKey, hash, nHashType, txin.scriptSig, whichTypeRet))
        return false;

    txin.scriptSig = scriptPrereq + txin.scriptSig;

    // Test the solution
    if (scriptPrereq.empty())
        if (!VerifyScript(txin.scriptSig, txout.scriptPubKey, txTo, nIn, 0, 0))
            return false;

    return true;
}

bool CreateAssetTransactionWithInputTx(
        const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxIn,
        int nTxOut, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet,
        const string& txData) {

    int64 nValue = 0;
    BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend) {
        if (nValue < 0)  return false;
        nValue += s.second;
    }
    if (vecSend.empty() || nValue < 0)
        return false;

    wtxNew.BindWallet(pwalletMain);
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        nFeeRet = nTransactionFee;
        loop {
            wtxNew.vin.clear();
            wtxNew.vout.clear();
            wtxNew.fFromMe = true;
            wtxNew.data = vchFromString(txData);

            int64 nTotalValue = nValue + nFeeRet;
            printf("CreateAssetTransactionWithInputTx: total value = %d\n",
                    (int) nTotalValue);
            double dPriority = 0;

            // vouts to the payees
            BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
                wtxNew.vout.push_back(CTxOut(s.second, s.first));

            int64 nWtxinCredit = wtxIn.vout[nTxOut].nValue;

            // Choose coins to use
            set<pair<const CWalletTx*, unsigned int> > setCoins;
            int64 nValueIn = 0;

            printf( "CreateAssetTransactionWithInputTx: SelectCoins(%s), nTotalValue = %s, nWtxinCredit = %s\n",
                    FormatMoney(nTotalValue - nWtxinCredit).c_str(),
                    FormatMoney(nTotalValue).c_str(),
                    FormatMoney(nWtxinCredit).c_str());

            // if the transaction value is greater than the input txn value
            // then select additional coins from our wallet
            if (nTotalValue - nWtxinCredit > 0) {
                if (!pwalletMain->SelectCoins(nTotalValue - nWtxinCredit, setCoins, nValueIn))
                    return false;
            }
            printf( "CreateAssetTransactionWithInputTx: selected %d tx outs, nValueIn = %s\n",
                    (int) setCoins.size(), FormatMoney(nValueIn).c_str());

            // turn coins set to vector
            vector<pair<const CWalletTx*,unsigned int> > vecCoins(setCoins.begin(), setCoins.end());

            // iterate through coins to calculate priority
            BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
                int64 nCredit = coin.first->vout[coin.second].nValue;
                dPriority += (double) nCredit  * coin.first->GetDepthInMainChain();
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
                    if (!SignAssetSignature(*coin.first, wtxNew, nIn++))
                        throw runtime_error("could not sign asset coin output");
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
                printf( "CreateAssetTransactionWithInputTx: re-iterating (nFreeRet = %s)\n",
                        FormatMoney(nFeeRet).c_str());
                continue;
            }

            // Fill vtxPrev by copying from previous transactions vtxPrev
            wtxNew.AddSupportingTransactions();
            wtxNew.fTimeReceivedIsTxTime = true;

            break;
        }
    }

    printf("CreateAssetTransactionWithInputTx succeeded:\n%s",
            wtxNew.ToString().c_str());
    return true;
}

// nTxOut is the output from wtxIn that we should grab
string SendAssetMoneyWithInputTx(CScript scriptPubKey, int64 nValue, int64 nNetFee, CWalletTx& wtxIn, CWalletTx& wtxNew, bool fAskFee, const string& txData) {
    
    int nTxOut = IndexOfAssetOutput(wtxIn);
    CReserveKey reservekey(pwalletMain);
    int64 nFeeRequired;
    vector<pair<CScript, int64> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));

    if (nNetFee) {
        CScript scriptFee;
        scriptFee << OP_RETURN;
        vecSend.push_back(make_pair(scriptFee, nNetFee));
    }

    if (!CreateAssetTransactionWithInputTx(vecSend, wtxIn, nTxOut, wtxNew, reservekey, nFeeRequired, txData)) {
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
        return _(
                "Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");

    return "";
}

bool GetAssetAddress(const CTransaction& tx, std::string& strAddress) {
    int op, nOut = 0;
    vector<vector<unsigned char> > vvch;

    if (!DecodeAssetTx(tx, op, nOut, vvch, -1))
        return error("GetAssetAddress() : could not decode asset tx.");

    const CTxOut& txout = tx.vout[nOut];

    const CScript& scriptPubKey = RemoveAssetScriptPrefix(txout.scriptPubKey);
    strAddress = CBitcoinAddress(scriptPubKey.GetID()).ToString();
    return true;
}

bool GetAssetAddress(const CDiskTxPos& txPos, std::string& strAddress) {
    CTransaction tx;
    if (!tx.ReadFromDisk(txPos))
        return error("GetAssetAddress() : could not read tx from disk");
    return GetAssetAddress(tx, strAddress);
}

CScript RemoveAssetScriptPrefix(const CScript& scriptIn) {
    int op;
    vector<vector<unsigned char> > vvch;
    CScript::const_iterator pc = scriptIn.begin();

    if (!DecodeAssetScript(scriptIn, op, vvch, pc))
	   printf ("RemoveAssetScriptPrefix() : Could not decode asset script (softfail). This is is known to happen for some OPs annd prevents those from getting displayed or accounted for.");
    
    return CScript(pc, scriptIn.end());
}

bool CheckAssetInputs(CBlockIndex *pindexBlock, const CTransaction &tx, CValidationState &state, CCoinsViewCache &inputs, map<vector<unsigned char>, uint256> &mapTestPool, bool fBlock, bool fMiner, bool fJustCheck) {

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

        // Strict check - bug disallowed
        for (int i = 0; i < (int) tx.vin.size(); i++) {
            prevOutput = &tx.vin[i].prevout;
            prevCoins = &inputs.GetCoins(prevOutput->hash);
            vector<vector<unsigned char> > vvch;
            if (DecodeAssetScript(prevCoins->vout[prevOutput->n].scriptPubKey, prevOp, vvch)) {
                found = true; vvchPrevArgs = vvch;
                break;
            }
            if(!found)vvchPrevArgs.clear();
        }

        // Make sure asset outputs are not spent by a regular transaction, or the asset would be lost
        if (tx.nVersion != SYSCOIN_TX_VERSION) {
            if (found)
                return error(
                        "CheckAssetInputs() : a non-syscoin transaction with a syscoin input");
            return true;
        }

        vector<vector<unsigned char> > vvchArgs;
        int op;
        int nOut;
        bool good = DecodeAssetTx(tx, op, nOut, vvchArgs, pindexBlock->nHeight);
        if (!good)
            return error("CheckAssetInputs() : could not decode asset tx");
        int nPrevHeight;
        int nDepth;
        int64 nNetFee;

        // unserialize asset object from txn, check for valid
        CAsset theAsset;
        theAsset.UnserializeFromTx(tx);
        if (theAsset.IsNull())
            error("CheckAssetInputs() : null asset object");

        if (vvchArgs[0].size() > MAX_NAME_LENGTH)
            return error("asset hex rand too long");

        switch (theAsset.nOp) {
        case XOP_ASSET_NEW:

            if (found)
                return error(
                        "CheckAssetInputs() : assetnew tx pointing to previous syscoin tx");

            if (vvchArgs[0].size() != 20)
                return error("assetnew tx with incorrect hash length");

            break;

        case XOP_ASSET_ACTIVATE:

            // check for enough fees
            nNetFee = GetAssetNetFee(tx);
            if (nNetFee < GetAssetNetworkFee(1, pindexBlock->nHeight) - COIN) // TODO CB - COIN???
                return error(
                        "CheckAssetInputs() : got tx %s with fee too low %lu",
                        tx.GetHash().GetHex().c_str(),
                        (long unsigned int) nNetFee);

            // validate conditions
            if ((!found || prevOp != OP_ASSET) && !fJustCheck)
                return error("CheckAssetInputs() : assetactivate tx without previous assetnew tx");

            if (vvchArgs[1].size() > 20)
                return error("assetactivate tx with rand too big");

            if (vvchArgs[2].size() > MAX_VALUE_LENGTH)
                return error("assetactivate tx with value too long");

            if (fBlock && !fJustCheck) {
                // Check hash
                const vector<unsigned char> &vchHash = vvchPrevArgs[0];
                const vector<unsigned char> &vchAsset = vvchArgs[0];
                const vector<unsigned char> &vchRand = vvchArgs[1];
                vector<unsigned char> vchToHash(vchRand);
                vchToHash.insert(vchToHash.end(), vchAsset.begin(), vchAsset.end());
                uint160 hash = Hash160(vchToHash);

                if (uint160(vchHash) != hash)
                    return error(
                            "CheckAssetInputs() : asset hash mismatch prev : %s cur %s",
                            HexStr(stringFromVch(vchHash)).c_str(), HexStr(stringFromVch(vchToHash)).c_str());

                // min activation depth is 1
                nDepth = CheckAssetTransactionAtRelativeDepth(pindexBlock, prevCoins, 1);
                if ((fBlock || fMiner) && nDepth >= 0 && (unsigned int) nDepth < 1)
                    return false;

                // check for previous asset
                nDepth = CheckAssetTransactionAtRelativeDepth(pindexBlock, prevCoins, 0);
                if (nDepth == -1)
                    return error(
                            "CheckAssetInputs() : CheckAssetTransactionAtRelativeDepth fail");

                // disallow activate on an already activated asset
                nPrevHeight = GetAssetHeight(vchAsset);
                if (!fBlock && nPrevHeight >= 0)
                    return error(
                            "CheckAssetInputs() : assetactivate on an active asset.");

                if(pindexBlock->nHeight == pindexBest->nHeight) {
                    BOOST_FOREACH(const MAPTESTPOOLTYPE& s, mapTestPool) {
                        if (vvchArgs[0] == s.first) {
                           return error("CheckInputs() : will not mine assetactivate %s because it clashes with %s",
                                   tx.GetHash().GetHex().c_str(),
                                   s.second.GetHex().c_str());
                        }
                    }
                }
            }
            break;

        case XOP_ASSET_SEND:

            // check for enough fees
            nNetFee = GetAssetNetFee(tx);
            if (nNetFee < GetAssetNetworkFee(1, pindexBlock->nHeight) - COIN) // TODO CB - COIN???
                return error(
                        "CheckAssetInputs() : got tx %s with fee too low %lu",
                        tx.GetHash().GetHex().c_str(),
                        (long unsigned int) nNetFee);

            // TODO CB add logic back
            if (fBlock && !fJustCheck) {
                // Check hash
//            	if(vvchPrevArgs.size()!=0) {
//                    const vector<unsigned char> &vchHash = vvchPrevArgs[0];
//                    const vector<unsigned char> &vchAsset = vvchArgs[0];
//                    const vector<unsigned char> &vchRand = vvchArgs[1];
//                    vector<unsigned char> vchToHash(vchRand);
//                    vchToHash.insert(vchToHash.end(), vchAsset.begin(), vchAsset.end());
//                    uint160 hash = Hash160(vchToHash);
//
//                    if (uint160(vchHash) != hash)
//                        return error(
//                                "CheckAssetInputs() : asset hash mismatch prev : %s cur %s",
//                                HexStr(stringFromVch(vchHash)).c_str(), HexStr(stringFromVch(vchToHash)).c_str());
//            	}
            }


            break;

        default:
            return error( "CheckAssetInputs() : asset transaction has unknown op");
        }

        // save serialized asset for later use
        CAsset serializedAsset = theAsset;

        // if not an assetnew, load the asset data from the DB.
        vector<CAsset> vtxPos;
        if(theAsset.nOp != XOP_ASSET_NEW) {
            if (passetdb->ExistsAsset(vvchArgs[0])) {
                if (!passetdb->ReadAsset(vvchArgs[0], vtxPos))
                    return error(
                            "CheckAssetInputs() : failed to read from asset DB");
            }
        }

        // these ifs are problably total bullshit except for the assetnew
        if (fBlock || (!fBlock && !fMiner && !fJustCheck) ) {

            // remove asset from pendings
            vector<unsigned char> vchAsset = theAsset.nOp == XOP_ASSET_NEW
            		? vchFromString(HexStr(vvchArgs[0])) : vvchArgs[0];

            // TODO CB this lock needed?
            LOCK(cs_main);

            std::map<std::vector<unsigned char>, std::set<uint256> >::iterator
                    mi = mapAssetPending.find(vchAsset);
            if (mi != mapAssetPending.end())  mi->second.erase(tx.GetHash());

            // get the fee for this asset txn
            int64 nTheFee = GetAssetNetFee(tx);

            // add up everybody's asset fees not just mine
        	if(theAsset.nOp != XOP_ASSET_NEW) {
                // compute verify and write fee data to DB
                InsertAssetFee(pindexBlock, tx.GetHash(), theAsset.nOp, nTheFee);
                if(nTheFee > 0) printf("ASSET FEES: Added %lf in fees to track for regeneration.\n", (double) nTheFee / COIN);
                vector<CAssetFee> vAssetFees(lstAssetFees.begin(), lstAssetFees.end());
                if (!passetdb->WriteAssetFees(vAssetFees))
                    return error( "CheckAssetInputs() : failed to write fees to asset DB");
        	}

        	// only record asset info to the database if it's activate (so everyone can see it)
        	// or if it's a send and we are the recipient
            if(theAsset.nOp == XOP_ASSET_ACTIVATE
            	|| (theAsset.nOp == XOP_ASSET_SEND && IsAssetMine(tx) ) ) {
                if (!fMiner && !fJustCheck && pindexBlock->nHeight != pindexBest->nHeight) {
                    int nHeight = pindexBlock->nHeight;

                    // get the latest asset from the db
					theAsset.GetAssetFromList(vtxPos);

                    // set the new local asset quantity. if a prev txn exists
                    // then we increment the asset count. otherwise set it to qty
                    if(serializedAsset.nOp == XOP_ASSET_SEND) {
                    	if(serializedAsset.isChange)
                    		theAsset.nQty = serializedAsset.nQty;
                    	else
                    		theAsset.nQty += serializedAsset.nQty;
                    }
                    else
                    	theAsset.nQty = IsAssetMine(tx) ? serializedAsset.nQty : 0;

                    // set the asset's txn-dependent values
                    theAsset.nHeight = pindexBlock->nHeight;
                    theAsset.vchRand = vvchArgs[0];
                    theAsset.txHash = tx.GetHash();
                    theAsset.nTime = pindexBlock->nTime;
                    theAsset.PutToAssetList(vtxPos);

                    // write asset
                    if (!passetdb->WriteAsset(vvchArgs[0], vtxPos))
                        return error( "CheckAssetInputs() : failed to write to asset DB");
                    mapTestPool[vvchArgs[0]] = tx.GetHash();

                    // debug
                    printf( "CONNECTED ASSET: op=%s asset=%s value=%llu symbol=%s title=%s txn=%s height=%d fees=%llu\n",
                            assetFromOp(theAsset.nOp).c_str(),
                            stringFromVch(vvchArgs[0]).c_str(),
                            theAsset.nQty,
                            stringFromVch(theAsset.vchSymbol).c_str(),
                            stringFromVch(theAsset.vchTitle).c_str(),
                            tx.GetHash().ToString().c_str(),
                            nHeight, nTheFee / COIN);
                }
            }

        }
    }
    return true;
}

bool ExtractAssetAddress(const CScript& script, string& address) {
    if (script.size() == 1 && script[0] == OP_RETURN) {
        address = string("network fee");
        return true;
    }

    vector<vector<unsigned char> > vvch;
    int op;
    if (!DecodeAssetScript(script, op, vvch))
        return false;

    string strOp = assetFromOp(op);
    string strAsset;

    // TODO CB Need to differentiate XOPs - which means we need to txn's data
    // or find some other way of doing it
    if (op == OP_ASSET) { 
#ifdef GUI
        LOCK(cs_main);

        std::map<uint160, std::vector<unsigned char> >::const_iterator mi = mapMyAssetHashes.find(uint160(vvch[0]));
        if (mi != mapMyAssetHashes.end())
        strAsset = stringFromVch(mi->second);
        else
#endif
        strAsset = HexStr(vvch[0]);
    }

    // TODO CB as per comment above. Currently this is never called
    else
        strAsset = stringFromVch(vvch[0]);

    address = strOp + ": " + strAsset;
    return true;
}

void rescanforassets(CBlockIndex *pindexRescan) {
    printf("Scanning blockchain for assets to create fast index...\n");
    passetdb->ReconstructAssetIndex(pindexRescan);
}

int GetAssetTxPosHeight(const CDiskTxPos& txPos) {
    // Read block header
    CBlock block;
    if (!block.ReadFromDisk(txPos)) return 0;
    // Find the block in the index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.GetHash());
    if (mi == mapBlockIndex.end()) return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain()) return 0;
    return pindex->nHeight;
}

int GetAssetTxPosHeight2(const CDiskTxPos& txPos, int nHeight) {
    nHeight = GetAssetTxPosHeight(txPos);
    return nHeight;
}

Value assetnew(const Array& params, bool fHelp) {
     
    if (fHelp || params.size() != 4)
        throw runtime_error(
                "assetnew <symbol> <title> <description> <totalshares>\n"
                        "<symbol> symbol, 255 bytes max."
                        "<title> title, 255 bytes max."
                        "<description> description, 16KB max."
                        "<totalshares> total number of shares, 1 min, 2^64 - 1 max."
                        + HelpRequiringPassphrase());
    // gather inputs
    vector<unsigned char> vchSymbol = vchFromValue(params[0]);
    vector<unsigned char> vchTitle = vchFromValue(params[1]);
    vector<unsigned char> vchDescription = vchFromValue(params[2]);
    uint64 nTotalQty = atoi(params[3].get_str().c_str()); // TODO CB better translation for total quantity

    if(vchSymbol.size() < 1)
        throw runtime_error("asset symbol < 1 bytes!\n");

    if(vchSymbol.size() > 10)
        throw runtime_error("asset symbol > 10 bytes!\n");

    if(vchTitle.size() < 1)
        throw runtime_error("asset title < 1 bytes!\n");

    if(vchTitle.size() > 255)
        throw runtime_error("asset title > 255 bytes!\n");

    if (vchDescription.size() < 1)
        throw runtime_error("asset description < 1 bytes!\n");

    if (vchDescription.size() > 16 * 1024)
        throw runtime_error("asset description > 16384 bytes!\n");

    if(nTotalQty<1)
        throw runtime_error("asset total quantity < 1!\n");

    // set wallet tx ver
    CWalletTx wtx;
    wtx.nVersion = SYSCOIN_TX_VERSION;

    // generate rand identifier as vch
    uint64 rand = GetRand((uint64) -1);
    vector<unsigned char> vchRand = CBigNum(rand).getvch();

    // generate a hex string of rand identifier as a vch
    vector<unsigned char> vchAsset = vchFromString(HexStr(vchRand));

    // concatenate string representation to number,  hash it
    vector<unsigned char> vchToHash(vchRand);
    vchToHash.insert(vchToHash.end(), vchAsset.begin(), vchAsset.end());
    uint160 assetHash = Hash160(vchToHash);

    // build asset object
    CAsset newAsset;
    newAsset.nOp = XOP_ASSET_NEW;
    newAsset.vchRand = vchAsset;
    newAsset.vchSymbol = vchSymbol;
    newAsset.vchTitle = vchTitle;
    newAsset.vchDescription = vchDescription;
    newAsset.nTotalQty = nTotalQty;
    newAsset.nQty = 0;

    // TODO CB potentially one could add a hash of the bdata to the txn
    string bdata = newAsset.SerializeToString();

    // create transaction keys
    CPubKey newDefaultKey;
    pwalletMain->GetKeyFromPool(newDefaultKey, false);
    CScript scriptPubKeyOrig;
    scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());
    CScript scriptPubKey;
    scriptPubKey << CScript::EncodeOP_N(OP_ASSET) << assetHash << OP_2DROP;
    scriptPubKey += scriptPubKeyOrig;

    // send transaction
    {
        LOCK(cs_main);
        EnsureWalletIsUnlocked();
        string strError = pwalletMain->SendMoney(scriptPubKey, MIN_AMOUNT, wtx, false, bdata);
        if (strError != "") throw JSONRPCError(RPC_WALLET_ERROR, strError);
        mapMyAssets[vchAsset] = wtx.GetHash();
    }
    printf("SENT:ASSETNEW : symbol=%s title=%s, description=%s, rand=%s, tx=%s, data:\n%s\n",
            stringFromVch(vchSymbol).c_str(), 
            stringFromVch(vchTitle).c_str(), 
            stringFromVch(vchDescription).c_str(), 
            stringFromVch(vchAsset).c_str(),
            wtx.GetHash().GetHex().c_str(), bdata.c_str());

    // return results
    vector<Value> res;
    res.push_back(wtx.GetHash().GetHex());
    res.push_back(HexStr(vchRand));

    return res;
}

Value assetactivate(const Array& params, bool fHelp) {
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
                "assetactivate <guid> [<tx>]\n"
                        "Activate an asset after creating one with assetnew.\n"
                        "<rand> asset guid.\n"
                        + HelpRequiringPassphrase());

    // gather inputs
    vector<unsigned char> vchRand = ParseHex(params[0].get_str());
    vector<unsigned char> vchAsset = vchFromValue(params[0]);

    // this is a syscoin transaction
    CWalletTx wtx;
    wtx.nVersion = SYSCOIN_TX_VERSION;

    // check for existing pending assets
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        if (mapAssetPending.count(vchAsset) && mapAssetPending[vchAsset].size()) {
            error( "assetactivate() : there are %d pending operations on that asset, including %s",
                   (int) mapAssetPending[vchAsset].size(),
                   mapAssetPending[vchAsset].begin()->GetHex().c_str());
            throw runtime_error("there are pending operations on that asset");
        }

        // look for an asset with identical hex rand keys. wont happen.
        CTransaction tx;
        if (GetTxOfAsset(*passetdb, vchAsset, tx)) {
            error( "assetactivate() : this asset is already active with tx %s",
                   tx.GetHash().GetHex().c_str());
            throw runtime_error("this asset is already active");
        }

        EnsureWalletIsUnlocked();

        // Make sure there is a previous asset tx on this asset and that the random value matches
        uint256 wtxInHash;
        if (params.size() == 1) {
            if (!mapMyAssets.count(vchAsset))
                throw runtime_error(
                        "could not find a coin with this asset, try specifying the assetnew transaction id");
            wtxInHash = mapMyAssets[vchAsset];
        } else
            wtxInHash.SetHex(params[1].get_str());
        if (!pwalletMain->mapWallet.count(wtxInHash))
            throw runtime_error("previous transaction is not in the wallet");

        // verify previous txn was asset
        CWalletTx& wtxIn = pwalletMain->mapWallet[wtxInHash];
        vector<unsigned char> vchHash;
        bool found = false;
        BOOST_FOREACH(CTxOut& out, wtxIn.vout) {
            vector<vector<unsigned char> > vvch;
            int op;
            if (DecodeAssetScript(out.scriptPubKey, op, vvch)) {
                if (op != OP_ASSET)
                    throw runtime_error(
                            "previous transaction wasn't asset");
                vchHash = vvch[0]; 
                found = true;
                break;
            }
        }
        if (!found)
            throw runtime_error("Could not decode asset transaction");

        // calculate network fees
        int64 nNetFee = GetAssetNetworkFee(1, pindexBest->nHeight);

        // unserialize asset object from txn, serialize back
        CAsset newAsset;
        if(!newAsset.UnserializeFromTx(wtxIn))
            throw runtime_error(
                    "could not unserialize asset from txn");
        if (newAsset.nOp != XOP_ASSET_NEW)
            throw runtime_error(
                    "previous transaction wasn't asset new");

        newAsset.nOp = XOP_ASSET_ACTIVATE;
        newAsset.vchRand = vchAsset;
        newAsset.nQty = newAsset.nTotalQty;
        newAsset.nFee = nNetFee;

        string bdata = newAsset.SerializeToString();
        vector<unsigned char> vchbdata = vchFromString(bdata);

        // check this hash against previous, ensure they match
        vector<unsigned char> vchToHash(vchRand);
        vchToHash.insert(vchToHash.end(), vchAsset.begin(), vchAsset.end());
        uint160 hash = Hash160(vchToHash);
        if (uint160(vchHash) != hash)
            throw runtime_error("previous tx has a different guid");

        vector<unsigned char> vchAmount = CBigNum(newAsset.nQty).getvch();

        //create assetactivate txn keys
        CPubKey newDefaultKey;
        pwalletMain->GetKeyFromPool(newDefaultKey, false);
        CScript scriptPubKeyOrig;
        scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());
        CScript scriptPubKey;
        scriptPubKey << CScript::EncodeOP_N(OP_ASSET) << vchAsset << vchRand << vchAmount << OP_2DROP << OP_2DROP;
        scriptPubKey += scriptPubKeyOrig;

        // send the transaction
        string strError = SendAssetMoneyWithInputTx(scriptPubKey, MIN_AMOUNT, nNetFee, wtxIn, wtx, false, bdata);
        if (strError != "") throw JSONRPCError(RPC_WALLET_ERROR, strError);

        printf("SENT:ASSETACTIVATE: symbol=%s title=%s amount=%s description=%s rand=%s tx=%s data:\n%s\n",
                stringFromVch(newAsset.vchSymbol).c_str(),
                stringFromVch(newAsset.vchTitle).c_str(),
                stringFromVch(vchAmount).c_str(),
                stringFromVch(newAsset.vchDescription).c_str(),
                stringFromVch(vchAsset).c_str(), 
                wtx.GetHash().GetHex().c_str(),
                stringFromVch(vchbdata).c_str() );
    }
    return wtx.GetHash().GetHex();
}

Value assetsend(const Array& params, bool fHelp) {
    if (fHelp || params.size() != 3)
        throw runtime_error(
                "assetsend <guid> <address> <amount>\n"
                        "Send shares of an asset you control to another address.\n"
                        "<guid> asset guid.\n"
                        "<address> destination syscoin address.\n"
                        "<amount> number of shares to send. minimum 1.\n"
                        + HelpRequiringPassphrase());

    // gather & validate inputs
    vector<unsigned char> vchAsset = vchFromValue(params[0]);
    vector<unsigned char> vchAddress = vchFromValue(params[1]);

    // TODO CB better translation for total quantity
    uint64 nQty = atoi(params[2].get_str().c_str());
    if(nQty < 1) throw runtime_error("Invalid asset quantity.");

    // validate destination address
    // TODO CB enable aliases
    CBitcoinAddress sendAddr(stringFromVch(vchAddress));
    if(!sendAddr.IsValid())
        throw runtime_error("Invalid Syscoin address.");

    // this is a syscoin txn
    CWalletTx wtx, wtxDest;
    wtx.nVersion = SYSCOIN_TX_VERSION;
    wtxDest.nVersion = SYSCOIN_TX_VERSION;

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        if (mapAssetPending.count(vchAsset) && mapAssetPending[vchAsset].size())
            throw runtime_error("there are pending operations on that asset");

        EnsureWalletIsUnlocked();

        // look for a transaction with this key
        CTransaction tx;
        if (!GetTxOfAsset(*passetdb, vchAsset, tx))
            throw runtime_error("could not find an asset with this key");

        // make sure asset is in wallet
        uint256 wtxInHash = tx.GetHash();
        if (!pwalletMain->mapWallet.count(wtxInHash))
            throw runtime_error("this asset is not in your wallet");

        // unserialize asset object from txn
        CAsset theAsset;
        if(!theAsset.UnserializeFromTx(tx))
            throw runtime_error("cannot unserialize asset from txn");

        // get the asset from DB
        vector<CAsset> vtxPos;
        if (!passetdb->ReadAsset(vchAsset, vtxPos))
            throw runtime_error("could not read asset from DB");
        theAsset = vtxPos.back();

        if(theAsset.nQty < nQty) {
            throw runtime_error("insufficient asset quantity");
        }
        // calculate network fees
        int64 nNetFee = GetAssetNetworkFee(2, pindexBest->nHeight);

        // update asset values
        theAsset.nOp   = XOP_ASSET_SEND;
        theAsset.nQty -= nQty;
        theAsset.nFee  = nNetFee;
        theAsset.isChange = true;

        // serialize asset object
        string bdata = theAsset.SerializeToString();

        // get a key from our wallet set dest as ourselves
        CScript scriptPubKeyOrig;
        CPubKey newDefaultKey;
        pwalletMain->GetKeyFromPool(newDefaultKey, false);
        scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());

        vector<unsigned char> vchAmount = CBigNum(theAsset.nQty).getvch();

        // create OP_ASSET txn keys
        CScript scriptPubKey;
        scriptPubKey << CScript::EncodeOP_N(OP_ASSET) << vchAsset << vchAmount << OP_2DROP << OP_DROP;
        scriptPubKey += scriptPubKeyOrig;

        // send the asset change to myself
        CWalletTx& wtxIn = pwalletMain->mapWallet[wtxInHash];
        string strError  = SendAssetMoneyWithInputTx(scriptPubKey, MIN_AMOUNT, nNetFee, wtxIn, wtx, false, bdata);
        if (strError != "") throw JSONRPCError(RPC_WALLET_ERROR, strError);

        // update asset quantities, re-serialize for receiver
        theAsset.nQty     = nQty;
        theAsset.isChange = false;
        bdata 			  = theAsset.SerializeToString();

        vchAmount = CBigNum(theAsset.nQty).getvch();

        // this asset txn goes to receiver
        CScript dscriptPubKeyOrig;
        dscriptPubKeyOrig.SetDestination(sendAddr.Get());
        CScript dscriptPubKey;
        dscriptPubKey << CScript::EncodeOP_N(OP_ASSET) << vchAsset << vchAmount << OP_2DROP << OP_DROP;
        dscriptPubKey += dscriptPubKeyOrig;

        // send the asset to receiver
        strError = pwalletMain->SendMoney(dscriptPubKey, MIN_AMOUNT, wtxDest, false, bdata);
        if (strError != "") throw JSONRPCError(RPC_WALLET_ERROR, strError);

        printf("SENT:ASSETSEND: symbol=%s title=%s amount=%s description=%s guid=%s tx=%s txchange=%s data:\n%s\n",
                stringFromVch(theAsset.vchSymbol).c_str(),
                stringFromVch(theAsset.vchTitle).c_str(),
                stringFromVch(vchAmount).c_str(),
                stringFromVch(theAsset.vchDescription).c_str(),
                stringFromVch(vchAsset).c_str(),
                wtxDest.GetHash().GetHex().c_str(),
                wtx.GetHash().GetHex().c_str(),
                bdata.c_str());
    }
    vector<Value> res;
    res.push_back(wtx.GetHash().GetHex());
    res.push_back(wtxDest.GetHash().GetHex());

    return res;
}

Value assetinfo(const Array& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("assetinfo <rand>\n"
                "Show stored values of an asset.\n");

    Object oLastAsset;
    vector<unsigned char> vchAsset = vchFromValue(params[0]);
    string asset = stringFromVch(vchAsset);
    {
        LOCK(pwalletMain->cs_wallet);

        vector<CAsset> vtxPos;
        if (!passetdb->ReadAsset(vchAsset, vtxPos))
            throw JSONRPCError(RPC_WALLET_ERROR,
                    "failed to read from asset DB");
        if (vtxPos.size() < 1)
            throw JSONRPCError(RPC_WALLET_ERROR, "no result returned");

        // get transaction pointed to by asset
        CTransaction tx;
        uint256 blockHash;
        uint256 txHash = vtxPos.back().txHash;
        if (!GetTransaction(txHash, tx, blockHash, true))
            throw JSONRPCError(RPC_WALLET_ERROR, "failed to read transaction from disk");

        CAsset theAsset = vtxPos.back();

        Object oAsset;
        vector<unsigned char> vchValue;
        int nHeight;
        uint256 assetHash;
        if (GetValueOfAssetTxHash(txHash, vchValue, assetHash, nHeight)) {
            oAsset.push_back(Pair("id", asset));
            oAsset.push_back(Pair("txid", tx.GetHash().GetHex()));
            string strAddress = "";
            GetAssetAddress(tx, strAddress);
            oAsset.push_back(Pair("address", strAddress));
            oAsset.push_back(Pair("value", stringFromVch(vchValue)));
            oAsset.push_back(Pair("symbol", stringFromVch(theAsset.vchSymbol)));
            oAsset.push_back(Pair("title", stringFromVch(theAsset.vchTitle)));
            oAsset.push_back(Pair("description", stringFromVch(theAsset.vchDescription)));
            oAsset.push_back(Pair("total_quantity", strprintf("%llu", theAsset.nTotalQty)));
            if(IsAssetMine(tx))
                oAsset.push_back(Pair("quantity", strprintf("%llu", theAsset.nQty)));
            else
                oAsset.push_back(Pair("quantity", "0"));

            oLastAsset = oAsset;
        }
    }
    return oLastAsset;

}

Value assetlist(const Array& params, bool fHelp) {
    if (fHelp || 1 < params.size())
        throw runtime_error("assetlist [<asset>]\n"
                "list my own assets");

    vector<unsigned char> vchName;

    if (params.size() == 1)
        vchName = vchFromValue(params[0]);

    vector<unsigned char> vchNameUniq;
    if (params.size() == 1)
        vchNameUniq = vchFromValue(params[0]);

    Array oRes;
    map< vector<unsigned char>, int > vNamesI;
    map< vector<unsigned char>, Object > vNamesO;

    {
        LOCK(pwalletMain->cs_wallet);

        uint256 blockHash;
        uint256 hash;
        CTransaction tx;

        vector<unsigned char> vchValue;
        int nHeight;

        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet)
        {
            // get txn hash, read txn index
            hash = item.second.GetHash();

            if (!GetTransaction(hash, tx, blockHash, true))
                continue;

            // skip non-syscoin txns
            if (tx.nVersion != SYSCOIN_TX_VERSION)
                continue;

            // decode txn, skip non-asset txns
            vector<vector<unsigned char> > vvch;
            int op, nOut;
            if (!DecodeAssetTx(tx, op, nOut, vvch, -1) || !IsAssetOp(op)) 
                continue;

            // get the txn height
            nHeight = GetAssetTxHashHeight(hash);

            // get the txn asset name
            if(!GetNameOfAssetTx(tx, vchName))
                continue;

            // skip this asset if it doesn't match the given filter value
            if(vchNameUniq.size() > 0 && vchNameUniq != vchName)
                continue;

            // get the value of the asset txn
            if(!GetValueOfAssetTx(tx, vchValue))
                continue;

            // build the output object
            Object oName;
            oName.push_back(Pair("name", stringFromVch(vchName)));
            oName.push_back(Pair("value", stringFromVch(vchValue)));
            
            string strAddress = "";
            GetAssetAddress(tx, strAddress);
            oName.push_back(Pair("address", strAddress));

            // get last active name only
            if(vNamesI.find(vchName) != vNamesI.end() && vNamesI[vchName] > nHeight)
                continue;

            vNamesI[vchName] = nHeight;
            vNamesO[vchName] = oName;
        }
    }

    BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, Object)& item, vNamesO)
        oRes.push_back(item.second);

    return oRes;
}

Value assethistory(const Array& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("assethistory <asset>\n"
                "List all stored values of an asset.\n");

    Array oRes;
    vector<unsigned char> vchAsset = vchFromValue(params[0]);
    string asset = stringFromVch(vchAsset);

    {
        LOCK(pwalletMain->cs_wallet);

        vector<CAsset> vtxPos;
        if (!passetdb->ReadAsset(vchAsset, vtxPos))
            throw JSONRPCError(RPC_WALLET_ERROR,
                    "failed to read from asset DB");

        CAsset txPos2;
        uint256 txHash;
        uint256 blockHash;
        BOOST_FOREACH(txPos2, vtxPos) {
            txHash = txPos2.txHash;
            CTransaction tx;
            if (!GetTransaction(txHash, tx, blockHash, true)) {
                error("could not read txpos");
                continue;
            }

            Object oAsset;
            vector<unsigned char> vchValue;
            int nHeight;
            uint256 hash;
            if (GetValueOfAssetTxHash(txHash, vchValue, hash, nHeight)) {
                oAsset.push_back(Pair("asset", asset));
                string value = stringFromVch(vchValue);
                oAsset.push_back(Pair("value", value));
                oAsset.push_back(Pair("txid", tx.GetHash().GetHex()));
                string strAddress = "";
                GetAssetAddress(tx, strAddress);
                oAsset.push_back(Pair("address", strAddress));
                oAsset.push_back(
                        Pair("expires_in",
                                nHeight + GetAssetDisplayExpirationDepth(nHeight)
                                        - pindexBest->nHeight));
                if (nHeight + GetAssetDisplayExpirationDepth(nHeight)
                        - pindexBest->nHeight <= 0) {
                    oAsset.push_back(Pair("expired", 1));
                }
                oRes.push_back(oAsset);
            }
        }
    }
    return oRes;
}

Value assetfilter(const Array& params, bool fHelp) {
    if (fHelp || params.size() > 5)
        throw runtime_error(
                "assetfilter [[[[[regexp] maxage=36000] from=0] nb=0] stat]\n"
                        "scan and filter assets\n"
                        "[regexp] : apply [regexp] on assets, empty means all assets\n"
                        "[maxage] : look in last [maxage] blocks\n"
                        "[from] : show results from number [from]\n"
                        "[nb] : show [nb] results, 0 means all\n"
                        "[stats] : show some stats instead of results\n"
                        "assetfilter \"\" 5 # list assets updated in last 5 blocks\n"
                        "assetfilter \"^asset\" # list all assets starting with \"asset\"\n"
                        "assetfilter 36000 0 0 stat # display stats (number of assets) on active assets\n");

    string strRegexp;
    int nFrom = 0;
    int nNb = 0;
    int nMaxAge = 36000;
    bool fStat = false;
    int nCountFrom = 0;
    int nCountNb = 0;

    if (params.size() > 0)
        strRegexp = params[0].get_str();

    if (params.size() > 1)
        nMaxAge = params[1].get_int();

    if (params.size() > 2)
        nFrom = params[2].get_int();

    if (params.size() > 3)
        nNb = params[3].get_int();

    if (params.size() > 4)
        fStat = (params[4].get_str() == "stat" ? true : false);

    Array oRes;

    vector<unsigned char> vchAsset;
    vector<pair<vector<unsigned char>, CAsset> > assetScan;
    if (!passetdb->ScanAssets(vchAsset, 100000000, assetScan))
        throw JSONRPCError(RPC_WALLET_ERROR, "scan failed");

    pair<vector<unsigned char>, CAsset> pairScan;
    BOOST_FOREACH(pairScan, assetScan) {
        string asset = stringFromVch(pairScan.first);

        // regexp
        using namespace boost::xpressive;
        smatch assetparts;
        sregex cregex = sregex::compile(strRegexp);
        if (strRegexp != "" && !regex_search(asset, assetparts, cregex))
            continue;

        CAsset txAsset = pairScan.second;
        int nHeight = txAsset.nHeight;

        // max age
        if (nMaxAge != 0 && pindexBest->nHeight - nHeight >= nMaxAge)
            continue;

        // from limits
        nCountFrom++;
        if (nCountFrom < nFrom + 1)
            continue;

        Object oAsset;
        oAsset.push_back(Pair("asset", asset));
        CTransaction tx;
        uint256 blockHash;
        uint256 txHash = txAsset.txHash;
        if ((nHeight + GetAssetDisplayExpirationDepth(nHeight) - pindexBest->nHeight
                <= 0) || !GetTransaction(txHash, tx, blockHash, true)) {
            oAsset.push_back(Pair("expired", 1));
        } else {
            vector<unsigned char> vchValue = txAsset.vchTitle;
            string value = stringFromVch(vchValue);
            oAsset.push_back(Pair("value", value));
            oAsset.push_back(
                    Pair("expires_in",
                            nHeight + GetAssetDisplayExpirationDepth(nHeight)
                                    - pindexBest->nHeight));
        }
        oRes.push_back(oAsset);

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

Value assetscan(const Array& params, bool fHelp) {
    if (fHelp || 2 > params.size())
        throw runtime_error(
                "assetscan [<start-asset>] [<max-returned>]\n"
                        "scan all assets, starting at start-asset and returning a maximum number of entries (default 500)\n");

    vector<unsigned char> vchAsset;
    int nMax = 500;
    if (params.size() > 0) {
        vchAsset = vchFromValue(params[0]);
    }

    if (params.size() > 1) {
        Value vMax = params[1];
        ConvertTo<double>(vMax);
        nMax = (int) vMax.get_real();
    }

    Array oRes;

    vector<pair<vector<unsigned char>, CAsset> > assetScan;
    if (!passetdb->ScanAssets(vchAsset, nMax, assetScan))
        throw JSONRPCError(RPC_WALLET_ERROR, "scan failed");

    pair<vector<unsigned char>, CAsset> pairScan;
    BOOST_FOREACH(pairScan, assetScan) {
        Object oAsset;
        string asset = stringFromVch(pairScan.first);
        oAsset.push_back(Pair("asset", asset));
        CTransaction tx;
        CAsset txAsset = pairScan.second;
        uint256 blockHash;

        int nHeight = txAsset.nHeight;
        vector<unsigned char> vchValue = txAsset.vchTitle;
        if ((nHeight + GetAssetDisplayExpirationDepth(nHeight) - pindexBest->nHeight
                <= 0) || !GetTransaction(txAsset.txHash, tx, blockHash, true)) {
            oAsset.push_back(Pair("expired", 1));
        } else {
            string value = stringFromVch(vchValue);
            //string strAddress = "";
            //GetCertAddress(tx, strAddress);
            oAsset.push_back(Pair("value", value));
            //oAsset.push_back(Pair("txid", tx.GetHash().GetHex()));
            //oAsset.push_back(Pair("address", strAddress));
            oAsset.push_back(
                    Pair("expires_in",
                            nHeight + GetAssetDisplayExpirationDepth(nHeight)
                                    - pindexBest->nHeight));
        }
        oRes.push_back(oAsset);
    }

    return oRes;
}


 Value assetclean(const Array& params, bool fHelp)
 {
     if (fHelp || params.size())
     throw runtime_error("asset_clean\nClean unsatisfiable transactions from the wallet\n");


     {
         LOCK2(cs_main,pwalletMain->cs_wallet);
         map<uint256, CWalletTx> mapRemove;

         printf("-----------------------------\n");

         {
             BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet)
             {
                 CWalletTx& wtx = item.second;
                 vector<unsigned char> vchAsset;
                 if (wtx.GetDepthInMainChain() < 1 && IsConflictedAssetTx(*pblocktree, wtx, vchAsset))
                 {
                     uint256 hash = wtx.GetHash();
                     mapRemove[hash] = wtx;
                 }
             }
         }

         bool fRepeat = true;
         while (fRepeat)
         {
             fRepeat = false;
             BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet)
             {
                 CWalletTx& wtx = item.second;
                 BOOST_FOREACH(const CTxIn& txin, wtx.vin)
                 {
                     uint256 hash = wtx.GetHash();

                     // If this tx depends on a tx to be removed, remove it too
                     if (mapRemove.count(txin.prevout.hash) && !mapRemove.count(hash))
                     {
                         mapRemove[hash] = wtx;
                         fRepeat = true;
                     }
                 }
             }
         }

         BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapRemove)
         {
             CWalletTx& wtx = item.second;

             UnspendInputs(wtx);
             wtx.RemoveFromMemoryPool();
             pwalletMain->EraseFromWallet(wtx.GetHash());
             vector<unsigned char> vchAsset;
             if (GetNameOfAssetTx(wtx, vchAsset) && mapAssetPending.count(vchAsset))
             {
                 string asset = stringFromVch(vchAsset);
                 printf("asset_clean() : erase %s from pending of asset %s",
                 wtx.GetHash().GetHex().c_str(), asset.c_str());
                 if (!mapAssetPending[vchAsset].erase(wtx.GetHash()))
                     error("asset_clean() : erase but it was not pending");
             }
             wtx.print();
         }

         printf("-----------------------------\n");
     }

     return true;
 }

