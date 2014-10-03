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

CCriticalSection cs_assetmaps;

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

extern void ListTransactions(const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret);

bool IsAssetOp(int op) {
    return op == OP_ASSET;
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
    case XOP_ASSET_SEND:
        return "assetsend";
    case XOP_ASSET_PEG:
        return "assetpeg";
    case XOP_ASSET_UPDATE:
        return "assetupdate";                
    case XOP_ASSET_GENERATE:
        return "assetgenerate";                
    case XOP_ASSET_DISSOLVE:
        return "assetdissolve";                              
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

string CAsset::toString() {
	return strprintf(
			"ASSET %s %s %f | "
			"SYMBOL: %s, "
			"TITLE: %s, "
			"DESC: %s, "
			"TOTAL QUANTITY: %f, "
			"COINS PER SHARE: %f, "
			"QUANTITY: %f | "
			"OP: %s, "
			"IS CHANGE: %s, "
			"CHANGE TXID: %s, "
			"IS GEN: %s, "
			"GEN TXID: %s, "
			"FEE: %f | "
			"TXID: %s, "
			"HEIGHT: %llu, "
			"TIME: %llu, "
			"NOUT: %llu\n",
			assetFromOp(nOp).c_str(),
			stringFromVch(vchSymbol).c_str(),
			ValueFromAmount(nQty).get_real(),
			stringFromVch(vchSymbol).c_str(),
			stringFromVch(vchTitle).c_str(),
			stringFromVch(vchDescription).c_str(),
			ValueFromAmount(nTotalQty).get_real(),
			ValueFromAmount(nCoinsPerShare).get_real(),
			((double)nQty/(double)nCoinsPerShare),
			assetFromOp(nOp).c_str(),
			(isChange?"true":"false"),
			(changeTxHash != 0 ? changeTxHash.GetHex().c_str() : "0"),
			(isGenerate?"true":"false"),
			(genTxHash != 0 ? genTxHash.GetHex().c_str() : "0"),
			ValueFromAmount(nFee).get_real(),
			txHash.GetHex().c_str(),
			nHeight,
			nTime,
			n );
}

bool CAsset::GetAsset(vector<unsigned char> &vchSymbol) {
    bool found = false;
    vector<CAsset> vtxPos;
    if (passetdb->ExistsAsset(vchSymbol)) {
        if (!passetdb->ReadAsset(vchSymbol, vtxPos)) {
            if(vtxPos.size()) {
                *this = vtxPos.back();
                found = true;
            }
        }
    }    
    return found;    
}


//TODO this is all completely broken in terms of given rsults
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

            // get the transaction
            if(!GetTransaction(tx.GetHash(), tx, txblkhash, true))
                continue;

            // attempt to read asset from txn
            CAsset txAsset, serializedAsset;
            if(!txAsset.UnserializeFromTx(tx))
                return error("ReconstructAssetIndex() : failed to unserialize asset from tx");
            serializedAsset = txAsset;

            uint64 xop = serializedAsset.nOp;

            vector<unsigned char> vchSymbol = txAsset.vchSymbol;

            // read asset from DB if it exists
            vector<CAsset> vtxPos;
            if (!ReadAsset(vchSymbol, vtxPos))
                return error("ReconstructAssetIndex() : failed to read asset from DB");

            if(vtxPos.size()!=0) {
                txAsset.GetAssetFromList(vtxPos);
            }

            // insert asset fees to regenerate list, write asset to master index
            int64 nTheFee = GetAssetNetFee(tx);
            InsertAssetFee(pindex, tx.GetHash(), txAsset.nOp, nTheFee);

            switch(xop) {
                case XOP_ASSET_NEW:
                    txAsset.nTotalQty = serializedAsset.nTotalQty;
                    break;
                case XOP_ASSET_SEND:
                    break;
                case XOP_ASSET_PEG:
                    txAsset.nCoinsPerShare = serializedAsset.nCoinsPerShare;
                    break;
                case XOP_ASSET_UPDATE:
                    txAsset.vchDescription = serializedAsset.vchDescription;
                    break;
                case XOP_ASSET_GENERATE:
                    txAsset.nTotalQty += serializedAsset.nQty;
                    break;
                case XOP_ASSET_DISSOLVE:
                    txAsset.nTotalQty -= serializedAsset.nQty;
                    break;
                default:
                    return error("ReconstructAssetIndex() : unknown asset op");
            }      

            if(serializedAsset.nOp != XOP_ASSET_SEND){
                txAsset.nOp = serializedAsset.nOp;
                txAsset.txHash = tx.GetHash();
                txAsset.nHeight = nHeight;
                txAsset.nTime = pindex->nTime;
                txAsset.isChange = serializedAsset.isChange;
                txAsset.changeTxHash = serializedAsset.changeTxHash;

                txAsset.PutToAssetList(vtxPos);

                if (!WriteAsset(vchSymbol, vtxPos))
                    return error("ReconstructAssetIndex() : failed to write to asset DB");

                printf( "RECONSTRUCT: %s\n", txAsset.toString().c_str());
            }
        }
        pindex = pindex->pnext;
        Flush();
    }
    }
    return true;
}

int CheckAssetTransactionAtRelativeDepth(CBlockIndex* pindexBlock, int target, int maxDepth) {

	if(maxDepth == -1){
		for (CBlockIndex* pindex = pindexBlock;
				pindex;
				pindex = pindex->pprev)
			if (pindex->nHeight == target)
				return pindexBlock->nHeight - pindex->nHeight;
	} else {
		for (CBlockIndex* pindex = pindexBlock;
				pindex && pindexBlock->nHeight - pindex->nHeight < maxDepth;
				pindex = pindex->pprev)
			if (pindex->nHeight == target)
				return pindexBlock->nHeight - pindex->nHeight;
	}

    return -1;
}

int GetAssetTxHashHeight(const uint256 txHash) {
    CDiskTxPos postx;
    pblocktree->ReadTxIndex(txHash, postx);
	return GetNameTxPosHeight(postx);
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
    if((nHeight - blk12hrht) + 1 == 0) {
    	return 0;
    }
    hr12 /= (nHeight - blk12hrht) + 1;
    hr1 /= (nHeight - blk1hrht) + 1;
    uint64 nSubsidyOut = hr1 > hr12 ? hr1 : hr12;
    return nSubsidyOut;
}

bool InsertAssetFee(CBlockIndex *pindex, uint256 hash, int nOp, uint64 nValue) {
    list<CAssetFee> txnDup;
    CAssetFee oFee;
    oFee.nTime = pindex->nTime;
    oFee.nHeight = pindex->nHeight;
    oFee.nOp = nOp;
    oFee.nFee = nValue;
    bool bFound = false;

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

int64 GetAssetHeight(vector<unsigned char> vchAsset) {
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
    
    if(vvchArgs.size()==0)
        return error("GetNameOfAssetTx() : no script values");

	asset = vvchArgs[0];
	return true;
}

bool GetValueOfAssetTx(const CTransaction& tx, vector<unsigned char>& value) {
    if (tx.nVersion != SYSCOIN_TX_VERSION)
        return false;

    vector<vector<unsigned char> > vvch;
    int op, nOut;

    if (!DecodeAssetTx(tx, op, nOut, vvch, -1))
        return false;

    if(!IsAssetOp(op)) return false;

    if(vvch.size()==0)
        return error("GetValueOfAssetTx() : no script values");

    value = vvch[vvch.size()-1];
    return true;
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

    if (IsMyAsset(tx, txout)) {
        printf("IsAssetMine() : found my transaction %s value %d\n",
                tx.GetHash().GetHex().c_str(), (int) txout.nValue);
        return true;
    }
    return false;
}

bool IsConflictedAssetTx(CBlockTreeDB& txdb, const CTransaction& tx, vector<unsigned char>& name) {
    if (tx.nVersion != SYSCOIN_TX_VERSION)
        return false;
    vector<vector<unsigned char> > vvchArgs;
    int op;
    int nOut;

    bool good = DecodeAssetTx(tx, op, nOut, vvchArgs, pindexBest->nHeight);
    if (!good)
        return error("IsConflictedAliasTx() : could not decode a syscoin tx");
    //int nPrevHeight;

    // TODO CB fix orkill this method
    // switch (op) {
    //     case OP_ALIAS_ACTIVATE:
    //         nPrevHeight = GetAssetHeight(vvchArgs[0]);
    //         name = vvchArgs[0];
    //         if (nPrevHeight >= 0 && pindexBest->nHeight - nPrevHeight < GetAliasExpirationDepth(pindexBest->nHeight))
    //             return true;
    // }
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
    vchValue = vchFromString(ValueFromAmount(txPos.nQty).get_str());
    return true;
}

bool GetTxOfAsset(CAssetDB& dbAsset, const vector<unsigned char> &vchAsset, CTransaction& tx) {
    vector<CAsset> vtxPos;
    if (!passetdb->ReadAsset(vchAsset, vtxPos) || vtxPos.empty())
        return false;

    CAsset& txPos = vtxPos.back();
    uint256 hashBlock;
    if (!GetTransaction(txPos.txHash, tx, hashBlock, true))
        return error("GetTxOfAsset() : could not read tx from disk");
    return true;
}

bool GetTxOfAssetSend(CAssetDB& dbAsset, const vector<unsigned char> &vchAsset, CTransaction& tx) {
    vector<CAsset> vtxPos;
    if (!passetdb->ReadAsset(vchAsset, vtxPos) || vtxPos.empty())
        return false;

    BOOST_REVERSE_FOREACH(CAsset &txPos, vtxPos) {
        if( txPos.nOp == XOP_ASSET_SEND ) {

			uint256 hashBlock;
			if (GetTransaction(txPos.txHash, tx, hashBlock, true))
				return true;
        }
    }
    return error("GetTxOfAssetSend() : could not read tx from disk");
}

bool GetTxOfAssetControl(CAssetDB& dbAsset, const vector<unsigned char> &vchAsset, CTransaction& tx) {
    vector<CAsset> vtxPos;
    if (!passetdb->ReadAsset(vchAsset, vtxPos) || vtxPos.empty())
        return false;

    BOOST_REVERSE_FOREACH(CAsset &txPos, vtxPos) {
        if( txPos.nOp == XOP_ASSET_PEG
         || txPos.nOp != XOP_ASSET_UPDATE ) {

			uint256 hashBlock;
			if (GetTransaction(txPos.txHash, tx, hashBlock, true))
				return true;
        }
    }
    return error("GetTxOfAssetControl() : could not read tx from disk");
}

bool DecodeAssetTx(const CTransaction& tx, int& op, int& nOut, vector<vector<unsigned char> >& vvch, int nHeight) {
    bool found = false;
    if (nHeight < 0)
        nHeight = pindexBest->nHeight;
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        vector<vector<unsigned char> > vvchRead;
        if (DecodeAssetScript(out.scriptPubKey, op, vvchRead)) {
            nOut = i;
            found = true;
            vvch = vvchRead;
            break;
        }
    }
    if (!found) vvch.clear();
    return found && IsAssetOp(op);
}

bool DecodeAssetTx(const CCoins& tx, int& op, int& nOut, vector<vector<unsigned char> >& vvch, int nHeight) {
    bool found = false;
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        vector<vector<unsigned char> > vvchRead;
        if (DecodeAssetScript(out.scriptPubKey, op, vvchRead)) {
            nOut = i;
            found = true;
            vvch = vvchRead;
            break;
        }
    }
    if (!found) vvch.clear();
    return found && IsAssetOp(op);
}

bool CAsset::IsAssetChange(uint160 compareHash) {

	return true;
	if(IsNull()) return false;

	CAsset theAsset = *this;

	theAsset.nOp 		  = XOP_ASSET_SEND;
	theAsset.isChange 	  = true;
	theAsset.changeTxHash = theAsset.txHash;
	uint160 theHash 	  = Hash160(vchFromString(theAsset.SerializeToString()));

	printf("IsAssetChange: %s\n", theAsset.toString().c_str());

	return (theHash==compareHash);
}

bool CAsset::IsGenesisAsset(uint160 compareHash) {

	if(IsNull()) return false;

	CAsset theAsset = *this;

	printf("IsGenesisAsset: BEFORE %s\n", theAsset.toString().c_str());

	theAsset.nOp 		= XOP_ASSET_NEW;
	theAsset.isGenerate = true;
	theAsset.genTxHash  = theAsset.txHash;
	theAsset.nQty 		= theAsset.nTotalQty;
	uint160 theHash  	= Hash160(vchFromString(theAsset.SerializeToString()));

	printf("IsGenesisAsset: AFTER %s\n", theAsset.toString().c_str());

	return (theHash==compareHash);
}

bool DecodeAssetTxExtraCoins(const CTransaction& tx, int& op, int& nOut, vector<vector<unsigned char> >& vvch, int nHeight) {
    bool found = false;
    if (nHeight < 0)
        nHeight = pindexBest->nHeight;
    CAsset theAsset(tx);

    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        vector<vector<unsigned char> > vvchRead;
        if (DecodeAssetScript(out.scriptPubKey, op, vvchRead)) {
        	uint160 theHash = uint160(vvchRead[1]);
        	if ( theAsset.IsGenesisAsset ( theHash )
        	   || theAsset.IsAssetChange ( theHash ) ) {
				nOut = i;
				found = true;
				vvch = vvchRead;
				break;
        	}
        }
    }
    if (!found) vvch.clear();
    return found;
}

bool DecodeAssetScript(const CScript& script, int& op, vector<vector<unsigned char> > &vvch) {
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

bool SignAssetSignature(const CTransaction& txFrom, CTransaction& txTo, unsigned int nIn, int nHashType = SIGHASH_ALL) {
    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    // Leave out the signature from the hash, since a signature can't sign itself.
    // The checksig op will also drop the signatures from its hash.
    const CScript& scriptPubKey = RemoveAssetScriptPrefix(txout.scriptPubKey);
    uint256 hash = SignatureHash(txout.scriptPubKey, txTo, nIn, nHashType);
    txnouttype whichTypeRet;

    // verify our signature
    if (!Solver(*pwalletMain, scriptPubKey, hash, nHashType, txin.scriptSig, whichTypeRet))
        return false;

    // Test the solution
    if (!VerifyScript(txin.scriptSig, txout.scriptPubKey, txTo, nIn, 0, 0)) {
    	printf("SignAssetSignature failed");
    	return false;
    }
    return true;
}

bool GetValueOfAssetTx(const CCoins& tx, vector<unsigned char>& value) {
    vector<vector<unsigned char> > vvch;

    int op, nOut;

    if (!DecodeAssetTx(tx, op, nOut, vvch, -1))
        return false;

    if(!IsAssetOp(op)) 
        return false;

    value = vvch[vvch.size()-1];
    return true;
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

    DecodeAssetScript(scriptIn, op, vvch, pc);
    
    return CScript(pc, scriptIn.end());
}

string CAsset::SendToDestination ( CWalletTx& wtxNew, const vector<unsigned char> *pvchAddress ) {

	int64 nAssetBalance = pwalletMain->GetAssetBalance(vchSymbol);
	int64 nAssetValue   = nQty;
	int64 nAssetChange  = nOp == XOP_ASSET_SEND ? nAssetBalance - nAssetValue : 0;

	// vector for all destinations
    vector<pair<CScript,int64> > vecSend;

    // serialize, hash asset data
    vector<vector<unsigned char> > vvchInputArgs;
    vvchInputArgs.push_back(vchSymbol);
    vvchInputArgs.push_back(CBigNum(nAssetValue).getvch());

    CScript assetSendScript;

    // main script for sending to dest
    CReserveKey reserveKey(pwalletMain);
    if(pvchAddress != NULL) {
        CBitcoinAddress sendAddr(stringFromVch(*pvchAddress));
        CTxDestination txDest = sendAddr.Get();
        assetSendScript = CreateAssetScript(
        		vvchInputArgs,
        		Hash160(vchFromString(SerializeToString())),
        		NULL,
        		&txDest);
    } else {
        // Reserve a new key from key pool
        CPubKey pubkeySend;
        assert(reserveKey.GetReservedKey(pubkeySend));
        CKeyID pkey = pubkeySend.GetID();
        assetSendScript = CreateAssetScript(
        		vvchInputArgs,
        		Hash160(vchFromString(SerializeToString())),
        		&pkey);
    }
    vecSend.push_back(make_pair(assetSendScript, nQty));

    printf("SendToDestination:%s\n", toString().c_str());

    // if there is any asset change, send change to ourselves
    if(nOp == XOP_ASSET_NEW) {

    	CAsset theAsset = *this;

    	// with change set to true and transaction ID
    	theAsset.isGenerate = true;
    	theAsset.genTxHash  = theAsset.txHash;
    	theAsset.nQty 	    = theAsset.nTotalQty;

    	// create the input vector for our script args
        vector<vector<unsigned char> > vvchInputArgs;
        vvchInputArgs.push_back(theAsset.vchSymbol);
        vvchInputArgs.push_back(CBigNum(theAsset.nTotalQty).getvch());

        printf("SendToDestination GENESIS:%s\n", toString().c_str());

        // Reserve a new key from key pool
        CPubKey pubkeyChange;
        assert(reserveKey.GetReservedKey(pubkeyChange));
        CKeyID pkey = pubkeyChange.GetID();

        // create the asset send transaction script and add to vector
        CScript assetChangeScript = CreateAssetScript(
        		vvchInputArgs,
        		Hash160(vchFromString(theAsset.SerializeToString())),
        		&pkey);
    	vecSend.push_back(make_pair(assetChangeScript, theAsset.nQty));

    	nAssetValue = theAsset.nTotalQty + COIN;
    }

    // if there is any asset change, send change to ourselves
    if(nAssetChange > 0) {

    	CAsset theAsset = *this;

    	// this transaction's hash is the asset object
    	// with change set to true and transaction ID
    	theAsset.isChange = true;
    	theAsset.changeTxHash = theAsset.txHash;

    	// create the input vector for our script args
        vector<vector<unsigned char> > vvchInputArgs;
        vvchInputArgs.push_back(theAsset.vchSymbol);
        vvchInputArgs.push_back(CBigNum(nAssetChange).getvch());

        // Reserve a new key from key pool
        CPubKey pubkey;
        assert(reserveKey.GetReservedKey(pubkey));
        CKeyID pkey = pubkey.GetID();
        // create the asset send transaction script and add to vector
        CScript assetChangeScript = CreateAssetScript(
        		vvchInputArgs,
        		Hash160(vchFromString(theAsset.SerializeToString())),
        		&pkey);
    	vecSend.push_back(make_pair(assetChangeScript, nAssetChange));
    }

    // get the service fee to send this transaction and create
    // a script burning those fees if the fee is non-zero
    int64 nServiceFee = GetServiceFee(2, pindexBest->nHeight);
    if (nServiceFee != 0) {
        CScript scriptFee;
        scriptFee << OP_RETURN;
        vecSend.push_back(make_pair(scriptFee, nServiceFee));
    }

    int64 nFeeRequired;

    // create the asset transaction. return with an error
    // message if the transaction has failed creation
//    if (!CreateTransaction(vecSend, wtxNew, reserveKey, nFeeRequired)) {
//        string strError = strprintf(_(
//			"Error: This transaction requires a transaction fee "
//			"of at least %s because of its amount, complexity, or "
//			"use of recently received funds "), FormatMoney(nFeeRequired).c_str());
//        return strError;
//    }
//    return "";


    // create the asset transaction. return with an error
    // message if the transaction has failed creation
    if (!CreateTransaction(vecSend, wtxNew, reserveKey, nFeeRequired)) {
        string strError = strprintf(_(
			"Error: This transaction requires a transaction fee "
			"of at least %s because of its amount, complexity, or "
			"use of recently received funds "), FormatMoney(nFeeRequired).c_str());
        return strError;
    }

    // commit the transaction to the database
	if (!pwalletMain->CommitTransaction(wtxNew, reserveKey))
		return _(
				"Error: The transaction was rejected.  This might "
				"happen if some of the coins in your wallet were "
				"already spent, such as if you used a copy of "
				"wallet.dat and coins were spent in the copy but "
				"not marked as spent here.");
    return "";
}


bool CAsset::CreateTransaction(
    const std::vector<std::pair<CScript, int64> >& vecSend, 
    CWalletTx& wtxNew, 
    CReserveKey& reservekey, 
    int64& nFeeRet, 
    bool bIsFromMe) {

    // add up the value of all output scripts. this is our value out for the transaction
    int64 nValue = 0;
    BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend) {
        if (nValue < 0)  return false;
        nValue += s.second;
    }
    if (vecSend.empty() || nValue < 0)
        return false;

    int64 nBaseValue = nQty + (nOp == XOP_ASSET_NEW ? nTotalQty : 0 );
    assert(nValue == nBaseValue);

    wtxNew.data = vchFromString(SerializeToString().c_str());

    wtxNew.BindWallet(pwalletMain);
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        nFeeRet = nTransactionFee;
        loop {
            int64 nTotalValue = nBaseValue + nFeeRet;

        	printf("CreateAssetTransaction: total value = %s\n", FormatMoney(nTotalValue).c_str());
            double dPriority = 0;

            // clear txn inputs and outputs
            wtxNew.vin.clear();
            wtxNew.vout.clear();
            wtxNew.fFromMe = bIsFromMe;

            // fill vouts with the payee scripts
            BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
                wtxNew.vout.push_back(CTxOut(s.second, s.first));

            vector<pair<const CWalletTx*,unsigned int> > vecCoins;
            set<pair<const CWalletTx*, unsigned int> > setCoins;
            vector<const CWalletTx*> vecAssetCoins;
            int64 nValueIn = 0,
            	  nStdCoinsIn = 0,
            	  nAssetCoinsIn = 0,
            	  nControlCoinsIn = 0;
            bool isControlOp = nOp != XOP_ASSET_SEND;
            bool isNewOp = nOp == XOP_ASSET_NEW;

            if (nTotalValue > 0) {

            	bool bRet;
            	if(isNewOp)
            		// asset coins and fee come out of regular balance
            		// for newly-created asset classes
            		bRet = pwalletMain->SelectCoins(
            				nTotalValue,
            				setCoins,
            				nStdCoinsIn);
            	else {
            		// asset control ops require an exiating asset contro
            		// coin to exist in order to create a txn
                 	if(isControlOp)
                 		bRet = pwalletMain->SelectAssetControlCoins(
                 				vchSymbol,
                 				COIN,
                 				setCoins,
                 				nAssetCoinsIn);
                 	// asset send ops require existing asset coins
                 	// in quantity equal to or greater than the send amt
					else bRet = pwalletMain->SelectAssetCoins(
							vchSymbol,
							nBaseValue,
							setCoins,
							nControlCoinsIn);

                 	// add these coins to a tracking vector. We use this later
                 	// to ensure that coins returned to pay fees are not duplicated
                 	if(bRet) {
						BOOST_FOREACH(const PAIRTYPE(const CWalletTx *, unsigned int)& coin, setCoins)
							vecAssetCoins.push_back(coin.first);
                 	}
            	}
            	if(!bRet) return false;

            	// sum the returned coins
            	nValueIn = nStdCoinsIn
            			 + nAssetCoinsIn
            			 + nControlCoinsIn;

                // gather a list of the previous asset coins we need to
                // successfully send this asset send transaction
                vecCoins.insert(vecCoins.end(), setCoins.begin(), setCoins.end());
                printf( "CreateAssetTransaction: selected %d coins for %s\n",
                    (int) setCoins.size(), FormatMoney(nValueIn).c_str());

                // if there's a fee to pay, and the total value of the
                // returned coins is less than the total value of the outputs
            	// then select additional coins for use for the fee
                if(nFeeRet != 0 && nValueIn <= nTotalValue) {
                	int64 nFeeValueIn;
                	if(!pwalletMain->SelectCoins(nFeeRet, setCoins, nFeeValueIn, NULL, false))
                		return false;

                	BOOST_FOREACH(const PAIRTYPE(const CWalletTx *, unsigned int)& coin, setCoins) {
						// add the txn to our to-check-for-dupes list
						vecCoins.push_back(coin);
						printf( "CreateAssetTransaction: selected %d tx outs for fee %s\n",
							(int) setCoins.size(), FormatMoney(nFeeRet).c_str());
                	}

					nValueIn += nFeeValueIn;
					printf( "CreateAssetTransaction: selected %d coins for fee %s\n",
						(int) setCoins.size(), FormatMoney(nFeeRet).c_str());
                }

            } 

            // iterate through coins to calculate priority
            BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
                int64 nCredit = coin.first->vout[coin.second].nValue;
                dPriority += (double) nCredit * coin.first->GetDepthInMainChain();
            }

            // Fill a vout back to self with any change
            int64 nChange = nValueIn - nTotalValue;
            bool thereIsChange = nChange >= CENT;
            if (thereIsChange) {
                // Reserve a new key pair from key pool
                CPubKey pubkey;
                //assert(reservekey.GetReservedKey(pubkey));
            	pwalletMain->GetKeyFromPool(pubkey, false);

                // Fill a vout to ourself, using same address type as the payment
                // Now sending always to hash160 (GetBitcoinAddressHash160 will
                // return hash160, even if pubkey is used)
                CScript scriptChange;
                if (Hash160(vecSend[0].first) != 0)
                    scriptChange.SetDestination(pubkey.GetID());
                else
                    scriptChange << pubkey << OP_CHECKSIG;
                // Insert change txn at end of list
                vector<CTxOut>::iterator position = wtxNew.vout.begin() + GetRandInt ( wtxNew.vout.size() + vecSend.size());
                wtxNew.vout.push_back(CTxOut(nChange, scriptChange));
            } else
                reservekey.ReturnKey();

            // Fill vin of txn with input coins
            BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
                wtxNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second));
                printf( "CreateAssetTransaction: filling vin (%s), pos = %d\n",
                    coin.first->GetHash().GetHex().c_str(), coin.second);
            }

            // Sign all the outputs of the txn. Make sure to sign Asset
            // inputs using SignAssetSignature, and sign the rest normally
            	int nOut = 0;
                BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins) {
                	bool bIsAssetCoin = std::find(
                			vecAssetCoins.begin(),
                			vecAssetCoins.end(),
                			coin.first) != vecAssetCoins.end();
                	if (bIsAssetCoin) {
                        if (!SignAssetSignature(*coin.first, wtxNew, nOut))
                            throw runtime_error("could not sign asset coin output");
                    } else {
                        if (!SignSignature(*pwalletMain, *coin.first, wtxNew, nOut))
                            return false;
                    }
                	nOut++;
                    printf( "CreateAssetTransaction: signed %s vin (%s), pos = %d\n",
                    	bIsAssetCoin ? "asset" : "",
                        coin.first->GetHash().GetHex().c_str(),
                        coin.second);
                }

            // Limit tranasction size to 1/10 of block size
            unsigned int nBytes = ::GetSerializeSize(*(CTransaction*) &wtxNew, SER_NETWORK, PROTOCOL_VERSION);
            if (nBytes >= MAX_BLOCK_SIZE_GEN / 5)
                return false;
            dPriority /= nBytes;

            // Check that enough fee is included to pay for txn.
            // if there isnt, grab the required fee and loop again
            // from the top so we can grab additional coins.
            int64 nPayFee = nTransactionFee * (1 + (int64) nBytes / 1000);
            bool fAllowFree = CTransaction::AllowFree(dPriority);
            int64 nMinFee = wtxNew.GetMinFee(1, fAllowFree);
            if (nFeeRet < max(nPayFee, nMinFee)) {
                nFeeRet = max(nPayFee, nMinFee);
            	if(nFeeRet < CENT) {
            		nFeeRet += CENT - 1; // Round up to CENT
            		nFeeRet  = (nFeeRet / CENT) * CENT;
            	}
                printf( "CreateAssetTransactionWithInputTxs: re-iterating (nFeeRet = %s)\n",
                        FormatMoney(nFeeRet).c_str());
                continue;
            }

            // Fill vtxPrev by copying from previous transactions vtxPrev
            wtxNew.AddSupportingTransactions();
            wtxNew.fTimeReceivedIsTxTime = true;

            break;
        }
    }

    printf("CreateAssetTransactionWithInputTxs succeeded:\n%s",
            wtxNew.ToString().c_str());
    return true;
}

bool IsSyscoinTransaction(const CTransaction &tx) {
    return tx.nVersion == SYSCOIN_TX_VERSION;
}

bool GetAssetPrevCoins(
	const CTransaction &tx,
	CCoinsViewCache &inputs,
	COutPoint &prevOutput,
	CCoins &prevCoins,
	int &prevOp,
	vector<vector<unsigned char> > &vvchPrevArgs) {

    bool found = false;
    // look for a previous asset transaction in this transaction's inputs
    for (int i = 0; i < (int) tx.vin.size(); i++) {
        prevOutput = tx.vin[i].prevout;
        prevCoins = inputs.GetCoins(prevOutput.hash);
        if (DecodeAssetScript(prevCoins.vout[prevOutput.n].scriptPubKey, prevOp, vvchPrevArgs)) {
            // make sure there are three parameters in the asset script
            if (vvchPrevArgs.size() != 3)
                break;
            found = true;
            break;
        }
    }
    if(!found) {
    	vvchPrevArgs.clear();
    	return false;
    }
    return true;
}

bool GetTxn(uint256 txHash, CTransaction &tx) {
    uint256 blockHash;
    return GetTransaction(txHash, tx, blockHash, true);
}

bool CheckAssetInputs(
		CBlockIndex *pindexBlock,
		const CTransaction &tx,
		CValidationState &state,
		CCoinsViewCache &inputs,
		map<vector<unsigned char>, uint256> &mapTestPool,
		bool fBlock,
		bool fMiner,
		bool fJustCheck) {

    if (tx.IsCoinBase()) return true;

    // if (fDebug)
    //     printf("CheckAssetInputs() block %d best %d %s %s %s %s\n", pindexBlock->nHeight,
    //             pindexBest->nHeight, tx.GetHash().ToString().c_str(),
    //             fBlock ? "BLOCK" : "", fMiner ? "MINER" : "",
    //             fJustCheck ? "JUSTCHECK" : "");

    COutPoint prevOutput;
    CCoins prevCoins;
    int prevOp, op, nOut, nPrevCoinsHeight, nDepth;
    vector<vector<unsigned char> > vvchArgs, vvchPrevArgs;

    // look for a previous asset transaction in this transaction's inputs
    bool hasAssetPrevout = GetAssetPrevCoins(tx, inputs, prevOutput, prevCoins, prevOp, vvchPrevArgs);

    // Make sure asset outputs are not spent by a regular transaction, or the asset would be lost
    if (!IsSyscoinTransaction(tx)) {
        if (hasAssetPrevout)
            return error(
                    "CheckAssetInputs() : a non-syscoin transaction with a syscoin input");
        return true;
    }

    int64 nNetFee;

    // look for an asset transaction in this transction
    bool good = DecodeAssetTx(tx, op, nOut, vvchArgs, pindexBlock->nHeight);
    if (!good) return error("CheckAssetInputs() : could not decode asset tx");

    // unserialize asset object from txn, check for valid
    CAsset theAsset(tx);
    if (theAsset.IsNull())
        error("CheckAssetInputs() : null asset object");

    // make sure there are three parameters in the asset script
    if (vvchArgs.size() != 3)
        return error("CheckAssetInputs() : bad number of script params for asset transaction");

    vector<unsigned char> vchAsset = vvchArgs[0];
    vector<unsigned char> vchHash  = vvchArgs[1];
    vector<unsigned char> vchValue = vvchArgs[2];

    // get the blockheight of the asset or -1 if it doesn't exist
    nPrevCoinsHeight = GetAssetHeight(vchAsset);

    bool isGeneratingBlock = ( fBlock || fMiner );
	bool isChangeSource    = !theAsset.isChange && theAsset.changeTxHash != 0;
	bool isGeneratedAsset  = theAsset.isGenerate || isChangeSource;

    // check for enough fees
    if(hasAssetPrevout) {
        nNetFee = GetAssetNetFee(tx);
        if (nNetFee < theAsset.GetServiceFee(1, pindexBlock->nHeight))
            return error(
                    "CheckAssetInputs() : got tx %s with fee too low %llu - fee should be %llu\n",
                    tx.GetHash().GetHex().c_str(),
                    nNetFee,
                    theAsset.GetServiceFee(1, pindexBlock->nHeight));
    }
    else {
		 // disallow transaction on a nonexistent asset on
		 // transactions when it constitutes in illegal state
		if(theAsset.nOp != XOP_ASSET_NEW
				&& !isGeneratedAsset)
			return error("CheckAssetInputs() : asset does not exist or invalid asset send.");
    }

    switch (theAsset.nOp) {

        case XOP_ASSET_NEW:

            // make sure no prevouts are assets
            if (hasAssetPrevout)
                return error( "CheckAssetInputs() : assetnew tx pointing to previous syscoin tx");

            // check to make sure symbol from script matches asset object
            if (vvchArgs[0] != theAsset.vchSymbol)
                return error("assetnew tx with incorrect symbol");

            // disallow activate on an already activated asset
            if (!fBlock && nPrevCoinsHeight >= 0)
                return error( "CheckAssetInputs() : assetnew on an active asset.");

            break;

        case XOP_ASSET_PEG:
        case XOP_ASSET_UPDATE:
        case XOP_ASSET_DISSOLVE:
        case XOP_ASSET_GENERATE:
        	break;

        case XOP_ASSET_SEND:

            if(!fJustCheck) {
            	if(isGeneratingBlock) {
            		// if this asset has an asset input, make sure there is at least a single
            		// confirmation of the input tx before accepting this block to be mined
            		if(hasAssetPrevout) {
    					 nDepth = CheckAssetTransactionAtRelativeDepth(pindexBlock, prevCoins.nHeight);
    					if ( nDepth >= 0 && (unsigned int) nDepth < 1) {
    						printf("CheckAssetInputs() : waiting to mine %s transaction %s until its prevout is mined\n",
    							assetFromOp(theAsset.nOp).c_str(), tx.GetHash().GetHex().c_str());
    						return false;
    					}
    				}
            		// if this asset send is a generate (it has no previous asset coins as inputs
            		// but another transaction is paired with it as its generator) then wait until
            		// the generating transaction has been accepted and mined before accepting it
                    if(isGeneratedAsset) {
                        CTransaction genTx;
                        uint256 genBlockHash = 0,
                        		genTxHash = isChangeSource ? theAsset.changeTxHash : theAsset.genTxHash;
                        bool genTxnFound = GetTransaction(genTxHash, genTx, genBlockHash, true);
                        if(genTxnFound) {
                        	CBlockLocator locator(genBlockHash);
                        	CBlockIndex *pindexGenBlk = locator.GetBlockIndex();
                        	if(pindexGenBlk) {
                        		nDepth = CheckAssetTransactionAtRelativeDepth(pindexBlock, pindexGenBlk->nHeight);
                        		nDepth = pindexBlock->nHeight - nDepth;
                                if(nDepth > -1 && nDepth < 1) {
                                	genTxnFound = false;
                                }
                        	}
                        }
                        // don't allow myself to be accepted into a block until the transaction that
                        // made me has appeared on the blockchain.
                        if(!genTxnFound) {
							printf("CheckAssetInputs() : waiting to accept this %s transaction %s until its prevtx %s is mined\n",
								assetFromOp(theAsset.nOp).c_str(), tx.GetHash().GetHex().c_str(),
								theAsset.changeTxHash.GetHex().c_str());
							return false;
                        }
                    }
            	}
            }

//            if(!fJustCheck) {
//                if(!isAssetSend) {
//                    if(prevOp != OP_ASSET)
//                        return error("CheckAssetInputs() : previous transaction is not asset");
//
//                    if(!hasAssetPrevout)
//                        return error("CheckAssetInputs() : previous asset transaction not found");
//                }
//
//            	// if this send has no previous txn, has a previous change tx, and is not change,
//            	// then it was sent via an assetnew or an assetsend. Check to see if the previous
//            	// transaction has been accepted. If not, we wait until it is.
//
//                if(isGeneratingBlock) {
//
//                    // min depth is 1 for asset transactions which have prev inputs.
//                    if(hasAssetPrevout) {
//                         nDepth = CheckAssetTransactionAtRelativeDepth(pindexBlock, prevCoins.nHeight);
//                        if ( nDepth >= 0 && (unsigned int) nDepth < 1) {
//                            printf("CheckAssetInputs() : waiting to mine %s transaction %s until its prevout is mined\n",
//                                assetFromOp(theAsset.nOp).c_str(), tx.GetHash().GetHex().c_str());
//                            return false;
//                        }
//                    }
//
//                    // if this is an asset generate (initial shares allotment created on assetnew) then
//                    // make sure that the assetnew transaction has been accepted and mined before accepting
//                    if(theAsset.isGenerate) {
//
//                        CTransaction genTx;
//                        uint256 genBlockHash = 0;
//                        bool genTxnFound = GetTransaction(theAsset.changeTxHash, genTx, genBlockHash, true);
//                        if(genTxnFound) {
//                        	CBlockLocator locator(genBlockHash);
//                        	CBlockIndex *pindexGenBlk = locator.GetBlockIndex();
//                        	if(pindexGenBlk) {
//                        		nDepth = CheckAssetTransactionAtRelativeDepth(pindexBlock, pindexGenBlk->nHeight);
//                        		nDepth = pindexBlock->nHeight - nDepth;
//                                if(nDepth > -1 && nDepth < 1) {
//                                    printf("CheckAssetInputs() : waiting to accept this %s transaction %s until its prevtx %s is mined\n",
//                                        assetFromOp(theAsset.nOp).c_str(), tx.GetHash().GetHex().c_str(),
//                                        theAsset.changeTxHash.GetHex().c_str());
//                                    return false;
//                                }
//                        	}
//                        }
//
//                    }
//                }
//
//                if(fBlock) {
//
//
//                    if(!hasAssetPrevout && isAssetSend) break;
//
//                    // check for previous asset
//                    nDepth = CheckAssetTransactionAtRelativeDepth(pindexBlock, prevCoins.nHeight);
//                    if (nDepth == -1)
//                        return error( "CheckAssetInputs() : no asset output in previous coins");
//
//                    // only mine 1 asset type per transaction
//                    if(pindexBlock->nHeight == pindexBest->nHeight) {
//                        BOOST_FOREACH(const MAPTESTPOOLTYPE& s, mapTestPool) {
//                            if (vchAsset == s.first) {
//                               return error("CheckInputs() : will not mine %s because it clashes with %s",
//                                       tx.GetHash().GetHex().c_str(),
//                                       s.second.GetHex().c_str());
//                            }
//                        }
//                    }
//                }
//            }

            break;

        default:
            return error( "CheckAssetInputs() : asset transaction has unknown op");
    }

    // save serialized asset for later use
    CAsset serializedAsset = theAsset;

    // try to load the asset data from the DB.
    vector<CAsset> vtxPos;
    if (passetdb->ExistsAsset(theAsset.vchSymbol)) {
        if (!passetdb->ReadAsset(theAsset.vchSymbol, vtxPos))
            return error(
                    "CheckAssetInputs() : failed to read from asset DB");
    }

    // these ifs are problably total bullshit except for the assetnew
    // CB Turns our they're not, after gaining an understanding of what they are.
    if (fBlock || (!isGeneratingBlock && !fJustCheck) ) {

        // remove asset from pendings
        vector<unsigned char> vchAsset = theAsset.vchSymbol;

    	// only record asset info to the database if it's activate (so everyone can see it)
    	// or if it's a send and we are the recipient

        if (!fMiner && !fJustCheck && pindexBlock->nHeight != pindexBest->nHeight) {

            // get the latest asset from the db
            // TODO CB Actually this is likely a new asset, thus telling me the ridiculous if statement above can be simplified
			theAsset.GetAssetFromList(vtxPos);

            // set the new local asset quantity. if a prev txn exists
            // then we increment the asset count. otherwise set it to qty
            switch(serializedAsset.nOp) {
                case XOP_ASSET_NEW:
                case XOP_ASSET_SEND:
                    break;
                case XOP_ASSET_PEG:
                    theAsset.nCoinsPerShare = serializedAsset.nCoinsPerShare;
                    break;
                case XOP_ASSET_UPDATE:
                    theAsset.vchDescription = serializedAsset.vchDescription;
                    break;
                case XOP_ASSET_GENERATE:
                    theAsset.nTotalQty += serializedAsset.nQty;
                    break;
                case XOP_ASSET_DISSOLVE:
                    theAsset.nTotalQty -= serializedAsset.nQty;
                    break;
            }

            // use data from latest asset info in DB as
            // a basis for creating a new asset for this txn
            theAsset.nQty = serializedAsset.nQty;
            theAsset.nOp = serializedAsset.nOp;
            theAsset.nHeight = pindexBlock->nHeight;
            theAsset.txHash = tx.GetHash();
            theAsset.nFee = serializedAsset.nFee;
            theAsset.isChange = serializedAsset.isChange;
            theAsset.changeTxHash = serializedAsset.changeTxHash;
            theAsset.isGenerate = serializedAsset.isGenerate;
            theAsset.genTxHash = serializedAsset.genTxHash;
            theAsset.nTime = pindexBlock->nTime;
            theAsset.n = nOut;
            theAsset.PutToAssetList(vtxPos);

            // write asset to database
            if (!passetdb->WriteAsset(vvchArgs[0], vtxPos))
                return error( "CheckAssetInputs() : failed to write to asset DB");

            // get the fee for this asset txn
            int64 nTheFee = GetAssetNetFee(tx);

            // compute verify and write fee data to DB
            InsertAssetFee(pindexBlock, tx.GetHash(), theAsset.nOp, nTheFee);
            if(nTheFee > 0) printf("ASSET FEES: Added %lf in fees to track for regeneration.\n", (double) nTheFee / COIN);
            vector<CAssetFee> vAssetFees(lstAssetFees.begin(), lstAssetFees.end());
            if (!passetdb->WriteAssetFees(vAssetFees))
                return error( "CheckAssetInputs() : failed to write fees to asset DB");

            {
                LOCK(cs_assetmaps);

				std::map<std::vector<unsigned char>, std::set<uint256> >::iterator mi
					= mapAssetPending.find(vchAsset);

				if (mi != mapAssetPending.end())
					mi->second.erase(tx.GetHash());

				mapTestPool[vvchArgs[0]] = tx.GetHash();
            }
            // debug
            if (fDebug)
                printf( "CONNECTED %s", theAsset.toString().c_str());
        }
    }

    return true;
}

/**
 * extract the value for the address field show on a listtransactions. 
 */
bool ExtractAssetAddress(const CScript& script, string& address) {
    if (script.size() == 1 && script[0] == OP_RETURN) {
        address = string("network fee");
        return true;
    }

    vector<vector<unsigned char> > vvch;
    int op;
    if (!DecodeAssetScript(script, op, vvch))
        return false;

    string strAsset = stringFromVch(vvch[0]);
    address = assetFromOp(OP_ASSET) + ": " + strAsset;
    
    return true;
}


/**
 * called on a -rescan. rescans the blockchain and rebuilds the db
 */
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

/**
 * create the script for the asset.
 */
CScript CreateAssetScript(const vector<vector<unsigned char> >& vvchArgs, uint160 assetHash, CKeyID *dest, const CTxDestination *txd) {
    assert( vvchArgs.size() == 2 );
    
    CScript scriptPubKeyOrig, scriptPubKey;
    if(dest != NULL) {
        scriptPubKeyOrig.SetDestination(*dest);   
    } 
    else if(txd != NULL) {
        scriptPubKeyOrig.SetDestination(*txd);   
    } 
    else {
        CPubKey newDefaultKey;
        pwalletMain->GetKeyFromPool(newDefaultKey, false);
        scriptPubKeyOrig.SetDestination(newDefaultKey.GetID());     
    }
       
    scriptPubKey << CScript::EncodeOP_N(OP_ASSET) << vvchArgs[0] << assetHash << vvchArgs[1] << OP_2DROP << OP_2DROP;
    scriptPubKey += scriptPubKeyOrig;
    return scriptPubKey;
}

/**
 * checks the pending asset transactions map to see if any other asset transactions of this asset type are pending
 */
bool IsAssetTransactionPending(const vector<unsigned char> &vchSymbol) {
    if (mapAssetPending.count(vchSymbol) && mapAssetPending[vchSymbol].size()) {
    	if(fDebug)
			error( "IsAssetTransactionPending() : there are %d pending operations on that asset, including %s",
				   (int) mapAssetPending[vchSymbol].size(),
				   mapAssetPending[vchSymbol].begin()->GetHex().c_str());
        return true;
    }
    return false;
}

bool AddAssetTransactionPending(const vector<unsigned char> &vchSymbol, uint256 txHash) {

	return true;
}

/**
 * checks the pending asset transactions map to see if any other asset transactions of this asset type are pending
 */
bool AssetTransactionExists(const vector<unsigned char> &vchSymbol) {
    CTransaction tx;
    if (GetTxOfAsset(*passetdb, vchSymbol, tx)) {
        return true;
    }
    return false;
}

Value assetnew(const Array& params, bool fHelp) {
     
    if (fHelp || params.size() != 4)
        throw runtime_error(
                "assetnew <symbol> <title> <description> <totalshares> [<coinspershare>] [<allowfractions>] [<allowpeg>] [<allowgenerate>] [<allowdissolve>] [<allowconversion>]\n"
                        "<symbol> symbol, 255 bytes max."
                        "<title> title, 255 bytes max."
                        "<description> description, 16KB max."
                        "<totalshares> total number of shares, 1 min, 2^64 - 1 max."
                        "[<coinspershare>] value per share, in SYS. Default 1"
                        "[<allowfractions>] allow fractional asset quantities. Default is true." // TODO CB implement this and allowsplit functionality
                        "[<allowpeg>] allow asset coins per share to be re-pegged in the future. Default is true."
                        "[<allowgenerate>] allow generation of additional shares of this asset. Default is true."
                        "[<allowdissolve>] allow dissolving shares of this asset. Default is true."
                        "[<allowconversion>] allow shares of this asset to be converted into another asset. Default is true."
                        + HelpRequiringPassphrase());
    // gather inputs
    vector<unsigned char> vchSymbol = vchFromValue(params[0]);
    vector<unsigned char> vchTitle = vchFromValue(params[1]);
    vector<unsigned char> vchDescription = vchFromValue(params[2]);
    uint64 nTotalQty = atoi64(params[3].get_str().c_str()); // TODO CB better translation for total quantit yof

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

    if(pwalletMain->GetBalance() < (int64)(nTotalQty * COIN) + (nTransactionFee * 2))
        throw runtime_error("Insufficient balance to create this asset\n");

    // this is a syscoin transaction
    CWalletTx wtx;
    wtx.nVersion = SYSCOIN_TX_VERSION;

    // TODO CB make sure the wallet is getting locked properly in the other commands
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        // make sure no pending transactions for this asset
        if(IsAssetTransactionPending(vchSymbol)) {
            throw runtime_error("there are pending operations on that asset");            
        }

        // cannot activate an asset if it is already active
        if (AssetTransactionExists(vchSymbol)) {
            throw runtime_error("this asset is already active");
        }

        EnsureWalletIsUnlocked();

        // build asset object
        CAsset newAsset;

        // values for asset_new txn
        newAsset.nOp            = XOP_ASSET_NEW;
        newAsset.txHash         = wtx.GetHash();
        newAsset.nTotalQty      = nTotalQty * COIN;
        newAsset.nQty			= COIN;
        newAsset.nCoinsPerShare = COIN;
        newAsset.vchSymbol      = vchSymbol;
        newAsset.vchTitle       = vchTitle;
        newAsset.vchDescription = vchDescription;
        newAsset.nFee           = 0;
        newAsset.isChange		= false;
        newAsset.changeTxHash	= 0;
        newAsset.isGenerate		= false;
        newAsset.genTxHash      = 0;

        // send the assetnew control transaction out
        string strError = newAsset.SendToDestination(wtx);
        if (strError != "") throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    return wtx.GetHash().GetHex();
}

Value assetsend(const Array& params, bool fHelp) {
    if (fHelp || params.size() != 3)
        throw runtime_error(
                "assetsend <symbol> <address> <amount>\n"
                        "Send shares of an asset you control to another address.\n"
                        "<symbol> asset symbol.\n"
                        "<address> destination syscoin address.\n"
                        "<amount> number of shares to send. minimum 1.\n"
                        + HelpRequiringPassphrase());

    // gather & validate inputs
    vector<unsigned char> vchAsset = vchFromValue(params[0]);
    vector<unsigned char> vchAddress = vchFromValue(params[1]);
    
    if (vchAsset.size() > 10)
        throw runtime_error("asset symbol > 10 bytes!\n");

    // TODO CB better translation for total quantity
    uint64 nQty = atoi64(params[2].get_str().c_str());
    if(nQty <= 0) throw runtime_error("Invalid asset quantity.");

    // validate destination address
    CBitcoinAddress sendAddr(stringFromVch(vchAddress));
    if(!sendAddr.IsValid())
        throw runtime_error("Invalid Syscoin address.");

    // this is a syscoin txn
    CWalletTx wtx;
    wtx.nVersion = SYSCOIN_TX_VERSION;

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        
        // make sure no pending transactions for this asset
        if(IsAssetTransactionPending(vchAsset))
            throw runtime_error("there are pending operations on that asset");            

        // cannot activate an asset if it is already active
        if (!AssetTransactionExists(vchAsset))
            throw runtime_error("this asset does not exist");

        EnsureWalletIsUnlocked();

        if (!pwalletMain->GetAssetBalance(vchAsset))
            throw runtime_error("this asset is not in your wallet");

        // get the asset from DB
        vector<CAsset> vtxPos;
        if (!passetdb->ReadAsset(vchAsset, vtxPos))
            throw runtime_error("could not read asset from DB");
        CAsset theAsset = vtxPos.back();

        uint64 nAssetBalance = pwalletMain->GetAssetBalance(vchAsset);
        nQty *= theAsset.nCoinsPerShare;

        // calculate network fees
        uint64 nNetFee = theAsset.GetServiceFee(2, pindexBest->nHeight);

        // make sure we have enough quantity to perform the send
        if(nAssetBalance == 0 || nQty == 0 || nAssetBalance < nQty + nNetFee )
            throw runtime_error("invalid asset quantity");

        // make sure there's enough funds to send this txn before trying 
        if(pwalletMain->GetBalance() < (int64)nNetFee)
            throw runtime_error("insufficient balance to pay asset send fee.");

        // populate the asset object
        theAsset.nOp            = XOP_ASSET_SEND;
        theAsset.txHash         = wtx.GetHash();
        theAsset.nQty			= nQty;
        theAsset.nFee           = 0;
        theAsset.isChange		= false;
        theAsset.changeTxHash	= 0;
        theAsset.isGenerate		= false;
        theAsset.genTxHash      = 0;
        
        string strError = theAsset.SendToDestination(wtx, &vchAddress);
        if (strError != "") throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    return wtx.GetHash().GetHex();
}

Value assetpeg(const Array& params, bool fHelp) {
    if (fHelp || params.size() != 2)
        throw runtime_error(
                "assetpeg <symbol>\n"
                "Peg the asset's SYS-per-share value to the given amount.\n"
                        "<symbol> asset symbol.\n"
                        "<amount> asset share value.\n"
                        + HelpRequiringPassphrase());

    // gather & validate inputs
    vector<unsigned char> vchAsset = vchFromValue(params[0]);

    if (vchAsset.size() > 10)
        throw runtime_error("asset symbol > 10 bytes!\n");

    uint64 nCoinsPerShare = params[1].get_real() * COIN;
    if(nCoinsPerShare < 1) throw runtime_error("Invalid asset share value.");

    // this is a syscoin txn
    CWalletTx wtx;
    wtx.nVersion = SYSCOIN_TX_VERSION;

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        // make sure no pending transactions for this asset
        if(IsAssetTransactionPending(vchAsset))
            throw runtime_error("there are pending operations on that asset");

        // cannot activate an asset if it is already active
        if (!AssetTransactionExists(vchAsset))
            throw runtime_error("this asset does not exist");

        EnsureWalletIsUnlocked();

        // look for a transaction with this key
        CTransaction tx;
        if (!GetTxOfAssetControl(*passetdb, vchAsset, tx))
            throw runtime_error("could not find an asset with this key");

        // make sure asset is in wallet
        uint256 wtxInHash = tx.GetHash();
        if (!pwalletMain->mapWallet.count(wtxInHash))
            throw runtime_error("this asset is not in your wallet");

        // unserialize asset object from txn
        CAsset theAsset;
        if(!theAsset.UnserializeFromTx(tx))
            throw runtime_error("cannot unserialize asset from txn");

        // try to get the asset from DB
        vector<CAsset> vtxPos;
        if (!passetdb->ReadAsset(vchAsset, vtxPos))
            throw runtime_error("could not read asset from DB");
        theAsset = vtxPos.back();

        // make sure there's enough funds to send this txn before trying 
        if(pwalletMain->GetAssetControlBalance(theAsset.vchSymbol) != COIN)
            throw runtime_error("you cannot modify this asset because you do not control it.");

        // asset transaction
        theAsset.nOp            = XOP_ASSET_PEG;
        theAsset.txHash         = wtx.GetHash();
        theAsset.nFee           = 0;
        theAsset.isChange		= false;
        theAsset.changeTxHash	= 0;
        theAsset.isGenerate		= false;
        theAsset.genTxHash      = 0;
        theAsset.nQty 			= COIN;
        theAsset.nCoinsPerShare = nCoinsPerShare;
        
        string strError = theAsset.SendToDestination(wtx);
        if (strError != "") throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    return wtx.GetHash().GetHex();
}

Value assetupdate(const Array& params, bool fHelp) {
    if (fHelp || params.size() != 2)
        throw runtime_error(
                "assetupdate <symbol> <description>\n"
                "Update the asset description.\n"
                        "<symbol> asset symbol.\n"
                        "<description> asset description.\n"
                        + HelpRequiringPassphrase());

    // gather & validate inputs
    vector<unsigned char> vchAsset = vchFromValue(params[0]);
    vector<unsigned char> vchDesc = vchFromValue(params[1]);

    if (vchAsset.size() > 10)
        throw runtime_error("asset symbol > 10 bytes!\n");

    if (vchDesc.size() > 16 * 1024)
        throw runtime_error("asset description > 16384 bytes!\n");

    // this is a syscoin txn
    CWalletTx wtx;
    wtx.nVersion = SYSCOIN_TX_VERSION;

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        if(IsAssetTransactionPending(vchAsset))
            throw runtime_error("there are pending operations on that asset");

        EnsureWalletIsUnlocked();

        // look for a transaction with this key
        CTransaction tx;
        if (!GetTxOfAssetControl(*passetdb, vchAsset, tx))
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

        // make sure there's enough funds to send this txn before trying 
        if(pwalletMain->GetAssetControlBalance(theAsset.vchSymbol) != COIN)
            throw runtime_error("you cannot modify this asset because you do not control it.");

        // asset transaction
        theAsset.nOp            = XOP_ASSET_UPDATE;
        theAsset.txHash         = wtx.GetHash();
        theAsset.nQty           = COIN;
        theAsset.nFee           = 0;
        theAsset.isChange		= false;
        theAsset.changeTxHash	= 0;
        theAsset.isGenerate		= false;
        theAsset.genTxHash      = 0;
        theAsset.vchDescription = vchDesc;

        
        string strError = theAsset.SendToDestination(wtx);
        if (strError != "") throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    return wtx.GetHash().GetHex();
}

Value assetgenerate(const Array& params, bool fHelp) {
    if (fHelp || params.size() != 2)
        throw runtime_error(
                "assetgenerate <symbol> <description>\n"
                "Generate new asset shares.\n"
                        "<symbol> asset symbol.\n"
                        "<amount> amount of asset shares to generate.\n"
                        + HelpRequiringPassphrase());

    // gather & validate inputs
    vector<unsigned char> vchAsset = vchFromValue(params[0]);
    uint64 nGenQty = atoi64(params[1].get_str().c_str());
    if(nGenQty < 1) throw runtime_error("Invalid generate quantity.");

    if (vchAsset.size() > 10)
        throw runtime_error("asset symbol > 10 bytes!\n");

    // this is a syscoin txn
    CWalletTx wtx;
    wtx.nVersion = SYSCOIN_TX_VERSION;

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        if(IsAssetTransactionPending(vchAsset))
            throw runtime_error("there are pending operations on that asset");

        EnsureWalletIsUnlocked();

        // look for a transaction with this key
        CTransaction tx;
        if (!GetTxOfAssetControl(*passetdb, vchAsset, tx))
            throw runtime_error("could not find an asset with this key");

        // unserialize asset object from txn
        CAsset theAsset;
        if(!theAsset.UnserializeFromTx(tx))
            throw runtime_error("cannot unserialize asset from txn");


        // make sure there's enough funds to send this txn before trying
        if(pwalletMain->GetAssetControlBalance(theAsset.vchSymbol) != COIN)
            throw runtime_error("you cannot modify this asset because you do not control it.");

        // make sure asset is in wallet
        uint256 wtxInHash = tx.GetHash();
        if (!pwalletMain->mapWallet.count(wtxInHash))
            throw runtime_error("this asset is not in your wallet");

        // get the asset from DB
        vector<CAsset> vtxPos;
        if (!passetdb->ReadAsset(vchAsset, vtxPos))
            throw runtime_error("could not read asset from DB");
        theAsset = vtxPos.back();

        // TODO CB make it incrementally more and more expensive to split an asset. this is to prevent someone from creating an asset with a low number of shares and then splitting it to save on fees.
        // serialize asset object
        
        // TODO CB MAKE SURE that the asset_activate txn is NOT used as an input to the txn for the destination or the original asset creator will be unable to update it
        // TODO Currently anyone holding this asset can split it. Fix that.

        // asset transaction
        theAsset.nOp          = XOP_ASSET_GENERATE;
        theAsset.txHash       = wtx.GetHash();
        theAsset.nFee         = 0;
        theAsset.isChange	  = false;
        theAsset.changeTxHash = 0;
        theAsset.isGenerate	  = false;
        theAsset.genTxHash    = 0;
        theAsset.nQty         = COIN;

        string strError = theAsset.SendToDestination(wtx);
        if (strError != "") throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    return wtx.GetHash().GetHex();
}

Value assetdissolve(const Array& params, bool fHelp) {
    if (fHelp || params.size() != 2)
        throw runtime_error(
                "assetdissolve <symbol> <amount>\n"
                "Generate new asset shares.\n"
                        "<symbol> asset symbol.\n"
                        "<amount> amount of asset shares to dissolve.\n"
                        + HelpRequiringPassphrase());

    // gather & validate inputs
    vector<unsigned char> vchAsset = vchFromValue(params[0]);
    uint64 nGenQty = atoi64(params[1].get_str().c_str());
    if(nGenQty < 1) throw runtime_error("Invalid dissolve quantity.");

    if (vchAsset.size() > 10)
        throw runtime_error("asset symbol > 10 bytes!\n");

    // this is a syscoin txn
    CWalletTx wtx;
    wtx.nVersion = SYSCOIN_TX_VERSION;

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        if(IsAssetTransactionPending(vchAsset))
            throw runtime_error("there are pending operations on that asset");

        EnsureWalletIsUnlocked();

        // look for a transaction with this key
        CTransaction tx;
        if (!GetTxOfAssetSend(*passetdb, vchAsset, tx))
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

        // make sure there's enough funds to send this txn before trying 
        if(pwalletMain->GetAssetControlBalance(theAsset.vchSymbol) != COIN)
            throw runtime_error("you cannot modify this asset because you do not control it.");

//        // get syscoin service fees
//        int64 nNetFee = theAsset.GetServiceFee(2, pindexBest->nHeight);
//
//        // make sure there's enough funds to send this txn before trying
//        if(pwalletMain->GetBalance() < nNetFee)
//            throw runtime_error("insufficient balance to pay assetdissolve fees.");

        // asset transaction
        theAsset.nOp          = XOP_ASSET_DISSOLVE;
        theAsset.txHash       = wtx.GetHash();
        theAsset.nQty         = COIN;
        theAsset.nFee         = 0;
        theAsset.isChange	  = false;
        theAsset.changeTxHash = 0;
        theAsset.isGenerate	  = false;
        theAsset.genTxHash    = 0;

        string strError = theAsset.SendToDestination(wtx);
        if (strError != "") throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    return wtx.GetHash().GetHex();
}

Value assetinfo(const Array& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("assetinfo <symbol>\n"
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
        uint64 nTotalAssetCoins = pwalletMain->GetAssetBalance(theAsset.vchSymbol);

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
            oAsset.push_back(Pair("total_quantity", (double) theAsset.nTotalQty / (double)theAsset.nCoinsPerShare ));
            oAsset.push_back(Pair("coins_per_share", ValueFromAmount(theAsset.nCoinsPerShare) ));
            oAsset.push_back(Pair("quantity", (double)nTotalAssetCoins / (double)theAsset.nCoinsPerShare));

            oLastAsset = oAsset;
        }
    }
    return oLastAsset;

}

Value assetlist(const Array& params, bool fHelp) {
    if (fHelp || 1 < params.size())
        throw runtime_error("assetlist [<symbol>]\n"
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

Value listassettransactions(const Array& params, bool fHelp) {
    if (fHelp || 1 < params.size())
        throw runtime_error("listassettransactions [<symbol>]\n"
                "list my asset transactions");

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
            oName.push_back(Pair("txid", tx.GetHash().GetHex()));
            oName.push_back(Pair("name", stringFromVch(vchName)));
            oName.push_back(Pair("value", stringFromVch(vchValue)));             
            string strAddress = "";
            GetAssetAddress(tx, strAddress);
            oName.push_back(Pair("address", strAddress));

            Array details;
            const CWalletTx &wtx = item.second;
            ListTransactions(wtx, "*", 0, false, details);
            oName.push_back(Pair("details", details));
    
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
        throw runtime_error("assethistory <symbol>\n"
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

