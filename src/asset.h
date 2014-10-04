#ifndef ASSET_H
#define ASSET_H

#include "bitcoinrpc.h"
#include "leveldb.h"
#include "script.h"

#include <boost/foreach.hpp>

class CTransaction;
class CTxOut;
class CValidationState;
class CCoinsViewCache;
class COutPoint;
class CCoins;
class CScript;
class CWalletTx;
class CDiskTxPos;
class CAsset;
class CCoin;

bool CheckAssetInputs(CBlockIndex *pindex, const CTransaction &tx, CValidationState &state, CCoinsViewCache &inputs,
                     std::map<std::vector<unsigned char>,uint256> &mapTestPool, bool fBlock, bool fMiner, bool fJustCheck);
bool IsAssetMine(const CTransaction& tx);
bool IsAssetMine(const CTransaction& tx, const CTxOut& txout, bool ignore_assetnew = false);
bool IsMyAsset(const CTransaction& tx, const CTxOut& txout);
CScript RemoveAssetScriptPrefix(const CScript& scriptIn);
int CheckAssetTransactionAtRelativeDepth(CBlockIndex* pindexBlock, int target, int maxDepth = -1);
bool DecodeAssetTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch, int nHeight, bool bDecodeAll = false);
bool DecodeAssetTx(CAsset theAsset, const CCoins& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch, int nHeight, bool bDecodeAll = false);
bool DecodeAssetScript(const CScript& script, int& op, std::vector<std::vector<unsigned char> > &vvch);
bool DecodeAssetTxExtraCoins(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch, int nHeight);
bool IsAssetOp(int op);
int IndexOfAssetOutput(const CTransaction& tx);
int IndexOfAssetExtraCoinsOutput(const CTransaction& tx);
uint64 GetAssetFeeSubsidy(unsigned int nHeight);
bool GetValueOfAssetTxHash(const uint256 &txHash, std::vector<unsigned char>& vchValue, uint256& hash, int& nHeight);
int GetAssetTxHashHeight(const uint256 txHash);
int GetAssetTxPosHeight(const CDiskTxPos& txPos);
int GetAssetTxPosHeight2(const CDiskTxPos& txPos, int nHeight);
int GetAssetDisplayExpirationDepth(int nHeight); // TODO CB remove references to 'expiration' - assets do not expire
int64 GetAssetNetworkFee(int seed, int nHeight);
int64 GetAssetNetFee(const CTransaction& tx);
bool InsertAssetFee(CBlockIndex *pindex, uint256 hash, int nOp, uint64 nValue);
bool ExtractAssetAddress(const CScript& script, std::string& address);
CScript CreateAssetScript(const std::vector<std::vector<unsigned char> >& vvchArgs, uint160 assetHash, CKeyID *dest = NULL, const CTxDestination *txd = NULL);
std::string stringFromVch(const std::vector<unsigned char> &vch);

std::string assetFromOp(int op);

extern std::map<std::vector<unsigned char>, uint256> mapMyAssets;
extern std::map<std::vector<unsigned char>, std::set<uint256> > mapAssetPending;

class CBitcoinAddress;

class CAsset {
public:
    std::vector<unsigned char> vchSymbol;
    std::vector<unsigned char> vchTitle;
    std::vector<unsigned char> vchDescription;
    uint64 nTotalQty;
    uint64 nQty;
    uint64 nCoinsPerShare;

    bool isChange;
    bool isGenerate;

    uint256 txHash;
    uint256 changeTxHash;
    uint256 genTxHash;
    
    uint64 nHeight;
    uint64 nTime;
    uint256 hash;
    uint64 n;
    uint64 nFee;
    uint64 nOp;

    CAsset() {
        SetNull();
    }

    CAsset(const CTransaction &tx) {
        if(!UnserializeFromTx(tx))
            SetNull();
    }

    CAsset(const CWalletTx &tx) {
        if(!UnserializeFromTx(tx))
            SetNull();
    }

    CAsset(std::vector<unsigned char> &vchSymbol) {
        if(!GetAsset(vchSymbol))
            SetNull();
    }

    CAsset(const std::string &sData) {
        if(!GetAsset(vchSymbol))
            SetNull();
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(vchSymbol);
        READWRITE(vchTitle);
        READWRITE(vchDescription);
        READWRITE(nTotalQty);
        READWRITE(nCoinsPerShare);
        READWRITE(nQty);
        READWRITE(isChange);
        READWRITE(isGenerate);
        READWRITE(txHash);
        READWRITE(changeTxHash);
        READWRITE(genTxHash);       
        READWRITE(nHeight);
        READWRITE(nTime);
        READWRITE(hash);
        READWRITE(n);
        READWRITE(nFee);
        READWRITE(nOp);
    )

    void PutToAssetList(std::vector<CAsset> &assetList) {
        assert(nHeight != 0 || txHash != 0);
        unsigned int i = assetList.size()-1;
        BOOST_REVERSE_FOREACH(CAsset o, assetList) {
        	if(o.nHeight != 0 && o.nHeight == nHeight) {
                assetList[i] = *this;
                return;
            }
        	else if(o.txHash != 0 && o.txHash == txHash) {
				assetList[i] = *this;
				return;
        	}
            i--;
        }
        assetList.push_back(*this);
    }

    bool GetAssetFromList(const std::vector<CAsset> &assetList) {
        if(assetList.size() == 0) return false;
        unsigned int i = assetList.size()-1;
        BOOST_FOREACH(CAsset o, assetList) {
        	if(o.nHeight == nHeight) {
                *this = assetList[i];
                return true;
            }
        	if(o.txHash == txHash) {
				*this = assetList[i];
				return true;
			}
            i--;
        }
        *this = assetList.back();
        return false;
    }

    bool GetAsset(std::vector<unsigned char> &vchSymbol); 

    bool GetAsset(CTransaction &tx) {
        return UnserializeFromTx(tx);
    }

    bool GetAssetSendFromList(const std::vector<CAsset> &assetList) {
        if(assetList.size() == 0) return false;
        unsigned int i = assetList.size()-1;
        BOOST_FOREACH(CAsset o, assetList) {
            if(o.nOp == XOP_ASSET_SEND) {
                if(nHeight != 0) {
                    if(o.nHeight == nHeight) {
                        *this = assetList[i];
                        return true;
                    }
                } else if (txHash != 0) {
                    if(o.txHash == txHash) {
                        *this = assetList[i];
                        return true;
                    }
                } else {
                    *this = assetList[i];
                    return true;
                }
            }
            i--;
        }
        return false;
    }

    bool GetAssetControlFromList(const std::vector<CAsset> &assetList) {
        if(assetList.size() == 0) return false;
        unsigned int i = assetList.size()-1;
        BOOST_FOREACH(CAsset o, assetList) {
            if(o.nOp != XOP_ASSET_SEND) {
                if(nHeight != 0) {
                    if(o.nHeight == nHeight) {
                        *this = assetList[i];
                        return true;
                    }
                } else if (txHash != 0) {
                    if(o.txHash == txHash) {
                        *this = assetList[i];
                        return true;
                    }
                } else {
                    *this = assetList[i];
                    return true;
                }
            }
            i--;
        }
        return false;
    }

    uint160 GetHash() {
    	return Hash160(SerializeToString());
    }

    uint160 GetGenesisHash() {
    	CAsset theAsset = *this;
    	theAsset.isGenerate = true;
    	theAsset.txHash = theAsset.genTxHash;
    	theAsset.nQty = theAsset.nTotalQty;
    	return Hash160(theAsset.SerializeToString());
    }

    uint160 GetChangeHash() {
    	CAsset theAsset = *this;
    	theAsset.isChange = true;
    	theAsset.txHash = theAsset.changeTxHash;
    	return Hash160(theAsset.SerializeToString());
    }


    friend bool operator==(const CAsset &a, const CAsset &b) {
        return (
           a.vchTitle == b.vchTitle
        && a.vchSymbol == b.vchSymbol
        && a.vchDescription == b.vchDescription
        && a.nTotalQty == b.nTotalQty
        && a.nQty == b.nQty
        && a.nCoinsPerShare == b.nCoinsPerShare
        && a.changeTxHash == b.changeTxHash
        && a.isChange == b.isChange
        && a.genTxHash == b.genTxHash
        && a.isGenerate == b.isGenerate
        && a.nFee == b.nFee
        && a.n == b.n
        && a.hash == b.hash
        && a.txHash == b.txHash
        && a.nHeight == b.nHeight
        && a.nTime == b.nTime
        && a.nOp == b.nOp
        );
    }

    CAsset operator=(const CAsset &b) {
        vchTitle = b.vchTitle;
        vchSymbol = b.vchSymbol;
        vchDescription = b.vchDescription;
        nTotalQty = b.nTotalQty;
        nQty = b.nQty;
        nCoinsPerShare = b.nCoinsPerShare;
        isChange = b.isChange;
        changeTxHash = b.changeTxHash;
        isGenerate = b.isGenerate;
        genTxHash = b.genTxHash;
        nFee = b.nFee;
        n = b.n;
        hash = b.hash;
        txHash = b.txHash;
        nHeight = b.nHeight;
        nTime = b.nTime;
        nOp = b.nOp;
        return *this;
    }

    friend bool operator!=(const CAsset &a, const CAsset &b) {
        return !(a == b);
    }

    void SetNull() { 
        nHeight = n = nOp = 0; 
        txHash = changeTxHash = genTxHash = hash = 0;
        nTotalQty = nQty = nCoinsPerShare = 0;
        isChange = false;
        isGenerate = false;
        vchSymbol.clear(); 
        vchTitle.clear(); 
        vchDescription.clear(); 
    }

    bool IsNull() const { 
        return (
            txHash == 0  && 
            changeTxHash == 0 && 
            genTxHash == 0 && 
            hash == 0 && 
            nHeight == 0 && 
            nOp == 0 &&
            vchSymbol.size() == 0 &&
            vchTitle.size() == 0 &&
            vchDescription.size() == 0);
    }

    bool IsAssetChange(uint160 compareHash);
    bool IsGenesisAsset(uint160 compareHash);

    // 10080 blocks = 1 week
    // certificate issuer expiration time is ~ 6 months or 26 weeks
    // expiration blocks is 262080 (final)
    // expiration starts at 87360, increases by 1 per block starting at
    // block 174721 until block 349440
    int64 GetServiceFee(int seed, int height = -1) {
        return 0;

        if (fCakeNet) return CENT;
        if(height == -1) height = nHeight;
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
        if(height>nTargetHeight) return nRes - nDif;
        else return nRes - ( (height/nTargetHeight) * nDif );
    }

    std::string SendToDestination(CWalletTx& wtxNew,  const std::vector<unsigned char> *pvchAddress = NULL);
    bool CreateTransaction(const std::vector<std::pair<CScript, int64> >& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet, bool bIsFromMe = true);
    std::string toString();
    bool UnserializeFromTx(const CTransaction &tx);
    bool UnserializeFromTx(const CWalletTx &tx);
    bool UnserializeFromString(const std::string &s);
    void SerializeToTx(CTransaction &tx);
    std::string SerializeToString();
};

class CAssetFee {
public:
    uint256 hash;
    uint64 nHeight;
    uint64 nTime;
    int    nOp;
    uint64 nFee;

    CAssetFee() {
        nTime = 0; nHeight = 0; hash = 0; nOp = 0;  nFee = 0;
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(hash);
        READWRITE(nHeight);
        READWRITE(nTime);
        READWRITE(nOp);
        READWRITE(nFee);
    )

    friend bool operator==(const CAssetFee &a, const CAssetFee &b) {
        return (
        a.nTime==b.nTime
        && a.hash==b.hash
        && a.nHeight==b.nHeight
        && a.nOp==b.nOp
        && a.nFee == b.nFee
        );
    }

    CAssetFee operator=(const CAssetFee &b) {
        nTime = b.nTime;
        nFee = b.nFee;
        hash = b.hash;
        nOp = b.nOp;
        nHeight = b.nHeight;
        return *this;
    }

    friend bool operator!=(const CAssetFee &a, const CAssetFee &b) { return !(a == b); }
    void SetNull() { hash = nTime = nHeight = nOp = nFee = 0;}
    bool IsNull() const { return (nTime == 0 && nFee == 0 && hash == 0 && nOp == 0 && nHeight == 0); }

};

class CAssetDB : public CLevelDB {
public:
    CAssetDB(size_t nCacheSize, bool fMemory, bool fWipe) : CLevelDB(GetDataDir() / "assets", nCacheSize, fMemory, fWipe) {}

    bool WriteAsset(const std::vector<unsigned char>& name, std::vector<CAsset>& vtxPos) {
        return Write(make_pair(std::string("asseti"), name), vtxPos);
    }

    bool EraseAsset(const std::vector<unsigned char>& name) {
        return Erase(make_pair(std::string("asseti"), name));
    }

    bool ReadAsset(const std::vector<unsigned char>& name, std::vector<CAsset>& vtxPos) {
        return Read(make_pair(std::string("asseti"), name), vtxPos);
    }

    bool ExistsAsset(const std::vector<unsigned char>& name) {
        return Exists(make_pair(std::string("asseti"), name));
    }

    bool WriteAssetFees(std::vector<CAssetFee>& vtxPos) {
        return Write(make_pair(std::string("asseti"), std::string("assettxf")), vtxPos);
    }

    bool ReadAssetFees(std::vector<CAssetFee>& vtxPos) {
        return Read(make_pair(std::string("asseti"), std::string("assettxf")), vtxPos);
    }

    bool ScanAssets(
            const std::vector<unsigned char>& vchName,
            unsigned int nMax,
            std::vector<std::pair<std::vector<unsigned char>, CAsset> >& assetScan);

    bool ReconstructAssetIndex(CBlockIndex *pindexRescan);
};
extern std::list<CAssetFee> lstAssetFees;

class CAssetCoin
{
public:
    CAsset asset;
    int op;
    int nOut;
    std::vector<std::vector<unsigned char> > vvch;
    int nHeight;
    int64 nValue;


    CAssetCoin(CAsset &aIn,  int o, int n, std::vector<std::vector<unsigned char> >& vv, int nh, int64 v)
    {
        asset = aIn;
        op = o;
        nOut = n;
        vvch = vv;
        nHeight = nh;
        nValue = v;
    }

    std::string ToString() const
    {
       // return strprintf("COutput(%s, %d, %d) [%s]", tx->GetHash().ToString().c_str(), i, nDepth, FormatMoney(tx->vout[i].nValue).c_str());
    	return "";
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};


bool GetTxOfAsset(CAssetDB& dbAsset, const std::vector<unsigned char> &vchAsset, CTransaction& tx);
bool GetTxOfAssetSend(CAssetDB& dbAsset, const std::vector<unsigned char> &vchAsset, CTransaction& tx);

#endif // ASSET_H
