#ifndef TRUTHMARKET_H
#define TRUTHMARKET_H

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
class CTruthMarket;
class CCoin;
class CBitcoinAddress;

extern std::map<std::vector<unsigned char>, uint256> mapMyTruthMarkets;
extern std::map<std::vector<unsigned char>, std::set<uint256> > mapTruthMarketsPending;

bool CheckTruthMarketInputs(CBlockIndex *pindex, const CTransaction &tx, CValidationState &state, CCoinsViewCache &inputs,
                     std::map<std::vector<unsigned char>,uint256> &mapTestPool, bool fBlock, bool fMiner, bool fJustCheck);
bool IsTruthMarketMine(const CTransaction& tx);
bool IsTruthMarketMine(const CTransaction& tx, const CTxOut& txout, bool ignore_truthMarketnew = false);
bool IsMyTruthMarket(const CTransaction& tx, const CTxOut& txout);
CScript RemoveTruthMarketScriptPrefix(const CScript& scriptIn);
int CheckTruthMarketTransactionAtRelativeDepth(CBlockIndex* pindexBlock, int target, int maxDepth = -1);
bool DecodeTruthMarketTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch, int nHeight, bool bDecodeAll = false);
bool DecodeTruthMarketTx(CTruthMarket theTruthMarket, const CCoins& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch, int nHeight, bool bDecodeAll = false);
bool DecodeTruthMarketScript(const CScript& script, int& op, std::vector<std::vector<unsigned char> > &vvch);

bool IsTruthMarketOp(int op);
int IndexOfTruthMarketOutput(const CTransaction& tx);
int IndexOfTruthMarketExtraCoinsOutput(const CTransaction& tx);
uint64 GetTruthMarketFeeSubsidy(unsigned int nHeight);
bool GetValueOfTruthMarketTxHash(const uint256 &txHash, std::vector<unsigned char>& vchValue, uint256& hash, int& nHeight);
int GetTruthMarketTxHashHeight(const uint256 txHash);
int GetTruthMarketTxPosHeight(const CDiskTxPos& txPos);
int GetTruthMarketTxPosHeight2(const CDiskTxPos& txPos, int nHeight);
int GetTruthMarketDisplayExpirationDepth(int nHeight); // TODO CB remove references to 'expiration' - truthMarkets do not expire
int64 GetTruthMarketNetworkFee(int seed, int nHeight);
int64 GetTruthMarketNetFee(const CTransaction& tx);
bool InsertTruthMarketFee(CBlockIndex *pindex, uint256 hash, int nOp, uint64 nValue);
bool ExtractTruthMarketAddress(const CScript& script, std::string& address);
CScript CreateTruthMarketScript(const std::vector<std::vector<unsigned char> >& vvchArgs, uint160 truthMarketHash, CKeyID *dest = NULL, const CTxDestination *txd = NULL);
std::string stringFromVch(const std::vector<unsigned char> &vch);

std::string truthMarketFromOp(int op);

// class CTruthMarketState {
//     std::vector<unsigned char> vchTitle;
//     std::vector<unsigned char> vchGUID;

//     CTruthMarketState() {
//         SetNull();
//     }

//    	IMPLEMENT_SERIALIZE (
//    		READWRITE(vchTitle);
//         READWRITE(vchGUID);
//     )

//     friend bool operator==(const CTruthMarketState &a, const CTruthMarketState &b) {
//         return (
//         a.vchTitle == b.vchTitle
//         && a.vchGUID == b.vchGUID
//         );
//     }

//     CTruthMarketState operator=(const CTruthMarketState &b) {
//         vchTitle = b.vchTitle;
//         vchGUID = b.vchGUID;
//         return *this;
//     }

//     friend bool operator!=(const CTruthMarketState &a, const CTruthMarketState &b) {
//         return !(a == b);
//     }

//     void SetNull() { 
//         vchGUID.clear(); 
//         vchTitle.clear(); 
//     }

//     bool IsNull() const { 
//         return (
//             vchGUID.size() == 0 &&
//             vchTitle.size() == 0);
//     }
// };

class CTruthMarketDecision{
    std::vector<unsigned char> vchGUID;
    std::vector<unsigned char> vchTitle;
    std::vector<unsigned char> vchDescription;
    int64 type  = 0; // 0 = binary, 1 = scalar;
    int64 state = 0; // 0 = inactive, 1 = active, 2 = matured, 3 = disputed, 4 = resolved;
    int64 xmin  = 0;
    int64 xmax  = 0;

    CTruthMarketDecision() {
        SetNull();
    }

   	IMPLEMENT_SERIALIZE (
        READWRITE(vchGUID);
        READWRITE(vchTitle);
        READWRITE(vchDescription);
        READWRITE(type);
        READWRITE(state);
        READWRITE(xmin);
        READWRITE(xmax);
    )

    friend bool operator==(const CTruthMarketDecision &a, const CTruthMarketDecision &b) {
        return (
        a.vchGUID == b.vchGUID &&
        a.vchTitle == b.vchTitle &&
        a.vchDescription == b.vchDescription &&
        a.type == b.type &&
        a.state == b.state &&
        a.xmin == b.xmin &&
        a.xmax == b.xmax
        );
    }

    CTruthMarketDecision operator=(const CTruthMarketDecision &b) {
        vchGUID = b.vchGUID;
        vchTitle = b.vchTitle;
        vchDescription = b.vchDescription;
        type = b.type;
        state = b.state;
        xmin = b.xmin;
        xmax = b.xmax;
        return *this;
    }

    friend bool operator!=(const CTruthMarketDecision &a, const CTruthMarketDecision &b) {
        return !(a == b);
    }

    void SetNull() { 
        vchGUID.clear(); 
        vchTitle.clear(); 
        vchDescription.clear(); 
        type = state = xmin = xmax = 0;
    }

    bool IsNull() const { 
        return (
            vchGUID.size() == 0 &&
            vchTitle.size() == 0 &&
        	vchDescription.size() == 0 &&
			type == 0 && state == 0 && xmin == 0 && xmax == 0 );
    }
};

class CTruthMarket {
public:
    std::vector<unsigned char> vchGUID;
    std::vector<unsigned char> vchTitle;
    std::vector<unsigned char> vchDescription;
    int64 state = 0; // 0 = inactive , 1 = trading, 2 = disputed, 3 = audited, 4 = resolved

    std::vector<CTruthMarketDecision> vMarketDecisions;

    uint64 nOp;

    bool isGenesis;

    uint256 txHash;
    uint256 genTxHash;
    
    uint64 nHeight;
    uint64 nTime;
    uint256 hash;
    uint64 n;
    uint64 nFee;

    CTruthMarket() {
        SetNull();
    }

    CTruthMarket(const CTransaction &tx) {
        if(!UnserializeFromTx(tx))
            SetNull();
    }

    CTruthMarket(const CWalletTx &tx) {
        if(!UnserializeFromTx(tx))
            SetNull();
    }

    CTruthMarket(std::vector<unsigned char> &vchGUID) {
        if(!GetTruthMarket(vchGUID))
            SetNull();
    }

    CTruthMarket(const std::string &sData) {
        if(!GetTruthMarket(vchGUID))
            SetNull();
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(vchGUID);
        READWRITE(vchTitle);
        READWRITE(vchDescription);
        READWRITE(state);
        READWRITE(vMarketDecisions);
        READWRITE(isGenesis);
        READWRITE(txHash);
        READWRITE(genTxHash);       
        READWRITE(nHeight);
        READWRITE(nTime);
        READWRITE(hash);
        READWRITE(n);
        READWRITE(nFee);
        READWRITE(nOp);
    )

    void PutToTruthMarketList(std::vector<CTruthMarket> &truthMarketList) {
        assert(nHeight != 0 || txHash != 0);
        unsigned int i = truthMarketList.size()-1;
        BOOST_REVERSE_FOREACH(CTruthMarket o, truthMarketList) {
        	if(o.nHeight != 0 && o.nHeight == nHeight) {
                truthMarketList[i] = *this;
                return;
            }
        	else if(o.txHash != 0 && o.txHash == txHash) {
				truthMarketList[i] = *this;
				return;
        	}
            i--;
        }
        truthMarketList.push_back(*this);
    }

    bool GetTruthMarketFromList(const std::vector<CTruthMarket> &truthMarketList) {
        if(truthMarketList.size() == 0) return false;
        unsigned int i = truthMarketList.size()-1;
        BOOST_FOREACH(CTruthMarket o, truthMarketList) {
        	if(o.nHeight == nHeight) {
                *this = truthMarketList[i];
                return true;
            }
        	if(o.txHash == txHash) {
				*this = truthMarketList[i];
				return true;
			}
            i--;
        }
        *this = truthMarketList.back();
        return false;
    }

    bool GetTruthMarket(std::vector<unsigned char> &vchGUID); 

    bool GetTruthMarket(CTransaction &tx) {
        return UnserializeFromTx(tx);
    }

    bool GetTruthMarketControlFromList(const std::vector<CTruthMarket> &truthMarketList) {
        if(truthMarketList.size() == 0) return false;
        unsigned int i = truthMarketList.size()-1;
        BOOST_FOREACH(CTruthMarket o, truthMarketList) {
            if(o.nOp != XOP_ASSET_SEND) {
                if(nHeight != 0) {
                    if(o.nHeight == nHeight) {
                        *this = truthMarketList[i];
                        return true;
                    }
                } else if (txHash != 0) {
                    if(o.txHash == txHash) {
                        *this = truthMarketList[i];
                        return true;
                    }
                } else {
                    *this = truthMarketList[i];
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
    	CTruthMarket theTruthMarket = *this;
    	theTruthMarket.isGenesis = true;
    	theTruthMarket.txHash = theTruthMarket.genTxHash;
    	theTruthMarket.nQty = theTruthMarket.nTotalQty;
    	return Hash160(theTruthMarket.SerializeToString());
    }

    friend bool operator==(const CTruthMarket &a, const CTruthMarket &b) {
        return (
           a.vchTitle == b.vchTitle
        && a.vchGUID == b.vchGUID
        && a.vchDescription == b.vchDescription
        && a.genTxHash == b.genTxHash
        && a.state == b.state
        && a.isGenesis == b.isGenesis
        && a.nFee == b.nFee
        && a.n == b.n
        && a.hash == b.hash
        && a.txHash == b.txHash
        && a.nHeight == b.nHeight
        && a.nTime == b.nTime
        && a.nOp == b.nOp
        && a.vMarketStates == b.vMarketStates
        && a.vMarketDecisions == b.vMarketDecisions
        );
    }

    CTruthMarket operator=(const CTruthMarket &b) {
        vchTitle = b.vchTitle;
        vchGUID = b.vchGUID;
        vchDescription = b.vchDescription;
        isGenesis = b.isGenesis;
        genTxHash = b.genTxHash;
        state = b.state;
        nFee = b.nFee;
        n = b.n;
        hash = b.hash;
        txHash = b.txHash;
        nHeight = b.nHeight;
        nTime = b.nTime;
        nOp = b.nOp;
        vMarketStates = b.vMarketStates;
        vMarketDecisions = b.vMarketDecisions;
        return *this;
    }

    friend bool operator!=(const CTruthMarket &a, const CTruthMarket &b) {
        return !(a == b);
    }

    void SetNull() { 
        nHeight = n = nOp = state = 0; 
        txHash = genTxHash = hash = 0;
        isGenesis = false;
        vchGUID.clear(); 
        vchTitle.clear(); 
        vchDescription.clear(); 
        vMarketStates.clear();
        vMarketDecisions.clear();
    }

    bool IsNull() const { 
        return (
            txHash == 0  && 
            genTxHash == 0 && 
            hash == 0 && 
            nHeight == 0 && 
            nOp == 0 &&
            state == 0 &&
            vchGUI.size() == 0 &&
            vchTitle.size() == 0 &&
            vchDescription.size() == 0 &&
            vMarketDecisions.size() == 0);
    }

    bool IsGenesisTx(uint160 compareHash);

    int64 GetServiceFee(int seed, int height = -1) {
        return 0;
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

class CTruthMarketFee {
public:
    uint256 hash;
    uint64 nHeight;
    uint64 nTime;
    int nOp;
    uint64 nFee;

    CTruthMarketFee() {
        nTime = 0; nHeight = 0; hash = 0; nOp = 0;  nFee = 0;
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(hash);
        READWRITE(nHeight);
        READWRITE(nTime);
        READWRITE(nOp);
        READWRITE(nFee);
    )

    friend bool operator==(const CTruthMarketFee &a, const CTruthMarketFee &b) {
        return (
        a.nTime==b.nTime
        && a.hash==b.hash
        && a.nHeight==b.nHeight
        && a.nOp==b.nOp
        && a.nFee == b.nFee
        );
    }

    CTruthMarketFee operator=(const CTruthMarketFee &b) {
        nTime = b.nTime;
        nFee = b.nFee;
        hash = b.hash;
        nOp = b.nOp;
        nHeight = b.nHeight;
        return *this;
    }

    friend bool operator!=(const CTruthMarketFee &a, const CTruthMarketFee &b) { return !(a == b); }
    void SetNull() { hash = nTime = nHeight = nOp = nFee = 0;}
    bool IsNull() const { return (nTime == 0 && nFee == 0 && hash == 0 && nOp == 0 && nHeight == 0); }

};

class CTruthMarketDB : public CLevelDB {
public:
    CTruthMarketDB(size_t nCacheSize, bool fMemory, bool fWipe) : CLevelDB(GetDataDir() / "truthmarkets", nCacheSize, fMemory, fWipe) {}

    bool WriteTruthMarket(const std::vector<unsigned char>& guid, std::vector<CTruthMarket>& vtxPos) {
        return Write(make_pair(std::string("truthmarketi"), guid), vtxPos);
    }

    bool EraseTruthMarket(const std::vector<unsigned char>& guid) {
        return Erase(make_pair(std::string("truthmarketi"), guid));
    }

    bool ReadTruthMarket(const std::vector<unsigned char>& guid, std::vector<CTruthMarket>& vtxPos) {
        return Read(make_pair(std::string("truthmarketi"), guid), vtxPos);
    }

    bool ExistsTruthMarket(const std::vector<unsigned char>& guid) {
        return Exists(make_pair(std::string("truthmarketi"), guid));
    }
    
    bool WriteTruthMarketFees(std::vector<CTruthMarketFee>& vtxPos) {
        return Write(make_pair(std::string("truthmarketi"), std::string("truthmarkettxf")), vtxPos);
    }

    bool ReadTruthMarketFees(std::vector<CTruthMarketFee>& vtxPos) {
        return Read(make_pair(std::string("truthmarketi"), std::string("truthmarkettxf")), vtxPos);
    }

    bool ScanTruthMarkets(
            const std::vector<unsigned char>& vchName,
            unsigned int nMax,
            std::vector<std::pair<std::vector<unsigned char>, CTruthMarket> >& truthMarketScan);

    bool ReconstructTruthMarketIndex(CBlockIndex *pindexRescan);
};
extern std::list<CTruthMarketFee> lstTruthMarketFees;

class CTruthMarketCoin
{
public:
    CTruthMarket truthMarket;
    int op;
    int nOut;
    std::vector<std::vector<unsigned char> > vvch;
    int nHeight;
    int64 nValue;


    CTruthMarketCoin(CTruthMarket &aIn,  int o, int n, std::vector<std::vector<unsigned char> >& vv, int nh, int64 v)
    {
        truthMarket = aIn;
        op = o;
        nOut = n;
        vvch = vv;
        nHeight = nh;
        nValue = v;
    }

    std::string ToString() const
    {
       // return strprintf("CTruthMarketCoin(%s, %d, %d) [%s]", tx->GetHash().ToString().c_str(), i, nDepth, FormatMoney(tx->vout[i].nValue).c_str());
    	return "";
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};


bool GetTxOfTruthMarket(CTruthMarketDB& dbTruthMarket, const std::vector<unsigned char> &vchTruthMarket, CTransaction& tx);


#endif // TRUTHMARKET_H