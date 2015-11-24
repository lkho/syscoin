#ifndef ALIAS_H
#define ALIAS_H

#include "bitcoinrpc.h"
#include "leveldb.h"
#include "script.h"
#include "serialize.h"
class CAliasIndex {
public:
    uint256 txHash;
    int64 nHeight;
    std::vector<unsigned char> vValue;
	std::vector<unsigned char> vchPubKey;
    CAliasIndex() { 
        SetNull();
    }
    CAliasIndex(const CTransaction &tx) {
        SetNull();
        UnserializeFromTx(tx);
    }
    CAliasIndex(uint256 txHashIn, uint64 nHeightIn, std::vector<unsigned char> vValueIn, std::vector<unsigned char> vchPubKeyIn) {
        txHash = txHashIn;
        nHeight = nHeightIn;
        vValue = vValueIn;
		vchPubKey = vchPubKeyIn;
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(txHash);
        READWRITE(VARINT(nHeight));
    	READWRITE(vValue);
		READWRITE(vchPubKey);
    )

    friend bool operator==(const CAliasIndex &a, const CAliasIndex &b) {
        return (a.nHeight == b.nHeight && a.txHash == b.txHash && a.vValue == b.vValue && a.vchPubKey == b.vchPubKey);
    }

    friend bool operator!=(const CAliasIndex &a, const CAliasIndex &b) {
        return !(a == b);
    }
    
    void SetNull() { txHash = 0; nHeight = 0; vValue.clear(); vchPubKey.clear(); }
    bool IsNull() const { return (nHeight == 0 && txHash == 0 && vValue.empty() && vchPubKey.empty()); }
	bool UnserializeFromTx(const CTransaction &tx);
    std::string SerializeToString();
};

class CAliasDB : public CLevelDB {
public:
    CAliasDB(size_t nCacheSize, bool fMemory, bool fWipe) : CLevelDB(GetDataDir() / "aliases", nCacheSize, fMemory, fWipe) {
    }

	bool WriteAlias(const std::vector<unsigned char>& name, std::vector<CAliasIndex>& vtxPos) {
		return Write(make_pair(std::string("namei"), name), vtxPos);
	}

	bool EraseAlias(const std::vector<unsigned char>& name) {
	    return Erase(make_pair(std::string("namei"), name));
	}
	bool ReadAlias(const std::vector<unsigned char>& name, std::vector<CAliasIndex>& vtxPos) {
		return Read(make_pair(std::string("namei"), name), vtxPos);
	}
	bool ExistsAlias(const std::vector<unsigned char>& name) {
	    return Exists(make_pair(std::string("namei"), name));
	}

    bool ScanNames(
            const std::vector<unsigned char>& vchName,
            unsigned int nMax,
            std::vector<std::pair<std::vector<unsigned char>, CAliasIndex> >& nameScan);

    bool ReconstructNameIndex(CBlockIndex *pindexRescan);
};





std::string stringFromVch(const std::vector<unsigned char> &vch);
std::vector<unsigned char> vchFromValue(const json_spirit::Value& value);
std::vector<unsigned char> vchFromString(const std::string &str);
std::string stringFromValue(const json_spirit::Value& value);

static const int SYSCOIN_TX_VERSION = 0x7400;
static const int64 MIN_AMOUNT = COIN;
static const unsigned int MAX_NAME_LENGTH = 255;
static const unsigned int MAX_VALUE_LENGTH = 1023;
static const unsigned int MIN_ACTIVATE_DEPTH = 1;
static const unsigned int MIN_ACTIVATE_DEPTH_CAKENET = 1;

bool CheckAliasInputs(
    CBlockIndex *pindex, const CTransaction &tx, CValidationState &state,
	CCoinsViewCache &inputs, bool fBlock, bool fMiner, bool fJustCheck);
bool ExtractAliasAddress(const CScript& script, std::string& address);
bool IsAliasMine(const CTransaction& tx);
bool IsAliasMine(const CTransaction& tx, const CTxOut& txout);
bool IsAliasOp(int op);


bool GetTxOfAlias(const std::vector<unsigned char> &vchName, CTransaction& tx);
int IndexOfNameOutput(const CTransaction& tx);
bool GetValueOfNameTxHash(const uint256& txHash, std::vector<unsigned char>& vchValue, uint256& hash, int& nHeight);
bool GetAliasOfTx(const CTransaction& tx, std::vector<unsigned char>& name);
bool GetValueOfAliasTx(const CTransaction& tx, std::vector<unsigned char>& value);
bool DecodeAliasTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch, int nHeight);
bool DecodeAliasTxInputs(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch, CCoinsViewCache &inputs);
bool GetValueOfAliasTx(const CCoins& tx, std::vector<unsigned char>& value);
bool DecodeAliasTx(const CCoins& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch, int nHeight);
bool DecodeAliasScript(const CScript& script, int& op, std::vector<std::vector<unsigned char> > &vvch);
bool DecodeAliasScript(const CScript& script, int& op,
		std::vector<std::vector<unsigned char> > &vvch, CScript::const_iterator& pc);
bool GetAliasAddress(const CTransaction& tx, std::string& strAddress);
bool GetAliasAddress(const CDiskTxPos& txPos, std::string& strAddress);
void GetAliasValue(const std::string& strName, std::string& strAddress);
std::string SendMoneyWithInputTx(CScript scriptPubKey, int64 nValue, int64 nNetFee, CWalletTx& wtxIn, CWalletTx& wtxNew, bool fAskFee, const std::string& txData = "");
bool CreateTransactionWithInputTx(const std::vector<std::pair<CScript, int64> >& vecSend, CWalletTx& wtxIn, int nTxOut, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet, const std::string& txData = "");
int64 GetAliasNetworkFee(opcodetype seed, unsigned int nHeight);
int64 GetAliasNetFee(const CTransaction& tx);
std::string getCurrencyToSYSFromAlias(const std::vector<unsigned char> &vchCurrency, int64 &nFee, const unsigned int &nHeightToFind, std::vector<std::string>& rateList, int &precision);
std::string aliasFromOp(int op);
bool IsAliasOp(int op);
int GetAliasDisplayExpirationDepth();
void UnspendInputs(CWalletTx& wtx);


#endif // ALIAS_H
