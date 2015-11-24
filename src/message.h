#ifndef MESSAGE_H
#define MESSAGE_H

#include "bitcoinrpc.h"
#include "leveldb.h"
#include "script.h"
#include "serialize.h"
class CTransaction;
class CTxOut;
class CValidationState;
class CCoinsViewCache;
class COutPoint;
class CCoins;
class CScript;
class CWalletTx;
class CDiskTxPos;

bool CheckMessageInputs(CBlockIndex *pindex, const CTransaction &tx, CValidationState &state, CCoinsViewCache &inputs, bool fBlock, bool fMiner, bool fJustCheck);
bool IsMessageMine(const CTransaction& tx);
bool IsMessageMine(const CTransaction& tx, const CTxOut& txout);
std::string SendMessageMoneyWithInputTx(std::vector<std::pair<CScript, int64> >& vecSend, int64 nValue, int64 nNetFee, CWalletTx& wtxIn, CWalletTx& wtxNew, 
    bool fAskFee, const std::string& txData);
std::string SendMessageMoneyWithInputTx(CScript scriptPubKey, int64 nValue,
        int64 nNetFee, CWalletTx& wtxIn, CWalletTx& wtxNew, bool fAskFee,
        const std::string& txData = "");
bool CreateMessageTransactionWithInputTx(const std::vector<std::pair<CScript, int64> >& vecSend, CWalletTx& wtxIn,
                                      int nTxOut, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet, const std::string& txData);

bool DecodeMessageTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch, int nHeight);
bool DecodeMessageTx(const CCoins& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch, int nHeight);
bool DecodeMessageScript(const CScript& script, int& op, std::vector<std::vector<unsigned char> > &vvch);
bool IsMessageOp(int op);
int IndexOfMessageOutput(const CTransaction& tx);
bool GetValueOfMessageTxHash(const uint256 &txHash, std::vector<unsigned char>& vchValue, uint256& hash, int& nHeight);
int GetMessageDisplayExpirationDepth();
int64 GetMessageNetworkFee(opcodetype seed, unsigned int nHeight);
int64 GetMessageNetFee(const CTransaction& tx);
bool InsertMessageFee(CBlockIndex *pindex, uint256 hash, uint64 nValue);
bool ExtractMessageAddress(const CScript& script, std::string& address);

std::string messageFromOp(int op);


class CBitcoinAddress;

class CMessage {
public:
    std::vector<unsigned char> vchRand;
	std::vector<unsigned char> vchPubKeyTo;
	std::vector<unsigned char> vchPubKeyFrom;
	std::vector<unsigned char> vchSubject;
	std::vector<unsigned char> vchFrom;
	std::vector<unsigned char> vchTo;
	std::vector<unsigned char> vchMessageTo;
	std::vector<unsigned char> vchMessageFrom;
    uint256 txHash;
    uint64 nHeight;
    CMessage() {
        SetNull();
    }
    CMessage(const CTransaction &tx) {
        SetNull();
        UnserializeFromTx(tx);
    }
    IMPLEMENT_SERIALIZE (
        READWRITE(vchRand);
        READWRITE(vchPubKeyTo);
		READWRITE(vchPubKeyFrom);
		READWRITE(vchSubject);
		READWRITE(vchFrom);
		READWRITE(vchTo);
		READWRITE(vchMessageTo);
		READWRITE(vchMessageFrom);
		READWRITE(txHash);
		READWRITE(nHeight);
    )

    friend bool operator==(const CMessage &a, const CMessage &b) {
        return (
        a.vchRand == b.vchRand
        && a.vchPubKeyTo == b.vchPubKeyTo
		&& a.vchPubKeyFrom == b.vchPubKeyFrom
		&& a.vchSubject == b.vchSubject
		&& a.vchMessageTo == b.vchMessageTo
		&& a.vchMessageFrom == b.vchMessageFrom
		&& a.txHash == b.txHash
		&& a.nHeight == b.nHeight
		&& a.vchFrom == b.vchFrom
		&& a.vchTo == b.vchTo
        );
    }

    CMessage operator=(const CMessage &b) {
        vchRand = b.vchRand;
        vchPubKeyTo = b.vchPubKeyTo;
		vchPubKeyFrom = b.vchPubKeyFrom;
		vchSubject = b.vchSubject;
		vchMessageTo = b.vchMessageTo;
		vchMessageFrom = b.vchMessageFrom;
		txHash = b.txHash;
		nHeight = b.nHeight;
		vchFrom = b.vchFrom;
		vchTo = b.vchTo;
        return *this;
    }

    friend bool operator!=(const CMessage &a, const CMessage &b) {
        return !(a == b);
    }

    void SetNull() { txHash=0; nHeight = 0;vchRand.clear(); vchFrom.clear(); vchTo.clear(); vchPubKeyTo.clear(); vchPubKeyFrom.clear(); vchSubject.clear(); vchMessageTo.clear();vchMessageFrom.clear();}
    bool IsNull() const { return txHash == 0 && nHeight == 0 && vchRand.empty(); }
    bool UnserializeFromTx(const CTransaction &tx);
    std::string SerializeToString();
};


class CMessageDB : public CLevelDB {
public:
    CMessageDB(size_t nCacheSize, bool fMemory, bool fWipe) : CLevelDB(GetDataDir() / "message", nCacheSize, fMemory, fWipe) {}

    bool WriteMessage(const std::vector<unsigned char>& name, std::vector<CMessage>& vtxPos) {
        return Write(make_pair(std::string("messagei"), name), vtxPos);
    }

    bool EraseMessage(const std::vector<unsigned char>& name) {
        return Erase(make_pair(std::string("messagei"), name));
    }

    bool ReadMessage(const std::vector<unsigned char>& name, std::vector<CMessage>& vtxPos) {
        return Read(make_pair(std::string("messagei"), name), vtxPos);
    }

    bool ExistsMessage(const std::vector<unsigned char>& name) {
        return Exists(make_pair(std::string("messagei"), name));
    }

    bool ScanMessages(
            const std::vector<unsigned char>& vchName,
            unsigned int nMax,
            std::vector<std::pair<std::vector<unsigned char>, CMessage> >& MessageScan);

    bool ReconstructMessageIndex(CBlockIndex *pindexRescan);
};

bool GetTxOfMessage(CMessageDB& dbMessage, const std::vector<unsigned char> &vchMessage, CTransaction& tx);

#endif // MESSAGE_H
