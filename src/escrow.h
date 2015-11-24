#ifndef ESCROW_H
#define ESCROW_H

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

bool CheckEscrowInputs(CBlockIndex *pindex, const CTransaction &tx, CValidationState &state, CCoinsViewCache &inputs, bool fBlock, bool fMiner, bool fJustCheck);
bool IsEscrowMine(const CTransaction& tx);
bool IsEscrowMine(const CTransaction& tx, const CTxOut& txout);
std::string SendEscrowMoneyWithInputTx(std::vector<std::pair<CScript, int64> >& vecSend, int64 nValue, int64 nNetFee, CWalletTx& wtxIn, CWalletTx& wtxNew, 
    bool fAskFee, const std::string& txData);
std::string SendEscrowMoneyWithInputTx(CScript scriptPubKey, int64 nValue,
        int64 nNetFee, CWalletTx& wtxIn, CWalletTx& wtxNew, bool fAskFee,
        const std::string& txData = "");
std::string SendEscrowMoneyWithMultiInputTx(std::vector<std::pair<CScript, int64> > &vecSend, int64 nValue,
        int64 nNetFee, CWalletTx& wtxCertIn, CWalletTx& wtxEscrowIn, CWalletTx& wtxNew, bool fAskFee,
        const std::string& txData);
bool CreateEscrowTransactionWithInputTx(const std::vector<std::pair<CScript, int64> >& vecSend, CWalletTx& wtxIn,
                                      int nTxOut, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet, const std::string& txData);
bool CreateEscrowTransactionWithMultiInputTx(
        const std::vector<std::pair<CScript, int64> >& vecSend, CWalletTx& wtxCertIn, CWalletTx& wtxEscrowIn,
        int nTxCertOut, int nTxEscrowOut, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet,
        const std::string& txData);
bool DecodeEscrowTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch, int nHeight);
bool DecodeEscrowTx(const CCoins& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch, int nHeight);
bool DecodeEscrowScript(const CScript& script, int& op, std::vector<std::vector<unsigned char> > &vvch);
bool IsEscrowOp(int op);
int IndexOfEscrowOutput(const CTransaction& tx);
bool GetValueOfEscrowTxHash(const uint256 &txHash, std::vector<unsigned char>& vchValue, uint256& hash, int& nHeight);
int GetEscrowDisplayExpirationDepth();
int64 GetEscrowNetworkFee(opcodetype seed, unsigned int nHeight);
int64 GetEscrowNetFee(const CTransaction& tx);
bool InsertEscrowFee(CBlockIndex *pindex, uint256 hash, uint64 nValue);
bool ExtractEscrowAddress(const CScript& script, std::string& address);
bool GetNameOfEscrowTx(const CTransaction& tx, std::vector<unsigned char>& escrow);
std::string escrowFromOp(int op);


class CBitcoinAddress;

class CEscrow {
public:
    std::vector<unsigned char> vchRand;
	std::vector<unsigned char> vchBuyerKey;
	std::vector<unsigned char> vchSellerKey;
	std::vector<unsigned char> vchArbiterKey;
	std::string arbiter;
	std::string seller;
	std::vector<unsigned char> vchRedeemScript;
	std::vector<unsigned char> vchOffer;
	std::vector<unsigned char> vchPaymentMessage;
	std::vector<unsigned char> rawTx;
	std::vector<unsigned char> vchOfferAcceptLink;
	
    uint256 txHash;
	uint256 escrowInputTxHash;
    uint64 nHeight;
	unsigned int nQty;
	int64 nPricePerUnit;
    CEscrow() {
        SetNull();
    }
    CEscrow(const CTransaction &tx) {
        SetNull();
        UnserializeFromTx(tx);
    }
    IMPLEMENT_SERIALIZE (
        READWRITE(vchRand);
        READWRITE(vchBuyerKey);
		READWRITE(arbiter);
		READWRITE(vchSellerKey);
		READWRITE(seller);
		READWRITE(vchArbiterKey);
		READWRITE(vchRedeemScript);
        READWRITE(vchOffer);
		READWRITE(vchPaymentMessage);
		READWRITE(rawTx);
		READWRITE(vchOfferAcceptLink);
		READWRITE(txHash);
		READWRITE(escrowInputTxHash);
		READWRITE(VARINT(nHeight));
		READWRITE(VARINT(nQty));
		READWRITE(VARINT(nPricePerUnit));
		
		
    )

    friend bool operator==(const CEscrow &a, const CEscrow &b) {
        return (
        a.vchRand == b.vchRand
        && a.vchBuyerKey == b.vchBuyerKey
		&& a.vchSellerKey == b.vchSellerKey
        && a.arbiter == b.arbiter
		&& a.seller == b.seller
		&& a.vchArbiterKey == b.vchArbiterKey
		&& a.vchRedeemScript == b.vchRedeemScript
        && a.vchOffer == b.vchOffer
		&& a.vchPaymentMessage == b.vchPaymentMessage
		&& a.rawTx == b.rawTx
		&& a.vchOfferAcceptLink == b.vchOfferAcceptLink
		&& a.txHash == b.txHash
		&& a.escrowInputTxHash == b.escrowInputTxHash
		&& a.nHeight == b.nHeight
		&& a.nQty == b.nQty
		&& a.nPricePerUnit == b.nPricePerUnit
        );
    }

    CEscrow operator=(const CEscrow &b) {
        vchRand = b.vchRand;
        vchBuyerKey = b.vchBuyerKey;
		vchSellerKey = b.vchSellerKey;
        arbiter = b.arbiter;
		seller = b.seller;
		vchArbiterKey = b.vchArbiterKey;
		vchRedeemScript = b.vchRedeemScript;
        vchOffer = b.vchOffer;
		vchPaymentMessage = b.vchPaymentMessage;
		rawTx = b.rawTx;
		vchOfferAcceptLink = b.vchOfferAcceptLink;
		txHash = b.txHash;
		escrowInputTxHash = b.escrowInputTxHash;
		nHeight = b.nHeight;
		nQty = b.nQty;
		nPricePerUnit = b.nPricePerUnit;
        return *this;
    }

    friend bool operator!=(const CEscrow &a, const CEscrow &b) {
        return !(a == b);
    }

    void SetNull() { nHeight = 0; txHash = 0; arbiter = ""; seller = ""; escrowInputTxHash = 0; nQty = 0; nPricePerUnit = 0; vchRand.clear(); vchBuyerKey.clear(); vchArbiterKey.clear(); vchSellerKey.clear(); vchRedeemScript.clear(); vchOffer.clear(); rawTx.clear(); vchOfferAcceptLink.clear(); vchPaymentMessage.clear();}
    bool IsNull() const { return (txHash == 0 && escrowInputTxHash == 0 && nHeight == 0 && nQty == 0 && nPricePerUnit == 0 && vchRand.size() == 0); }
    bool UnserializeFromTx(const CTransaction &tx);
    std::string SerializeToString();
};


class CEscrowDB : public CLevelDB {
public:
    CEscrowDB(size_t nCacheSize, bool fMemory, bool fWipe) : CLevelDB(GetDataDir() / "escrow", nCacheSize, fMemory, fWipe) {}

    bool WriteEscrow(const std::vector<unsigned char>& name, std::vector<CEscrow>& vtxPos) {
        return Write(make_pair(std::string("escrowi"), name), vtxPos);
    }

    bool EraseEscrow(const std::vector<unsigned char>& name) {
        return Erase(make_pair(std::string("escrowi"), name));
    }

    bool ReadEscrow(const std::vector<unsigned char>& name, std::vector<CEscrow>& vtxPos) {
        return Read(make_pair(std::string("escrowi"), name), vtxPos);
    }

    bool ExistsEscrow(const std::vector<unsigned char>& name) {
        return Exists(make_pair(std::string("escrowi"), name));
    }

    bool ScanEscrows(
            const std::vector<unsigned char>& vchName,
            unsigned int nMax,
            std::vector<std::pair<std::vector<unsigned char>, CEscrow> >& escrowScan);

    bool ReconstructEscrowIndex(CBlockIndex *pindexRescan);
};

bool GetTxOfEscrow(CEscrowDB& dbEscrow, const std::vector<unsigned char> &vchEscrow, CEscrow& txPos, CTransaction& tx);

#endif // ESCROW_H
