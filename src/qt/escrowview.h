/*
 * Syscoin Developers 2016
 */
#ifndef ESCROWVIEW_H
#define ESCROWVIEW_H

#include <QStackedWidget>

class BitcoinGUI;
class ClientModel;
class WalletModel;
class EscrowListPage;
class MyEscrowListPage;

QT_BEGIN_NAMESPACE
class QObject;
class QWidget;
class QLabel;
class QModelIndex;
class QTabWidget;
class QStackedWidget;
class QAction;
QT_END_NAMESPACE

/*
  EscrowView class. This class represents the view to the syscoin Escrows
  
*/
class EscrowView: public QObject
 {
     Q_OBJECT

public:
    explicit EscrowView(QStackedWidget *parent, BitcoinGUI *_gui);
    ~EscrowView();

    void setBitcoinGUI(BitcoinGUI *gui);
    /** Set the client model.
        The client model represents the part of the core that communicates with the P2P network, and is wallet-agnostic.
    */
    void setClientModel(ClientModel *clientModel);
    /** Set the wallet model.
        The wallet model represents a bitcoin wallet, and offers access to the list of transactions, address book and sending
        functionality.
    */
    void setWalletModel(WalletModel *walletModel);
    
    bool handleURI(const QString &uri);


private:
    BitcoinGUI *gui;
    ClientModel *clientModel;
    WalletModel *walletModel;

    QTabWidget *tabWidget;
    EscrowListPage *escrowListPage;
	MyEscrowListPage *myEscrowListPage;


public:
    /** Switch to offer page */
    void gotoEscrowListPage();

signals:
    /** Signal that we want to show the main window */
    void showNormalIfMinimized();
};

#endif // ESCROWVIEW_H
