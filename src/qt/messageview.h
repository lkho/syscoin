/*
 * Syscoin Developers 2016
 */
#ifndef MESSAGEVIEW_H
#define MESSAGEVIEW_H

#include <QStackedWidget>

class BitcoinGUI;
class ClientModel;
class WalletModel;
class InMessageListPage;
class OutMessageListPage;

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
  MessageView class. This class represents the view to the syscoin messagees
  
*/
class MessageView: public QObject
 {
     Q_OBJECT

public:
    explicit MessageView(QStackedWidget *parent, BitcoinGUI *_gui);
    ~MessageView();

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
    InMessageListPage *inMessageListPage;
	OutMessageListPage *outMessageListPage;

public:
    /** Switch to offer page */
    void gotoMessageListPage();

signals:
    /** Signal that we want to show the main window */
    void showNormalIfMinimized();
};

#endif // MESSAGEVIEW_H
