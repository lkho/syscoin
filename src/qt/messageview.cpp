/*
 * Syscoin Developers 2016
 */
#include "messageview.h"
#include "bitcoingui.h"


#include "clientmodel.h"
#include "walletmodel.h"
#include "optionsmodel.h"
#include "inmessagelistpage.h"
#include "outmessagelistpage.h"
#include "messagetablemodel.h"
#include "ui_interface.h"

#include <QAction>
#if QT_VERSION < 0x050000
#include <QDesktopServices>
#else
#include <QStandardPaths>
#endif
#include <QPushButton>

MessageView::MessageView(QStackedWidget *parent, BitcoinGUI *_gui):
    gui(_gui),
    clientModel(0),
    walletModel(0)
{
	tabWidget = new QTabWidget();
    inMessageListPage = new InMessageListPage();
	outMessageListPage = new OutMessageListPage();
	tabWidget->addTab(inMessageListPage, tr("&Inbox"));
	tabWidget->setTabIcon(0, QIcon(":/icons/inmail"));
	tabWidget->addTab(outMessageListPage, tr("&Outbox"));
	tabWidget->setTabIcon(1, QIcon(":/icons/outmail"));
	parent->addWidget(tabWidget);

}

MessageView::~MessageView()
{
}

void MessageView::setBitcoinGUI(BitcoinGUI *gui)
{
    this->gui = gui;
}

void MessageView::setClientModel(ClientModel *clientModel)
{
    this->clientModel = clientModel;
    if (clientModel)
    {    
        inMessageListPage->setOptionsModel(clientModel->getOptionsModel());
		outMessageListPage->setOptionsModel(clientModel->getOptionsModel());
    }
}

void MessageView::setWalletModel(WalletModel *walletModel)
{

    this->walletModel = walletModel;
    if (walletModel)
    {
        inMessageListPage->setModel(walletModel, walletModel->getMessageTableModelIn());
		outMessageListPage->setModel(walletModel, walletModel->getMessageTableModelOut());

    }
}


void MessageView::gotoMessageListPage()
{
	tabWidget->setCurrentWidget(inMessageListPage);
}


bool MessageView::handleURI(const QString& strURI)
{
 // URI has to be valid
    if (inMessageListPage->handleURI(strURI) || outMessageListPage->handleURI(strURI))
    {
        gotoMessageListPage();
        emit showNormalIfMinimized();
        return true;
    }
    
    return false;
}
