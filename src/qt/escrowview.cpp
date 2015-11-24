/*
 * Syscoin Developers 2016
 */
#include "escrowview.h"
#include "bitcoingui.h"


#include "clientmodel.h"
#include "walletmodel.h"
#include "optionsmodel.h"
#include "escrowlistpage.h"
#include "myescrowlistpage.h"
#include "escrowtablemodel.h"
#include "ui_interface.h"

#include <QAction>
#if QT_VERSION < 0x050000
#include <QDesktopServices>
#else
#include <QStandardPaths>
#endif
#include <QPushButton>

EscrowView::EscrowView(QStackedWidget *parent, BitcoinGUI *_gui):
    gui(_gui),
    clientModel(0),
    walletModel(0)
{
	tabWidget = new QTabWidget();
    escrowListPage = new EscrowListPage();
    myEscrowListPage = new MyEscrowListPage();
	
	tabWidget->addTab(myEscrowListPage, tr("&My Escrows"));
	tabWidget->addTab(escrowListPage, tr("&Search"));
	tabWidget->setTabIcon(0, QIcon(":/icons/escrow"));
	tabWidget->setTabIcon(1, QIcon(":/icons/search"));

	parent->addWidget(tabWidget);

}

EscrowView::~EscrowView()
{
}

void EscrowView::setBitcoinGUI(BitcoinGUI *gui)
{
    this->gui = gui;
}

void EscrowView::setClientModel(ClientModel *clientModel)
{
    this->clientModel = clientModel;
    if (clientModel)
    {    
        escrowListPage->setOptionsModel(clientModel->getOptionsModel());
		myEscrowListPage->setOptionsModel(clientModel,clientModel->getOptionsModel());
    }
}

void EscrowView::setWalletModel(WalletModel *walletModel)
{

    this->walletModel = walletModel;
    if (walletModel)
    {
        escrowListPage->setModel(walletModel, walletModel->getEscrowTableModelAll());
		myEscrowListPage->setModel(walletModel, walletModel->getEscrowTableModelMine());

    }
}


void EscrowView::gotoEscrowListPage()
{
	tabWidget->setCurrentWidget(myEscrowListPage);
}


bool EscrowView::handleURI(const QString& strURI)
{
 // URI has to be valid
    if (escrowListPage->handleURI(strURI))
    {
        gotoEscrowListPage();
        emit showNormalIfMinimized();
        return true;
    }
	else if (myEscrowListPage->handleURI(strURI))
    {
        gotoEscrowListPage();
        emit showNormalIfMinimized();
        return true;
    }   
    return false;
}
