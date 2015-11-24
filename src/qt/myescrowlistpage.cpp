/*
 * Syscoin Developers 2016
 */
#include "myescrowlistpage.h"
#include "ui_myescrowlistpage.h"
#include "escrowtablemodel.h"
#include "newmessagedialog.h"
#include "clientmodel.h"
#include "optionsmodel.h"
#include "walletmodel.h"
#include "bitcoingui.h"
#include "bitcoinrpc.h"
#include "script.h"
#include "csvmodelwriter.h"
#include "guiutil.h"

#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QMenu>

using namespace std;
using namespace json_spirit;
extern int nBestHeight;
int64 GetEscrowNetworkFee(opcodetype seed, unsigned int nHeight);
extern const CRPCTable tableRPC;
MyEscrowListPage::MyEscrowListPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MyEscrowListPage),
    model(0),
    optionsModel(0)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    ui->newEscrow->setIcon(QIcon());
    ui->copyEscrow->setIcon(QIcon());
    ui->exportButton->setIcon(QIcon());
	ui->refreshButton->setIcon(QIcon());
	ui->releaseButton->setIcon(QIcon());
	ui->refundButton->setIcon(QIcon());
	ui->completeButton->setIcon(QIcon());
	ui->buyerMessageButton->setIcon(QIcon());
	ui->sellerMessageButton->setIcon(QIcon());
	ui->arbiterMessageButton->setIcon(QIcon());
#endif

	ui->buttonBox->setVisible(false);

    ui->labelExplanation->setText(tr("These are your registered Syscoin Escrows. Escrow operations (create, release, refund, complete) take 2-5 minutes to become active."));
	
	
    // Context menu actions
    QAction *copyEscrowAction = new QAction(ui->copyEscrow->text(), this);
    releaseAction = new QAction(tr("Release Escrow"), this);
	refundAction = new QAction(tr("Refund Escrow"), this);
	completeAction = new QAction(tr("Complete Escrow"), this);

    buyerMessageAction = new QAction(tr("Send Message To Buyer"), this);
	sellerMessageAction = new QAction(tr("Send Message To Seller"), this);
	arbiterMessageAction = new QAction(tr("Send Message To Arbiter"), this);

    // Build context menu
    contextMenu = new QMenu();
    contextMenu->addAction(copyEscrowAction);
	contextMenu->addAction(buyerMessageAction);
	contextMenu->addAction(sellerMessageAction);
	contextMenu->addAction(arbiterMessageAction);
    contextMenu->addSeparator();
	contextMenu->addAction(releaseAction);
	contextMenu->addAction(refundAction);
	contextMenu->addAction(completeAction);
    // Connect signals for context menu actions
    connect(copyEscrowAction, SIGNAL(triggered()), this, SLOT(on_copyEscrow_clicked()));
	connect(releaseAction, SIGNAL(triggered()), this, SLOT(on_releaseButton_clicked()));
	connect(refundAction, SIGNAL(triggered()), this, SLOT(on_refundButton_clicked()));
	connect(completeAction, SIGNAL(triggered()), this, SLOT(on_completeButton_clicked()));

	connect(buyerMessageAction, SIGNAL(triggered()), this, SLOT(on_buyerMessageButton_clicked()));
	connect(sellerMessageAction, SIGNAL(triggered()), this, SLOT(on_sellerMessageButton_clicked()));
	connect(arbiterMessageAction, SIGNAL(triggered()), this, SLOT(on_arbiterMessageButton_clicked()));

    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));

    // Pass through accept action from button box
    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));

}

MyEscrowListPage::~MyEscrowListPage()
{
    delete ui;
}
void MyEscrowListPage::showEvent ( QShowEvent * event )
{
    if(!walletModel) return;

}
void MyEscrowListPage::setModel(WalletModel *walletModel, EscrowTableModel *model)
{
    this->model = model;
	this->walletModel = walletModel;
    if(!model) return;
    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);

  
	// Receive filter
	proxyModel->setFilterRole(EscrowTableModel::TypeRole);

   

	ui->tableView->setModel(proxyModel);
	ui->tableView->sortByColumn(0, Qt::AscendingOrder);
    ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableView->setSelectionMode(QAbstractItemView::SingleSelection);
     // Set column widths
#if QT_VERSION < 0x050000
    ui->tableView->horizontalHeader()->setResizeMode(EscrowTableModel::Escrow, QHeaderView::ResizeToContents);
	ui->tableView->horizontalHeader()->setResizeMode(EscrowTableModel::Time, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setResizeMode(EscrowTableModel::Arbiter, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(EscrowTableModel::Seller, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(EscrowTableModel::Offer, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(EscrowTableModel::OfferAccept, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(EscrowTableModel::Total, QHeaderView::ResizeToContents);
	ui->tableView->horizontalHeader()->setResizeMode(EscrowTableModel::Status, QHeaderView::ResizeToContents);
#else
    ui->tableView->horizontalHeader()->setSectionResizeMode(EscrowTableModel::Escrow, QHeaderView::ResizeToContents);
	ui->tableView->horizontalHeader()->setSectionResizeMode(EscrowTableModel::Time, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setSectionResizeMode(EscrowTableModel::Arbiter, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(EscrowTableModel::Seller, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(EscrowTableModel::Offer, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(EscrowTableModel::OfferAccept, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(EscrowTableModel::Total, QHeaderView::ResizeToContents);
	ui->tableView->horizontalHeader()->setSectionResizeMode(EscrowTableModel::Status, QHeaderView::ResizeToContents);
#endif

    connect(ui->tableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection,QItemSelection)),
            this, SLOT(selectionChanged()));

    // Select row for newly created escrow
    connect(model, SIGNAL(rowsInserted(QModelIndex,int,int)), this, SLOT(selectNewEscrow(QModelIndex,int,int)));

    selectionChanged();
}

void MyEscrowListPage::setOptionsModel(ClientModel* clientmodel, OptionsModel *optionsModel)
{
    this->optionsModel = optionsModel;
	this->clientModel = clientmodel;
}

void MyEscrowListPage::on_copyEscrow_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, EscrowTableModel::Escrow);
}

void MyEscrowListPage::on_releaseButton_clicked()
{
 	if(!model)	
		return;
	if(!ui->tableView->selectionModel())
        return;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if(selection.isEmpty())
    {
        return;
    }
	QString escrow = selection.at(0).data(EscrowTableModel::EscrowRole).toString();
	Array params;
	int updateFee = (double)GetEscrowNetworkFee(OP_ESCROW_RELEASE, nBestHeight)/(double)COIN;
	string updateFeeStr = strprintf("%.2f", updateFee);
    QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm Escrow Release"),
        tr("Warning: Releasing an escrow will cost ") + QString::fromStdString(updateFeeStr) + " SYS<br><br>" + tr("Are you sure you wish release this escrow?"),
			 QMessageBox::Yes|QMessageBox::Cancel,
			 QMessageBox::Cancel);
	if(retval != QMessageBox::Yes)
	{
		return;
	}
	string strMethod = string("escrowrelease");
	params.push_back(escrow.toStdString());
	try {
		Value result = tableRPC.execute(strMethod, params);
	}
	catch (Object& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
        tr("Error releasing escrow: \"%1\"").arg(QString::fromStdString(strError)),
			QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
            tr("General exception releasing escrow"),
			QMessageBox::Ok, QMessageBox::Ok);
	}	
}
void MyEscrowListPage::on_refundButton_clicked()
{
	if(!model)	
		return;
	if(!ui->tableView->selectionModel())
        return;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if(selection.isEmpty())
    {
        return;
    }
	QString escrow = selection.at(0).data(EscrowTableModel::EscrowRole).toString();
	Array params;
	int updateFee = (double)GetEscrowNetworkFee(OP_ESCROW_REFUND, nBestHeight)/(double)COIN;
	string updateFeeStr = strprintf("%.2f", updateFee);
    QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm Escrow Refund"),
        tr("Warning: Refunding an escrow will cost ") + QString::fromStdString(updateFeeStr) + " SYS<br><br>" + tr("Are you sure you wish refund this escrow?"),
			 QMessageBox::Yes|QMessageBox::Cancel,
			 QMessageBox::Cancel);
	if(retval != QMessageBox::Yes)
	{
		return;
	}
	string strMethod = string("escrowrefund");
	params.push_back(escrow.toStdString());
	try {
		Value result = tableRPC.execute(strMethod, params);
	}
	catch (Object& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
        tr("Error refunding escrow: \"%1\"").arg(QString::fromStdString(strError)),
			QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
            tr("General exception refunding escrow"),
			QMessageBox::Ok, QMessageBox::Ok);
	}
}
void MyEscrowListPage::on_completeButton_clicked()
{
	if(!model)	
		return;
	if(!ui->tableView->selectionModel())
        return;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if(selection.isEmpty())
    {
        return;
    }
	QString escrow = selection.at(0).data(EscrowTableModel::EscrowRole).toString();
	Array params;
	string strMethod = string("escrowclaimrelease");
	params.push_back(escrow.toStdString());
	try {
		Value result = tableRPC.execute(strMethod, params);
	}
	catch (Object& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
        tr("Error completing escrow: \"%1\"").arg(QString::fromStdString(strError)),
			QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
            tr("General exception completing escrow"),
			QMessageBox::Ok, QMessageBox::Ok);
	}

}
void MyEscrowListPage::on_buyerMessageButton_clicked()
{
 	if(!model)	
		return;
	if(!ui->tableView->selectionModel())
        return;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if(selection.isEmpty())
    {
        return;
    }
	QString buyerKey = selection.at(0).data(EscrowTableModel::BuyerKeyRole).toString();
	// send message to seller
	NewMessageDialog dlg(NewMessageDialog::NewMessage, buyerKey);   
	dlg.exec();
}
void MyEscrowListPage::on_sellerMessageButton_clicked()
{
 	if(!model)	
		return;
	if(!ui->tableView->selectionModel())
        return;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if(selection.isEmpty())
    {
        return;
    }
	QString sellerAlias = selection.at(0).data(EscrowTableModel::SellerRole).toString();
	// send message to seller
	NewMessageDialog dlg(NewMessageDialog::NewMessage, sellerAlias);   
	dlg.exec();
}
void MyEscrowListPage::on_arbiterMessageButton_clicked()
{
 	if(!model)	
		return;
	if(!ui->tableView->selectionModel())
        return;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if(selection.isEmpty())
    {
        return;
    }
	QString arbAlias = selection.at(0).data(EscrowTableModel::ArbiterRole).toString();
	// send message to arbiter
	NewMessageDialog dlg(NewMessageDialog::NewMessage, arbAlias);   
	dlg.exec();
}
void MyEscrowListPage::on_refreshButton_clicked()
{
    if(!model)
        return;
    model->refreshEscrowTable();
}
void MyEscrowListPage::on_newEscrow_clicked()
{
    if(!model)
        return;

   /* NewEscrowDialog dlg;
    dlg.setModel(walletModel,model);
    if(dlg.exec())
    {
        newEscrowToSelect = dlg.getEscrow();
    }*/
}
void MyEscrowListPage::selectionChanged()
{
    // Set button states based on selected tab and selection
    QTableView *table = ui->tableView;
    if(!table->selectionModel())
        return;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();

	
    if(table->selectionModel()->hasSelection())
    {
		QString status = selection.at(0).data(EscrowTableModel::StatusRole).toString();
		releaseAction->setEnabled(false);
		refundAction->setEnabled(false);
		completeAction->setEnabled(false);
		ui->refundButton->setEnabled(false);
		ui->releaseButton->setEnabled(false);
		ui->completeButton->setEnabled(false);
		buyerMessageAction->setEnabled(true);
		sellerMessageAction->setEnabled(true);
		arbiterMessageAction->setEnabled(true);
		ui->buyerMessageButton->setEnabled(true);
		ui->sellerMessageButton->setEnabled(true);
		ui->arbiterMessageButton->setEnabled(true);

        ui->copyEscrow->setEnabled(true);
		if(status == QString("inescrow"))
		{
			releaseAction->setEnabled(true);
			ui->refundButton->setEnabled(true);
			ui->releaseButton->setEnabled(true);
			refundAction->setEnabled(true);
		}
		else if(status == QString("escrowreleased"))
		{
			completeAction->setEnabled(true);
			ui->completeButton->setEnabled(true);
		}
		else if(status == QString("escrowrefunded"))
		{
			completeAction->setEnabled(true);
			ui->completeButton->setEnabled(true);
		}
		else if(status == QString("complete"))
		{
			buyerMessageAction->setEnabled(false);
			sellerMessageAction->setEnabled(false);
			arbiterMessageAction->setEnabled(false);
			ui->buyerMessageButton->setEnabled(false);
			ui->sellerMessageButton->setEnabled(false);
			ui->arbiterMessageButton->setEnabled(false);
		}
    }
    else
    {
        ui->copyEscrow->setEnabled(false);
		releaseAction->setEnabled(false);
		refundAction->setEnabled(false);
		completeAction->setEnabled(false);
		ui->refundButton->setEnabled(false);
		ui->releaseButton->setEnabled(false);
		ui->completeButton->setEnabled(false);
		ui->buyerMessageButton->setEnabled(false);
		ui->sellerMessageButton->setEnabled(false);
		ui->arbiterMessageButton->setEnabled(false);
		buyerMessageAction->setEnabled(false);
		sellerMessageAction->setEnabled(false);
		arbiterMessageAction->setEnabled(false);
    }
}



void MyEscrowListPage::on_exportButton_clicked()
{
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(
            this,
            tr("Export Escrow Data"), QString(),
            tr("Comma separated file (*.csv)"));

    if (filename.isNull()) return;

    CSVModelWriter writer(filename);

    // name, column, role
    writer.setModel(proxyModel);
    writer.addColumn("Escrow", EscrowTableModel::Escrow, Qt::EditRole);
	writer.addColumn("Time", EscrowTableModel::Time, Qt::EditRole);
    writer.addColumn("Arbiter", EscrowTableModel::Arbiter, Qt::EditRole);
	writer.addColumn("Seller", EscrowTableModel::Seller, Qt::EditRole);
	writer.addColumn("Offer", EscrowTableModel::Offer, Qt::EditRole);
	writer.addColumn("OfferAccept", EscrowTableModel::OfferAccept, Qt::EditRole);
	writer.addColumn("Total", EscrowTableModel::Total, Qt::EditRole);
	writer.addColumn("Status", EscrowTableModel::Status, Qt::EditRole);
    if(!writer.write())
    {
        QMessageBox::critical(this, tr("Error exporting"), tr("Could not write to file %1.").arg(filename),
                              QMessageBox::Abort, QMessageBox::Abort);
    }
}



void MyEscrowListPage::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if(index.isValid()) {
        contextMenu->exec(QCursor::pos());
    }
}

void MyEscrowListPage::selectNewEscrow(const QModelIndex &parent, int begin, int /*end*/)
{
    QModelIndex idx = proxyModel->mapFromSource(model->index(begin, EscrowTableModel::Escrow, parent));
    if(idx.isValid() && (idx.data(Qt::EditRole).toString() == newEscrowToSelect))
    {
        // Select row of newly created escrow, once
        ui->tableView->setFocus();
        ui->tableView->selectRow(idx.row());
        newEscrowToSelect.clear();
    }
}
bool MyEscrowListPage::handleURI(const QString& strURI)
{
 
    return false;
}
