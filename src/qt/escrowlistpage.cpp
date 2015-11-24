#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>

#include "escrowlistpage.h"
#include "ui_escrowlistpage.h"

#include "escrowtablemodel.h"
#include "optionsmodel.h"
#include "walletmodel.h"
#include "bitcoingui.h"
#include "bitcoinrpc.h"
#include "csvmodelwriter.h"
#include "guiutil.h"
#include "ui_interface.h"
#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QKeyEvent>
#include <QDateTime>
#include <QMenu>
#include "main.h"
using namespace std;
using namespace json_spirit;

extern const CRPCTable tableRPC;
extern string JSONRPCReply(const Value& result, const Value& error, const Value& id);
int GetEscrowDisplayExpirationDepth();
EscrowListPage::EscrowListPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EscrowListPage),
    model(0),
    optionsModel(0)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    ui->copyEscrow->setIcon(QIcon());
    ui->exportButton->setIcon(QIcon());
#endif

    ui->labelExplanation->setText(tr("Search for Syscoin Escrows. Select the number of results desired from the dropdown box and click Search."));
	
    // Context menu actions
    QAction *copyEscrowAction = new QAction(ui->copyEscrow->text(), this);
    QAction *copyOfferAction = new QAction(tr("&Copy Offer ID"), this);


    // Build context menu
    contextMenu = new QMenu();
    contextMenu->addAction(copyEscrowAction);
    contextMenu->addAction(copyOfferAction);

    // Connect signals for context menu actions
    connect(copyEscrowAction, SIGNAL(triggered()), this, SLOT(on_copyEscrow_clicked()));
    connect(copyOfferAction, SIGNAL(triggered()), this, SLOT(on_copyOffer_clicked()));
   
    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));


	ui->lineEditEscrowSearch->setPlaceholderText(tr("Enter search term. Search for arbiter/seller or escrow GUID. Empty will search for all."));
}

EscrowListPage::~EscrowListPage()
{
    delete ui;
}
void EscrowListPage::showEvent ( QShowEvent * event )
{
    if(!walletModel) return;

}
void EscrowListPage::setModel(WalletModel* walletModel, EscrowTableModel *model)
{
    this->model = model;
	this->walletModel = walletModel;
    if(!model) return;

    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterRole(EscrowTableModel::TypeRole);
    ui->tableView->setModel(proxyModel);
    ui->tableView->sortByColumn(1, Qt::DescendingOrder);

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

void EscrowListPage::setOptionsModel(OptionsModel *optionsModel)
{
    this->optionsModel = optionsModel;
}

void EscrowListPage::on_copyEscrow_clicked()
{
   
    GUIUtil::copyEntryData(ui->tableView, EscrowTableModel::Escrow);
}

void EscrowListPage::on_copyOffer_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, EscrowTableModel::Offer);
}


void EscrowListPage::selectionChanged()
{
    // Set button states based on selected tab and selection
    QTableView *table = ui->tableView;
    if(!table->selectionModel())
        return;

    if(table->selectionModel()->hasSelection())
    {
        ui->copyEscrow->setEnabled(true);
    }
    else
    {
        ui->copyEscrow->setEnabled(false);
    }
}
void EscrowListPage::keyPressEvent(QKeyEvent * event)
{
  if( event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter )
  {
	on_searchEscrow_clicked();
    event->accept();
  }
  else
    QDialog::keyPressEvent( event );
}
void EscrowListPage::on_exportButton_clicked()
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



void EscrowListPage::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if(index.isValid()) {
        contextMenu->exec(QCursor::pos());
    }
}

void EscrowListPage::selectNewEscrow(const QModelIndex &parent, int begin, int /*end*/)
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

void EscrowListPage::on_searchEscrow_clicked()
{
    if(!walletModel) return;
       Array params;
        Value valError;
        Object ret ;
        Value valResult;
        Array arr;
        Value valId;
        Value result ;
        string strReply;
        string strError;
        string strMethod = string("escrowfilter");
		string name_str;
		string time_str;
		string seller_str;
		string arbiter_str;
		string status_str;
		string offeraccept_str;
		string offer_str;
		string total_str;	
		string buyerkey_str;
		int unixTime;
		QDateTime dateTime;
        params.push_back(ui->lineEditEscrowSearch->text().toStdString());
        params.push_back(GetEscrowDisplayExpirationDepth());
		params.push_back(0);
		params.push_back(ui->comboBox->currentText().toInt());

        try {
            result = tableRPC.execute(strMethod, params);
        }
        catch (Object& objError)
        {
            strError = find_value(objError, "message").get_str();
            QMessageBox::critical(this, windowTitle(),
            tr("Error searching Escrow: \"%1\"").arg(QString::fromStdString(strError)),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        }
        catch(std::exception& e)
        {
            QMessageBox::critical(this, windowTitle(),
                tr("General exception when searching escrow"),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        }
		if (result.type() == array_type)
			{
				this->model->clear();
			
			  Array arr = result.get_array();
			  BOOST_FOREACH(Value& input, arr)
				{
				if (input.type() != obj_type)
					continue;
				Object& o = input.get_obj();
				name_str = "";
				time_str = "";
				seller_str = "";
				arbiter_str = "";
				status_str = "";
				offeraccept_str = "";
				offer_str = "";
				total_str = "";
				buyerkey_str = "";
				
				const Value& name_value = find_value(o, "escrow");
				if (name_value.type() == str_type)
					name_str = name_value.get_str();
				const Value& time_value = find_value(o, "time");
				if (time_value.type() == str_type)
					time_str = time_value.get_str();
				const Value& seller_value = find_value(o, "seller");
				if (seller_value.type() == str_type)
					seller_str = seller_value.get_str();
				const Value& arbiter_value = find_value(o, "arbiter");
				if (arbiter_value.type() == str_type)
					arbiter_str = arbiter_value.get_str();
				const Value& buyerkey_value = find_value(o, "buyerkey");
				if (buyerkey_value.type() == str_type)
					buyerkey_str = buyerkey_value.get_str();
				const Value& offer_value = find_value(o, "offer");
				if (offer_value.type() == str_type)
					offer_str = offer_value.get_str();
				const Value& offeraccept_value = find_value(o, "offeraccept");
				if (offeraccept_value.type() == str_type)
					offeraccept_str = offeraccept_value.get_str();
				const Value& total_value = find_value(o, "total");
				if (total_value.type() == str_type)
					total_str = total_value.get_str();
				const Value& status_value = find_value(o, "status");
				if (status_value.type() == str_type)
					status_str = status_value.get_str();

				unixTime = atoi(time_str.c_str());
				dateTime.setTime_t(unixTime);
				time_str = dateTime.toString().toStdString();

				model->addRow(QString::fromStdString(name_str), QString::fromStdString(time_str),
						QString::fromStdString(seller_str),
						QString::fromStdString(arbiter_str),
						QString::fromStdString(offer_str),
						QString::fromStdString(offeraccept_str),
						QString::fromStdString(total_str),
						QString::fromStdString(status_str),
						QString::fromStdString(buyerkey_str));
					this->model->updateEntry(QString::fromStdString(name_str), QString::fromStdString(time_str),
						QString::fromStdString(seller_str),
						QString::fromStdString(arbiter_str),
						QString::fromStdString(offer_str),
						QString::fromStdString(offeraccept_str),
						QString::fromStdString(total_str),
						QString::fromStdString(status_str), 
						QString::fromStdString(buyerkey_str), AllEscrow, CT_NEW);	
			  }

            
         }   
        else
        {
            QMessageBox::critical(this, windowTitle(),
                tr("Error: Invalid response from escrowfilter command"),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        }

}

bool EscrowListPage::handleURI(const QString& strURI)
{
 
    return false;
}
