#include "outmessagelistpage.h"
#include "ui_messagelistpage.h"
#include "guiutil.h"
#include "messagetablemodel.h"
#include "optionsmodel.h"
#include "walletmodel.h"
#include "newmessagedialog.h"
#include "messageinfodialog.h"
#include "csvmodelwriter.h"
#include "ui_interface.h"
#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QKeyEvent>
#include <QMenu>

using namespace std;

OutMessageListPage::OutMessageListPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MessageListPage),
    model(0),
    optionsModel(0)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
	ui->newMessage->setIcon(QIcon());
    ui->copyMessage->setIcon(QIcon());
    ui->exportButton->setIcon(QIcon());
	ui->detailButton->setIcon(QIcon());
#endif

    ui->labelExplanation->setText(tr("These are Syscoin messages you sent out."));
	
    // Context menu actions
    QAction *copyGuidAction = new QAction(ui->copyMessage->text(), this);
    QAction *copySubjectAction = new QAction(tr("Copy &Subject"), this);
	QAction *copyMessageAction = new QAction(tr("Copy &Message"), this);
	QAction *newMessageAction = new QAction(tr("&New Message"), this);
	QAction *detailsAction = new QAction(tr("&Details"), this);

    // Build context menu
    contextMenu = new QMenu();
    contextMenu->addAction(copyGuidAction);
    contextMenu->addAction(copySubjectAction);
	contextMenu->addAction(copyMessageAction);
	contextMenu->addAction(detailsAction);
    contextMenu->addSeparator();
    contextMenu->addAction(newMessageAction);

    // Connect signals for context menu actions
    connect(copyGuidAction, SIGNAL(triggered()), this, SLOT(on_copyGuid_clicked()));
    connect(copySubjectAction, SIGNAL(triggered()), this, SLOT(on_copySubject_clicked()));
	connect(copyMessageAction, SIGNAL(triggered()), this, SLOT(on_copyMessage_clicked()));
	connect(newMessageAction, SIGNAL(triggered()), this, SLOT(on_newMessage_clicked()));
	connect(ui->tableView, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(on_detailButton_clicked()));
	connect(detailsAction, SIGNAL(triggered()), this, SLOT(on_detailButton_clicked()));
    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));

}
void OutMessageListPage::on_detailButton_clicked()
{
    if(!ui->tableView->selectionModel())
        return;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if(!selection.isEmpty())
    {
        MessageInfoDialog dlg;
		QModelIndex origIndex = proxyModel->mapToSource(selection.at(0));
		dlg.setModel(walletModel, model);	
		dlg.loadRow(origIndex.row());
        dlg.exec();
    }
}
void OutMessageListPage::on_newMessage_clicked()
{
    NewMessageDialog dlg(NewMessageDialog::NewMessage);
    dlg.setModel(walletModel, model);
    dlg.exec();
}
OutMessageListPage::~OutMessageListPage()
{
    delete ui;
}
void OutMessageListPage::showEvent ( QShowEvent * event )
{
    if(!walletModel) return;
}
void OutMessageListPage::setModel(WalletModel* walletModel, MessageTableModel *model)
{
    this->model = model;
	this->walletModel = walletModel;
    if(!model) return;

    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableView->setModel(proxyModel);
    ui->tableView->sortByColumn(1, Qt::DescendingOrder);

    // Set column widths
#if QT_VERSION < 0x050000
    ui->tableView->horizontalHeader()->setResizeMode(MessageTableModel::GUID, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(MessageTableModel::Time, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(MessageTableModel::From, QHeaderView::ResizeToContents);
	ui->tableView->horizontalHeader()->setResizeMode(MessageTableModel::To, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(MessageTableModel::Subject, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setResizeMode(MessageTableModel::Message, QHeaderView::Stretch);
#else
    ui->tableView->horizontalHeader()->setSectionResizeMode(MessageTableModel::GUID, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(MessageTableModel::Time, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(MessageTableModel::From, QHeaderView::ResizeToContents);
	ui->tableView->horizontalHeader()->setSectionResizeMode(MessageTableModel::To, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(MessageTableModel::Subject, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setSectionResizeMode(MessageTableModel::Message, QHeaderView::Stretch);
#endif


    connect(ui->tableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection,QItemSelection)),
            this, SLOT(selectionChanged()));


    // Select row for newly created outmessage
    connect(model, SIGNAL(rowsInserted(QModelIndex,int,int)), this, SLOT(selectNewMessage(QModelIndex,int,int)));

    selectionChanged();

}

void OutMessageListPage::setOptionsModel(OptionsModel *optionsModel)
{
    this->optionsModel = optionsModel;
}

void OutMessageListPage::on_refreshButton_clicked()
{
    if(!model)
        return;
    model->refreshMessageTable();
}
void OutMessageListPage::on_copyMessage_clicked()
{
   
    GUIUtil::copyEntryData(ui->tableView, MessageTableModel::Message);
}
void OutMessageListPage::on_copyGuid_clicked()
{
   
    GUIUtil::copyEntryData(ui->tableView, MessageTableModel::GUID);
}
void OutMessageListPage::on_copySubject_clicked()
{
   
    GUIUtil::copyEntryData(ui->tableView, MessageTableModel::Subject);
}



void OutMessageListPage::selectionChanged()
{
    // Set button states based on selected tab and selection
    QTableView *table = ui->tableView;
    if(!table->selectionModel())
        return;

    if(table->selectionModel()->hasSelection())
    {
        ui->copyMessage->setEnabled(true);
		ui->detailButton->setEnabled(true);
    }
    else
    {
        ui->copyMessage->setEnabled(false);
		ui->detailButton->setEnabled(false);
    }
}
void OutMessageListPage::keyPressEvent(QKeyEvent * event)
{
  if( event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter )
  {
	on_newMessage_clicked();
    event->accept();
  }
  else
    QDialog::keyPressEvent( event );
}
void OutMessageListPage::on_exportButton_clicked()
{
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(
            this,
            tr("Export Message Data"), QString(),
            tr("Comma separated file (*.csv)"));

    if (filename.isNull()) return;

    CSVModelWriter writer(filename);

    // name, column, role
    writer.setModel(proxyModel);
    writer.addColumn("GUID", MessageTableModel::GUID, Qt::EditRole);
    writer.addColumn("Time", MessageTableModel::Time, Qt::EditRole);
    writer.addColumn("From", MessageTableModel::From, Qt::EditRole);
	writer.addColumn("To", MessageTableModel::To, Qt::EditRole);
	writer.addColumn("Subject", MessageTableModel::Subject, Qt::EditRole);
	writer.addColumn("Message", MessageTableModel::Message, Qt::EditRole);
    if(!writer.write())
    {
        QMessageBox::critical(this, tr("Error exporting"), tr("Could not write to file %1.").arg(filename),
                              QMessageBox::Abort, QMessageBox::Abort);
    }
}



void OutMessageListPage::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if(index.isValid()) {
        contextMenu->exec(QCursor::pos());
    }
}

void OutMessageListPage::selectNewMessage(const QModelIndex &parent, int begin, int /*end*/)
{
    QModelIndex idx = proxyModel->mapFromSource(model->index(begin, MessageTableModel::GUID, parent));
    if(idx.isValid() && (idx.data(Qt::EditRole).toString() == newMessageToSelect))
    {
        // Select row of newly created outmessage, once
        ui->tableView->setFocus();
        ui->tableView->selectRow(idx.row());
        newMessageToSelect.clear();
    }
}

bool OutMessageListPage::handleURI(const QString& strURI)
{
 
    return false;
}
