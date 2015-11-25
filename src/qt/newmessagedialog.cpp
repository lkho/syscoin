#include "newmessagedialog.h"
#include "ui_newmessagedialog.h"

#include "messagetablemodel.h"
#include "guiutil.h"
#include "walletmodel.h"
#include "bitcoingui.h"
#include "ui_interface.h"
#include "bitcoinrpc.h"
#include "script.h"
#include <QDataWidgetMapper>
#include <QMessageBox>

using namespace std;
using namespace json_spirit;
extern int nBestHeight;
extern const CRPCTable tableRPC;
int64 GetMessageNetworkFee(opcodetype seed, unsigned int nHeight);
NewMessageDialog::NewMessageDialog(Mode mode, const QString &to, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::NewMessageDialog), mapper(0), mode(mode), model(0), walletModel(0)
{
    ui->setupUi(this);
	loadAliases();
	GUIUtil::setupAddressWidget(ui->toEdit, this);
	if(to != QString(""))
	{
		ui->toEdit->setEnabled(false);
		ui->toEdit->setText(to);
	}
    switch(mode)
    {
    case NewMessage:
        setWindowTitle(tr("New Message"));   
		ui->replyEdit->setVisible(false);
		ui->replyLabel->setVisible(false);
		ui->fromDisclaimer->setText(tr("<font color='red'>Enter an alias you own</font>"));
        break;
    case ReplyMessage:
        setWindowTitle(tr("Reply Message"));
		ui->replyEdit->setVisible(true);
		ui->replyLabel->setVisible(true);
		ui->toEdit->setEnabled(false);
		ui->aliasEdit->setEnabled(false);
        break;
	}
    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
}

NewMessageDialog::~NewMessageDialog()
{
    delete ui;
}

void NewMessageDialog::loadAliases()
{
	ui->aliasEdit->clear();
	string strMethod = string("aliaslist");
    Array params; 
	Value result ;
	string name_str;
	int expired = 0;
	
	try {
		result = tableRPC.execute(strMethod, params);

		if (result.type() == array_type)
		{
			name_str = "";
			expired = 0;


	
			Array arr = result.get_array();
			BOOST_FOREACH(Value& input, arr)
			{
				if (input.type() != obj_type)
					continue;
				Object& o = input.get_obj();
				name_str = "";

				expired = 0;


		
				const Value& name_value = find_value(o, "name");
				if (name_value.type() == str_type)
					name_str = name_value.get_str();		
				const Value& expired_value = find_value(o, "expired");
				if (expired_value.type() == int_type)
					expired = expired_value.get_int();
				
				if(expired == 0)
				{
					QString name = QString::fromStdString(name_str);
					ui->aliasEdit->addItem(name);					
				}
				
			}
		}
	}
	catch (Object& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
			tr("Could not refresh cert list: %1").arg(QString::fromStdString(strError)),
				QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("There was an exception trying to refresh the cert list: ") + QString::fromStdString(e.what()),
				QMessageBox::Ok, QMessageBox::Ok);
	}         
 
}
void NewMessageDialog::setModel(WalletModel* walletModel, MessageTableModel *model)
{
    this->model = model;
	this->walletModel = walletModel;
    if(!model || mode != ReplyMessage) return;

    mapper->setModel(model);
	mapper->addMapping(ui->replyEdit, MessageTableModel::Message);
    mapper->addMapping(ui->toEdit, MessageTableModel::From);
	mapper->addMapping(ui->topicEdit, MessageTableModel::Subject); 
}

void NewMessageDialog::loadRow(int row)
{
	const QModelIndex tmpIndex;
	if(model)
	{
		if(mode == ReplyMessage)	
			mapper->setCurrentIndex(row);
		QModelIndex indexAlias = model->index(row, MessageTableModel::To, tmpIndex);
		if(indexAlias.isValid())
		{
			QString aliasStr = indexAlias.data(MessageTableModel::ToRole).toString();
			ui->aliasEdit->setCurrentIndex(ui->aliasEdit->findText(aliasStr));
		}
	}

}

bool NewMessageDialog::saveCurrentRow()
{

    if(walletModel)
	{
		WalletModel::UnlockContext ctx(walletModel->requestUnlock());
		if(model && !ctx.isValid())
		{
			model->editStatus = MessageTableModel::WALLET_UNLOCK_FAILURE;
			return false;
		}
	}
	Array params;
	string strMethod;
	double activateFee;
	std::string activateFeeStr;
	QMessageBox::StandardButton retval;
    switch(mode)
    {
    case NewMessage:
        if (ui->messageEdit->toPlainText().trimmed().isEmpty()) {
            QMessageBox::information(this, windowTitle(),
            tr("Empty message not allowed. Please try again"),
                QMessageBox::Ok, QMessageBox::Ok);
            return false;
        }
		activateFee = (double)GetMessageNetworkFee(OP_MESSAGE_ACTIVATE, nBestHeight)/(double)COIN;
		activateFeeStr = strprintf("%.2f", activateFee);
        retval = QMessageBox::question(this, tr("Confirm Send Message"),
            tr("Warning: New message will cost ") + QString::fromStdString(activateFeeStr) + " SYS<br><br>" + tr("Are you sure you want to send this message?"),
				 QMessageBox::Yes|QMessageBox::Cancel,
				 QMessageBox::Cancel);
		if(retval != QMessageBox::Yes)
		{
			return false;
		}
		strMethod = string("messagenew");
		params.push_back(ui->topicEdit->text().toStdString());
		params.push_back(ui->messageEdit->toPlainText().trimmed().toStdString());
		params.push_back(ui->aliasEdit->currentText().toStdString());
		params.push_back(ui->toEdit->text().toStdString());
		

		try {
            Value result = tableRPC.execute(strMethod, params);
			if (result.type() != null_type)
			{
				message = ui->messageEdit->toPlainText();	
			}
		}
		catch (Object& objError)
		{
			string strError = find_value(objError, "message").get_str();
			QMessageBox::critical(this, windowTitle(),
			tr("Error creating new message: \"%1\"").arg(QString::fromStdString(strError)),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}
		catch(std::exception& e)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("General exception creating new message"),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}							

        break;
    case ReplyMessage:
        if (ui->messageEdit->toPlainText().trimmed().isEmpty()) {
            QMessageBox::information(this, windowTitle(),
            tr("Empty message not allowed. Please try again"),
                QMessageBox::Ok, QMessageBox::Ok);
            return false;
        }
        if(mapper->submit())
        {
			activateFee = (double)GetMessageNetworkFee(OP_MESSAGE_ACTIVATE, nBestHeight)/(double)COIN;
			activateFeeStr = strprintf("%.2f", activateFee);
			retval = QMessageBox::question(this, tr("Confirm Reply Message"),
				tr("Warning: Reply message will cost ") + QString::fromStdString(activateFeeStr) + " SYS<br><br>" + tr("Are you sure you want to reply to this message?"),
					 QMessageBox::Yes|QMessageBox::Cancel,
					 QMessageBox::Cancel);
			if(retval != QMessageBox::Yes)
			{
				return false;
			}
			strMethod = string("messagenew");
			params.push_back(ui->topicEdit->text().toStdString());
			params.push_back(ui->messageEdit->toPlainText().trimmed().toStdString());
			params.push_back(ui->aliasEdit->currentText().toStdString());
			params.push_back(ui->toEdit->text().toStdString());
			
			try {
				Value result = tableRPC.execute(strMethod, params);
				if (result.type() != null_type)
				{
					message = ui->messageEdit->toPlainText();	
				}
			}
			catch (Object& objError)
			{
				string strError = find_value(objError, "message").get_str();
				QMessageBox::critical(this, windowTitle(),
				tr("Error replying to message: \"%1\"").arg(QString::fromStdString(strError)),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}
			catch(std::exception& e)
			{
				QMessageBox::critical(this, windowTitle(),
					tr("General exception replying to message"),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}	
        }
        break;
	}
    return !message.isEmpty();
}

void NewMessageDialog::accept()
{
	bool saveState = saveCurrentRow();
    if(!saveState && model)
    {
        switch(model->getEditStatus())
        {
        case MessageTableModel::OK:
            // Failed with unknown reason. Just reject.
            break;
        case MessageTableModel::NO_CHANGES:
            // No changes were made during edit operation. Just reject.
            break;
        case MessageTableModel::INVALID_MESSAGE:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered message \"%1\" is not a valid Syscoin Message.").arg(ui->topicEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case MessageTableModel::DUPLICATE_MESSAGE:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered message \"%1\" is already taken.").arg(ui->topicEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case MessageTableModel::WALLET_UNLOCK_FAILURE:
            QMessageBox::critical(this, windowTitle(),
                tr("Could not unlock wallet."),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        }
    }
	else if(saveState)
		QDialog::accept();
}

