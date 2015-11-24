#ifndef OFFERACCEPTDIALOG_H
#define OFFERACCEPTDIALOG_H

#include <QDialog>
namespace Ui {
    class OfferAcceptDialog;
}

class COffer;
/** Dialog for editing an address and associated information.
 */
class OfferAcceptDialog : public QDialog
{
    Q_OBJECT

public:
    explicit OfferAcceptDialog(QString offer, QString quantity, QString notes, QString title, QString currencyCode, QString strPrice, QWidget *parent=0);
    ~OfferAcceptDialog();

    bool getPaymentStatus();

private:
	void setupEscrowCheckboxState();
    Ui::OfferAcceptDialog *ui;
	QString quantity;
	QString notes;
	QString price;
	QString title;
	QString offer;
	bool offerPaid; 
	

private slots:
	void acceptPayment();
	void onEscrowCheckBoxChanged(bool);
	void on_cancelButton_clicked();
    void acceptOffer();
	void acceptEscrow();
};

#endif // OFFERACCEPTDIALOG_H
