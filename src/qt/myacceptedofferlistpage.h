#ifndef MYACCEPTEDOFFERLISTPAGE_H
#define MYACCEPTEDOFFERLISTPAGE_H

#include <QDialog>

namespace Ui {
    class MyAcceptedOfferListPage;
}
class OfferAcceptTableModel;
class OptionsModel;
class ClientModel;
class WalletModel;
QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QSortFilterProxyModel;
class QMenu;
class QModelIndex;
QT_END_NAMESPACE

/** Widget that shows a list of owned certes.
  */
class MyAcceptedOfferListPage : public QDialog
{
    Q_OBJECT

public:


    explicit MyAcceptedOfferListPage(QWidget *parent = 0);
    ~MyAcceptedOfferListPage();

    void setModel(WalletModel*, OfferAcceptTableModel *model);
    void setOptionsModel(ClientModel* clientmodel, OptionsModel *optionsModel);
    const QString &getReturnValue() const { return returnValue; }
	bool handleURI(const QString &uri);
	void showEvent ( QShowEvent * event );
public slots:
    void done(int retval);

private:
	ClientModel* clientModel;
	WalletModel *walletModel;
    Ui::MyAcceptedOfferListPage *ui;
    OfferAcceptTableModel *model;
    OptionsModel *optionsModel;
    QString returnValue;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QAction *deleteAction; // to be able to explicitly disable it
    QString newOfferToSelect;

private slots:

    void on_copyOffer_clicked();
    void onCopyOfferValueAction();
    /** Export button clicked */
    void on_exportButton_clicked();
	void on_refreshButton_clicked();
	void on_messageButton_clicked();
    void selectionChanged();
    void contextualMenu(const QPoint &point);
    void selectNewOffer(const QModelIndex &parent, int begin, int /*end*/);
	void on_detailButton_clicked();
	void on_refundButton_clicked();

};

#endif // MYACCEPTEDOFFERLISTPAGE_H
