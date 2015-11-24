#ifndef MYESCROWLISTPAGE_H
#define MYESCROWLISTPAGE_H

#include <QDialog>

namespace Ui {
    class MyEscrowListPage;
}
class EscrowTableModel;
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
class MyEscrowListPage : public QDialog
{
    Q_OBJECT

public:


    explicit MyEscrowListPage(QWidget *parent = 0);
    ~MyEscrowListPage();

    void setModel(WalletModel*, EscrowTableModel *model);
    void setOptionsModel(ClientModel* clientmodel, OptionsModel *optionsModel);
    const QString &getReturnValue() const { return returnValue; }
	bool handleURI(const QString &uri);
	void showEvent ( QShowEvent * event );
private:
	ClientModel* clientModel;
	WalletModel *walletModel;
    Ui::MyEscrowListPage *ui;
    EscrowTableModel *model;
    OptionsModel *optionsModel;
    QString returnValue;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QString newEscrowToSelect;
	QAction *releaseAction;
	QAction *refundAction;
	QAction *completeAction;
	QAction *buyerMessageAction;
	QAction *sellerMessageAction;
	QAction *arbiterMessageAction;
private slots:
    void on_newEscrow_clicked();
    void on_copyEscrow_clicked();
    /** Export button clicked */
    void on_exportButton_clicked();
	void on_refreshButton_clicked();
	void on_buyerMessageButton_clicked();
	void on_sellerMessageButton_clicked();
	void on_arbiterMessageButton_clicked();
	void on_releaseButton_clicked();
	void on_refundButton_clicked();
	void on_completeButton_clicked();
    /** Set button states based on selected tab and selection */
    void selectionChanged();
    /** Spawn contextual menu (right mouse menu) for cert book entry */
    void contextualMenu(const QPoint &point);
    /** New entry/entries were added to cert table */
    void selectNewEscrow(const QModelIndex &parent, int begin, int /*end*/);

};

#endif // MYESCROWLISTPAGE_H
