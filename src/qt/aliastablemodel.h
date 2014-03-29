#ifndef ALIASTABLEMODEL_H
#define ALIASTABLEMODEL_H

#include <QAbstractTableModel>
#include <QStringList>

class AliasTablePriv;
class CWallet;
class WalletModel;

/**
   Qt model of the alias                                                                                                                                                        book in the core. This allows views to access and modify the alias book.
 */
class AliasTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit AliasTableModel(CWallet *wallet, WalletModel *parent = 0);
    ~AliasTableModel();

    enum ColumnIndex {
        Name = 0,   /**< alias name */
        Value = 1,  /**< Alias value */
        ExpirationDepth = 2
    };

    enum RoleIndex {
        TypeRole = Qt::UserRole /**< Type of alias (#Send or #Receive) */
    };

    /** Return status of edit/insert operation */
    enum EditStatus {
        OK,                     /**< Everything ok */
        NO_CHANGES,             /**< No changes were made during edit operation */
        INVALID_ALIAS,        /**< Unparseable alias */
        DUPLICATE_ALIAS,      /**< Alias already in alias book */
        WALLET_UNLOCK_FAILURE  /**< Wallet could not be unlocked */
    };

    static const QString Alias;      /**< Specifies send alias */
    static const QString DataAlias;   /**< Specifies receive alias */

    /** @name Methods overridden from QAbstractTableModel
        @{*/
    int rowCount(const QModelIndex &parent) const;
    int columnCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    bool setData(const QModelIndex &index, const QVariant &value, int role);
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    QModelIndex index(int row, int column, const QModelIndex &parent) const;
    bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex());
    Qt::ItemFlags flags(const QModelIndex &index) const;
    /*@}*/

    /* Add an alias to the model.
       Returns the added alias on success, and an empty string otherwise.
     */
    QString addRow(const QString &type, const QString &value, const QString &alias);

    /* Look up label for alias in alias book, if not found return empty string.
     */
    QString valueForAlias(const QString &alias) const;

    /* Look up row index of an alias in the model.
       Return -1 if not found.
     */
    int lookupAlias(const QString &alias) const;

    EditStatus getEditStatus() const { return editStatus; }

private:
    WalletModel *walletModel;
    CWallet *wallet;
    AliasTablePriv *priv;
    QStringList columns;
    EditStatus editStatus;

    /** Notify listeners that data changed. */
    void emitDataChanged(int index);

public slots:
    /* Update alias list from core.
     */
    void updateEntry(const QString &alias, const QString &value, bool isData, int status);

    friend class AliasTablePriv;
};

#endif // ALIASTABLEMODEL_H
