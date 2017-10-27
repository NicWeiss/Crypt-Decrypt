#ifndef MAINCRYPT_H
#define MAINCRYPT_H

#include <QMainWindow>
#include <QJsonDocument>
#include <QJsonObject>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>


namespace Ui {
class MainCrypt;
}

class MainCrypt : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainCrypt(QWidget *parent = 0);
    ~MainCrypt();
    static QString encrypted;

private slots:
    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

private:
    Ui::MainCrypt *ui;
};

#endif // MAINCRYPT_H
