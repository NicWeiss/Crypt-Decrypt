#include "maincrypt.h"
#include "ui_maincrypt.h"
#include "crypt_class.h"
#include "RSA_key.h"

QString MainCrypt::encrypted;

MainCrypt::MainCrypt(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainCrypt)
{
    ui->setupUi(this);
}

MainCrypt::~MainCrypt()
{
    delete ui;
}

/**
 * @brief MainCrypt::on_pushButton_clicked
 * шифруем содержимое textedit
 */
void MainCrypt::on_pushButton_clicked()
{

    QString message = ui->textEdit->toPlainText();
    //зашифровываем данные
    MainCrypt::encrypted = crypt_class::rsaEncrypt( crypt_class::rsaPubKey, message);
       ui->textEdit_2->setText(MainCrypt::encrypted);
       //расшифровываем данные

}

/**
 * @brief MainCrypt::on_pushButton_2_clicked
 * расшифровываем содержимое текстового поля textedit 2
 */
void MainCrypt::on_pushButton_2_clicked()
{
    MainCrypt::encrypted = ui->textEdit_2->toPlainText();
    QString  data2 = crypt_class::rsaDecrypt(crypt_class::rsaPrivKey, encrypted);
    ui->textEdit_4->setText(data2.toStdString().c_str());
}

void MainCrypt::on_pushButton_3_clicked()
{
    QString pub_key,priv_key;
    pub_key = ui->textEdit_3->toPlainText();
    priv_key = ui->textEdit_5->toPlainText();
      // LOAD PUBLIC KEY
      crypt_class::rsaPubKey = crypt_class::loadPUBLICKeyFromString( pub_key.toStdString().c_str() ) ;
      // LOADR PRIVATE KEY
      crypt_class::rsaPrivKey = crypt_class::loadPRIVATEKeyFromString( priv_key.toStdString().c_str()  ) ;
}
