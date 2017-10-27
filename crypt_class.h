#ifndef CRYPT_CLASS_H
#define CRYPT_CLASS_H
#include <QString>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <fcntl.h>
#include <sys/types.h>
#include <linux/hdreg.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <QDebug>
#include <QFile>
#include <QSslKey>
#include <QTextCodec>



class crypt_class
{
public:
    crypt_class();
   // static QString encrypt(QString source);
   // static QString decrypt(QString crypt_str);
    static QString rsaDecrypt(RSA *privKey, QString encryptedData);
    static QString rsaEncrypt(RSA *pubKey, QString str);
    static RSA *loadPRIVATEKeyFromString(const char *privateKeyStr);
    static RSA *loadPUBLICKeyFromString(const char *publicKeyStr);
    static RSA* rsaPrivKey;
    static RSA* rsaPubKey;
};

#endif // CRYPT_H
