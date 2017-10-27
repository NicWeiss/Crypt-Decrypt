#ifndef RSA_key_H
#define RSA_key_H
#include <QFile>
#include <QJsonObject>
#include <QSslCertificate>
#include <QSslKey>
#include <QMap>
#include <QFileInfo>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <QByteArray>
#include <QVariant>
#include <QDebug>
#include <QTextStream>

class RSA_key
{
public:
    RSA_key();
    static QJsonObject open_rsa();
    static QJsonObject Key_Gen();
    static QByteArray QByteArray_from_X509(X509 *x509);
    static bool isPrivateKeyCorrespondsToCertificate( QSslCertificate cert, QSslKey key );
};

#endif // RSA_key_H
