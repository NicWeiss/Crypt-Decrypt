#include "RSA_key.h"

RSA_key::RSA_key()
{

}

QJsonObject RSA_key::open_rsa()
{
    ///.... //--------------------------------------------------------------------------------------------
    //проверяем наличие текстового, конфигурационного файла
    bool nokey=false;
    QJsonObject key_data;
    QString str;
    QFile file;
      file.setFileName("RSA_public.key");
      if(QFileInfo::exists("RSA_public.key")){if(file.open(QIODevice::ReadOnly |QIODevice::Text)){
           str = file.readAll();
           key_data["public"] = str;
           file.close();
       }}else{nokey=true;}
    file.setFileName("RSA_private.key");
       if(QFileInfo::exists("RSA_private.key")){if(file.open(QIODevice::ReadOnly |QIODevice::Text)){
               str = file.readAll();
            key_data["private"] = str;
            file.close();
       }}else{nokey=true;}
    file.setFileName("RSA_server_public.key");
       if(QFileInfo::exists("RSA_server_public.key")){if(file.open(QIODevice::ReadOnly |QIODevice::Text)){
               str = file.readAll();
           key_data["server_public"] = str;
           file.close();
       }}else{key_data["server_public"] = "none";}
    file.setFileName("PERSONAL_UID.key");
        if(QFileInfo::exists("PERSONAL_UID.key")){if(file.open(QIODevice::ReadOnly |QIODevice::Text)){
                str = file.readAll();
            key_data["uid"] = str;
            file.close();
        }}else{key_data["uid"] = "none";}

       if(nokey)
       {
           QJsonObject new_keys = RSA_key::Key_Gen();
           file.setFileName("RSA_public.key");
           if(file.open(QIODevice::WriteOnly)){
                   QTextStream writeStream(&file);
                   writeStream.setCodec("UTF8");
                   writeStream << QString(new_keys.value("public").toString());
                   file.close();
           }
           file.setFileName("RSA_private.key");
           if(file.open(QIODevice::WriteOnly)){
                   QTextStream writeStream(&file);
                   writeStream.setCodec("UTF8");
                   writeStream << QString(new_keys.value("private").toString());
                   file.close();
           }
           key_data=new_keys;
           key_data["server_public"] = "none";
       }
       return key_data;

}

QJsonObject RSA_key::Key_Gen()
{
    QJsonObject keys;
    EVP_PKEY *pk;
        RSA *rsa;
        X509 *x;
        X509_NAME *name=NULL;
        bool ok;
        //parameters
        int bits=4096;
        long serial=57;
        long days=1895;
        QString certSubject="Nic";
        QString certOrganization="Sovr";
        QString certEMail="Ixornic@gmail.com";
        QSslKey pkey;
        QSslCertificate cert;
        QString str_public, str_private, tmp;

        //create private key
        pk=EVP_PKEY_new();
        rsa=RSA_generate_key(bits,RSA_F4,NULL,NULL);
        EVP_PKEY_assign_RSA(pk,rsa);
        {
            //save it to QSslKey
            BIO *bio = BIO_new(BIO_s_mem());
            PEM_write_bio_RSAPrivateKey(bio, rsa, (const EVP_CIPHER *)0, NULL, 0, 0, 0);
            QByteArray pem;
            char *data;
            long size = BIO_get_mem_data(bio, &data);
            pem = QByteArray(data, size);
            BIO_free(bio);
            pkey=QSslKey(pem,QSsl::Rsa);
            ok=!pkey.isNull();
        }
        x=X509_new();
        X509_set_version(x,2);
        ASN1_INTEGER_set(X509_get_serialNumber(x),serial);
        X509_gmtime_adj(X509_get_notBefore(x),(long)60*60*24*(-2));
        X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
        X509_set_pubkey(x,pk);

        name=X509_get_subject_name(x);


        X509_NAME_add_entry_by_txt(name,"CN", MBSTRING_ASC,(unsigned char*) certSubject.data(), -1, -1, 0);
        X509_NAME_add_entry_by_txt(name,"O", MBSTRING_ASC,(unsigned char*) certOrganization.data(), -1, -1, 0);
        X509_NAME_add_entry_by_txt(name,"emailAddress", MBSTRING_ASC,(unsigned char*) certEMail.data(), -1, -1, 0);

        X509_set_issuer_name(x,name);

        X509_sign(x,pk,EVP_md5());
        {
            QByteArray crt=QByteArray_from_X509(x);
            cert=QSslCertificate(crt);
            ok=cert.isBlacklisted();
        }

        ok=isPrivateKeyCorrespondsToCertificate(cert,pkey);


        str_private = pkey.toPem().toStdString().c_str();
        tmp = str_private.left(str_private.length()-31);
        str_private=tmp.right(tmp.length()-32);

        str_public = cert.toPem().toStdString().c_str();
        tmp = str_public.left(str_public.length()-31);
        str_public=tmp.right(tmp.length()-32);

        keys["public"] =str_public;
        keys["private"] = str_private;
        return keys;
}



QByteArray RSA_key::QByteArray_from_X509(X509 *x509)
{
    if (!x509)
        return QByteArray();

    // Use i2d_X509 to convert the X509 to an array.
    int length = i2d_X509(x509, 0);
    QByteArray array;
    array.resize(length);
    char *data = array.data();
    char **dataP = &data;
    unsigned char **dataPu = (unsigned char **)dataP;
    if (i2d_X509(x509, dataPu) < 0)
        return QByteArray();

    // Convert to Base64 - wrap at 64 characters.
    array = array.toBase64();
    QByteArray tmp;
    for (int i = 0; i < array.size() - 64; i += 64) {
        tmp += QByteArray::fromRawData(array.data() + i, 64);
        tmp += "\n";
    }
    if (int remainder = array.size() % 64) {
        tmp += QByteArray::fromRawData(array.data() + array.size() - remainder, remainder);
        tmp += "\n";
    }

    return "-----BEGIN CERTIFICATE-----\n" + tmp + "-----END CERTIFICATE-----\n";
}

bool RSA_key::isPrivateKeyCorrespondsToCertificate(QSslCertificate cert, QSslKey key)
{
    X509 *x;
    EVP_PKEY *k;

    x=(X509 *)cert.handle();
    k=EVP_PKEY_new();
    if(key.algorithm() == QSsl::Rsa)
        EVP_PKEY_assign_RSA(k, (RSA *)key.handle());
    else
        EVP_PKEY_assign_DSA(k, (DSA *)key.handle());
    if(X509_check_private_key(x,k)==1)
        return true;
    return false;
}
