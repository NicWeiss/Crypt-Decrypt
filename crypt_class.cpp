#include "crypt_class.h"

crypt_class::crypt_class()
{}

/**
 * @brief crypt_class::rsaPrivKey
 * глобальная переменная для хранения загруженного приватного ключа
 */
RSA* crypt_class::rsaPrivKey;
/**
 * @brief crypt_class::rsaPubKey
 * глобальная переменная для хранения загруженного публичного ключа
 */
RSA* crypt_class::rsaPubKey;



/**
 * @brief crypt_class::loadPUBLICKeyFromString
 * @param publicKeyStr
 * @return
 * функция загрузки публичного ключа
 */
RSA* crypt_class::loadPUBLICKeyFromString( const char* publicKeyStr )
{
  BIO* bio = BIO_new_mem_buf( (void*)publicKeyStr, -1 ) ;
  BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL ) ;
  RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY( bio, NULL, NULL, NULL ) ;
  if( !rsaPubKey ){
      qDebug()<< "ERROR: Could not load PUBLIC KEY!  PEM_read_bio_RSA_PUBKEY FAILED: %s\n";
      return NULL;
  }
    BIO_free( bio ) ;
    return rsaPubKey ;
}

/**
 * @brief crypt_class::loadPRIVATEKeyFromString
 * @param privateKeyStr
 * @return
 * Функция загрузки приватного ключа
 */
RSA* crypt_class::loadPRIVATEKeyFromString( const char* privateKeyStr )
{
  BIO *bio = BIO_new_mem_buf( (void*)privateKeyStr, -1 );
  RSA* rsaPrivKey = PEM_read_bio_RSAPrivateKey( bio, NULL, NULL, NULL ) ;
  if ( !rsaPrivKey ){
      qDebug()<< "ERROR: Could not load PRIVATE KEY!  PEM_read_bio_RSAPrivateKey FAILED: %s\n";
      return NULL;
  }
  BIO_free( bio ) ;
  return rsaPrivKey ;
}



/**
 * @brief crypt_class::rsaEncrypt
 * @param pubKey RSA
 * @param str source data in string
 * @return
 * шифруем данные и конвертируем в HEX для удобства работы со строками
 */
QString crypt_class::rsaEncrypt(RSA *pubKey, QString str)
{
  int size = str.length();
  unsigned char* tmp = (unsigned char*)malloc(RSA_size(pubKey)) ;
  memset(tmp,0,RSA_size(pubKey));
  QByteArray *binary;
  QByteArray tempar;
  QString element;
  int str_size_to_crypt=((RSA_size(pubKey)-11)/2)-1;
  int cyc=0;
  while (size>0){
         if( size>str_size_to_crypt){element = str.mid(cyc*str_size_to_crypt, str_size_to_crypt);}else{element = str.mid(cyc*str_size_to_crypt, str.length());}
         RSA_public_encrypt( RSA_size(pubKey)-11, (const unsigned char*)element.toStdString().c_str(), tmp, pubKey, RSA_PKCS1_PADDING );
         binary = new QByteArray((char*)tmp,RSA_size(pubKey));
         size -= str_size_to_crypt;
         tempar.append(*binary);
         delete binary;
         cyc++;
 }
  free(tmp);
  return tempar.toHex();
}


/**
 * @brief crypt_class::rsaDecrypt
 * @param privKey RSA
 * @param HextData hex in QString
 * @return
 * читаем строку с HEX значениями, переводим в байты и расшифровываем
 */
QString crypt_class::rsaDecrypt( RSA *privKey,QString HextData)
{
    QByteArray encryptedData;
    for (int i=0; i<HextData.length()/2; i++){
        QString str = HextData.mid(i*2,2);
        int iVal = str.toInt(NULL,16);
          encryptedData[i]=iVal;
    }
    int size=encryptedData.length();
    unsigned char* decryptedBin = (unsigned char*)malloc(RSA_size(privKey)) ;
    memset(decryptedBin,0,RSA_size(privKey));
    int i=0;
    QString *string;
    QString out;
    unsigned char* ptr = (unsigned char*)encryptedData.constData();
    int cyc=0;
    while (size>0){
        if (RSA_private_decrypt( RSA_size(privKey), ptr, decryptedBin, privKey, RSA_PKCS1_PADDING )==-1){ qDebug() << "ERROR";}
        string = new QString( reinterpret_cast< char* >( decryptedBin ) );
        ptr += RSA_size(privKey);
        out.append(*string);
        delete string;
        size -=  RSA_size(privKey);
        cyc++;
    }
    free(decryptedBin);
  return out ;
}



