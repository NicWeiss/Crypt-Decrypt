#-------------------------------------------------
#
# Project created by QtCreator 2017-10-24T10:07:26
#
#-------------------------------------------------

QT       += core gui network widgets sql

TARGET = Crypt-Decrypt
TEMPLATE = app


SOURCES += main.cpp\
        maincrypt.cpp \
    RSA_key.cpp \
    crypt_class.cpp

HEADERS  += maincrypt.h \
    RSA_key.h \
    crypt_class.h


FORMS    += maincrypt.ui
MOBILITY =
unix:LIBS    += -lssl
unix:LIBS    += -lcrypto
