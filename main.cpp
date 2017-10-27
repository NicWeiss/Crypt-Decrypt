#include "maincrypt.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainCrypt w;
    w.show();

    return a.exec();
}
