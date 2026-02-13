#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Timer.h"
#include "UnitTests.h"

int main(int argc, char** argv)
{
    oc::CLP clp(argc, argv);

    if (clp.isSet("u"))
        clp.set("u");

    oc::TestCollection tests;

    tests += uppidtests::Tests;
    tests.runIf(clp);

    return 0;
}