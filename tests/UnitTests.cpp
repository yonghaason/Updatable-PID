#include "UnitTests.h"
#include "DoublePrf_tests.h"
#include "SSLJ_tests.h"

#include <functional>

namespace uppidtests {
    oc::TestCollection Tests([](oc::TestCollection& t) {
    t.add("doublePrf_Altmod_Test            ", doublePrf_AltMod_test);
    t.add("doublePrf_DDH_Test               ", doublePrf_DDH_test);
    t.add("sslj_test                        ", sslj_test);
    });
}
