#include "UnitTests.h"
#include "DoublePrf_tests.h"

#include <functional>

namespace uppidtests {
    oc::TestCollection Tests([](oc::TestCollection& t) {
    t.add("doublePrf_Altmod_Test            ", doublePrf_AltMod_test);
    t.add("doublePrf_DDH_Test               ", doublePrf_DDH_test);
    });
}
