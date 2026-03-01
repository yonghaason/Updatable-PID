#include "UnitTests.h"
#include "DoublePrf_tests.h"
#include "SsLeftJoin_tests.h"
#include "PseudonymisedDB_tests.h"

#include <functional>

namespace uppidtests {
    oc::TestCollection Tests([](oc::TestCollection& t) {
    t.add("doublePrf_Altmod_test            ", doublePrf_AltMod_test);
    t.add("doublePrf_DDH_test               ", doublePrf_DDH_test);
    t.add("ssLeftJoin_test                  ", ssLeftJoin_test);
    t.add("pseudonymisedDB_test             ", pseudonymisedDB_test);
    });
}
