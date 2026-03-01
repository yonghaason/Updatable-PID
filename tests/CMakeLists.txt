add_executable(uppid_tests
  main.cpp
  DoublePrf_tests.cpp
  SsLeftJoin_tests.cpp
  PseudonymisedDB_tests.cpp
  UnitTests.cpp
)

target_link_libraries(uppid_tests PRIVATE UPPID)
target_include_directories(uppid_tests PRIVATE
  ${CMAKE_SOURCE_DIR}/uppid
)