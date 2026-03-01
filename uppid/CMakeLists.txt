set(SRCS
  "DoublePrf.cpp"
  "SsLeftJoin.cpp"
  "PseudonymisedDB.cpp"
)

if(TARGET Kunlun)
  message(STATUS "Kunlun target exists")
else()
  message(STATUS "Kunlun target DOES NOT exist (will become -lKunlun)")
endif()

add_library(UPPID STATIC ${SRCS})
target_link_libraries(UPPID 
  PRIVATE visa::secureJoin
  PUBLIC visa::volePSI
  PUBLIC Kunlun
)

target_include_directories(UPPID PUBLIC
  "${CMAKE_SOURCE_DIR}/thirdparty/install/secure-join/include/secureJoin"
  "${CMAKE_SOURCE_DIR}/thirdparty/volepsi/out/build/linux"
  "${CMAKE_SOURCE_DIR}/thirdparty/install/volepsi/include"
  "${CMAKE_SOURCE_DIR}/thirdparty"
)
