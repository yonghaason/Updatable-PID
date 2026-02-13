set(SRCS
  "DoublePrf.cpp"
  "SSLJ.cpp"
)

if(TARGET Kunlun)
  message(STATUS "Kunlun target exists")
else()
  message(STATUS "Kunlun target DOES NOT exist (will become -lKunlun)")
endif()

add_library(UPPID STATIC ${SRCS})
target_link_libraries(UPPID 
  PRIVATE visa::secureJoin visa::volePSI
  PUBLIC Kunlun
)

target_include_directories(UPPID PUBLIC
  "${CMAKE_SOURCE_DIR}/thirdparty/install/secure-join/include/secureJoin"
  "${CMAKE_SOURCE_DIR}/thirdparty/install/secure-join/include"
  "${CMAKE_SOURCE_DIR}/thirdparty/install/volepsi/include/volePSI"
  "${CMAKE_SOURCE_DIR}/thirdparty/install/volepsi/include"
  "${CMAKE_SOURCE_DIR}/thirdparty"
)
