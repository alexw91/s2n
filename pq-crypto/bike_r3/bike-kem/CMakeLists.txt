cmake_minimum_required(VERSION 3.0.0)
project(bike_r3 C)

set(INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(SRC_DIR ${PROJECT_SOURCE_DIR}/src)
set(TESTS_DIR ${PROJECT_SOURCE_DIR}/tests)

include_directories(${INCLUDE_DIR})
include_directories(${INCLUDE_DIR}/internal)

include(cmake/arch.cmake)
include(cmake/compilation-flags.cmake)
include(cmake/clang-format.cmake)

add_library(${PROJECT_NAME} "")
add_executable(bike-test "")

add_subdirectory(${SRC_DIR})
add_subdirectory(${TESTS_DIR})

target_link_libraries(bike-test ${PROJECT_NAME})

if(LINK_OPENSSL)
  message(STATUS "Linking OpenSSL")
  find_package(OpenSSL REQUIRED)
  set(OPENSSL_USE_STATIC_LIBS TRUE)
  target_link_libraries(bike-test OpenSSL::Crypto)
endif()

if (UNIX AND NOT APPLE)
    include(GNUInstallDirs)
elseif(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR "lib")
endif()

install(
        TARGETS ${PROJECT_NAME}
        EXPORT ${PROJECT_NAME}-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Development
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Runtime
        RUNTIME DESTINATION bin COMPONENT Runtime
)

configure_file("cmake/${PROJECT_NAME}-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        @ONLY)
        
if (BUILD_SHARED_LIBS)
   set (TARGET_DIR "shared")
else()
   set (TARGET_DIR "static")
endif()

install(EXPORT "${PROJECT_NAME}-targets"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/cmake/${TARGET_DIR}"
        NAMESPACE AWS::
        COMPONENT Development)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/cmake/"
        COMPONENT Development)
        
        