find_package(OpenSSL REQUIRED)

add_executable(notification_gateway src/gateway_main.cpp)
target_link_libraries(notification_gateway PRIVATE OpenSSL::Crypto)
