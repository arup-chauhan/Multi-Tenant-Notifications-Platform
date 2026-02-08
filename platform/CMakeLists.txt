cmake_minimum_required(VERSION 3.20)
project(multi_tenant_notification_platform LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_subdirectory(services/notification-gateway)
add_subdirectory(services/notification-dispatcher)
add_subdirectory(services/notification-storage)
