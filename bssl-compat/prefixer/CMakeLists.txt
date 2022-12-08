project(prefixer)

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

add_executable(prefixer prefixer.cpp)

target_include_directories(prefixer PRIVATE "${LLVM_INCLUDE_DIRS}")
target_link_directories(prefixer PRIVATE "${LLVM_LIBRARY_DIRS}")
target_link_libraries(prefixer PRIVATE clang-cpp LLVM)
