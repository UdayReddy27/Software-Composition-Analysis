cmake_minimum_required(VERSION 3.10)
project(ExampleProject)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find packages
find_package(OpenCV REQUIRED)
find_package(Boost REQUIRED)

# Include directories
include_directories(${OpenCV_INCLUDE_DIRS})
include_directories(${Boost_INCLUDE_DIRS})

# Add the executable
add_executable(example main.cpp)

# Link libraries
target_link_libraries(example ${OpenCV_LIBS} ${Boost_LIBRARIES})
