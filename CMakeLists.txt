# This file is automatically generated from cmake.toml - DO NOT EDIT
# See https://github.com/build-cpp/cmkr for more information

cmake_minimum_required(VERSION 3.25)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
	message(FATAL_ERROR "In-tree builds are not supported. Run CMake from a separate directory: cmake -B build")
endif()

set(CMKR_ROOT_PROJECT OFF)
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
	set(CMKR_ROOT_PROJECT ON)

	# Bootstrap cmkr and automatically regenerate CMakeLists.txt
	include(cmkr.cmake OPTIONAL RESULT_VARIABLE CMKR_INCLUDE_RESULT)
	if(CMKR_INCLUDE_RESULT)
		cmkr()
	endif()

	# Enable folder support
	set_property(GLOBAL PROPERTY USE_FOLDERS ON)

	# Create a configure-time dependency on cmake.toml to improve IDE support
	set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS cmake.toml)
endif()

project(zyemu)

# Subdirectory: thirdparty
set(CMKR_CMAKE_FOLDER ${CMAKE_FOLDER})
if(CMAKE_FOLDER)
	set(CMAKE_FOLDER "${CMAKE_FOLDER}/thirdparty")
else()
	set(CMAKE_FOLDER thirdparty)
endif()
add_subdirectory(thirdparty)
set(CMAKE_FOLDER ${CMKR_CMAKE_FOLDER})

# Target: zyemu
set(zyemu_SOURCES
	cmake.toml
	"include/zyemu/types.hpp"
	"include/zyemu/zyemu.hpp"
	"src/zyemu/assembler.cpp"
	"src/zyemu/assembler.hpp"
	"src/zyemu/codegen.cpp"
	"src/zyemu/codegen.hpp"
	"src/zyemu/cpu.cpp"
	"src/zyemu/internal.hpp"
	"src/zyemu/registers.cpp"
	"src/zyemu/registers.hpp"
)

add_library(zyemu STATIC)

target_sources(zyemu PRIVATE ${zyemu_SOURCES})
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${zyemu_SOURCES})

add_library(zyemu::zyemu ALIAS zyemu)
target_compile_features(zyemu PUBLIC
	cxx_std_23
)

target_include_directories(zyemu PUBLIC
	include
)

target_link_libraries(zyemu PUBLIC
	Zydis
	sfl::sfl
)

# Target: zyemu-playground
set(zyemu-playground_SOURCES
	cmake.toml
	"src/playground/main.cpp"
)

add_executable(zyemu-playground)

target_sources(zyemu-playground PRIVATE ${zyemu-playground_SOURCES})
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${zyemu-playground_SOURCES})

target_compile_features(zyemu-playground PRIVATE
	cxx_std_23
)

target_link_libraries(zyemu-playground PRIVATE
	zyemu::zyemu
)

get_directory_property(CMKR_VS_STARTUP_PROJECT DIRECTORY ${PROJECT_SOURCE_DIR} DEFINITION VS_STARTUP_PROJECT)
if(NOT CMKR_VS_STARTUP_PROJECT)
	set_property(DIRECTORY ${PROJECT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT zyemu-playground)
endif()

# Target: zyemu-tests
set(zyemu-tests_SOURCES
	cmake.toml
	"src/tests/main.cpp"
	"src/tests/testdata.hpp"
	"src/tests/tests/emulation.cpp"
	"src/tests/tests/emulation.testdata.cpp"
	"src/tests/tests/memory.hpp"
)

add_executable(zyemu-tests)

target_sources(zyemu-tests PRIVATE ${zyemu-tests_SOURCES})
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${zyemu-tests_SOURCES})

target_compile_features(zyemu-tests PRIVATE
	cxx_std_23
)

target_include_directories(zyemu-tests PRIVATE
	"src/tests"
)

target_link_libraries(zyemu-tests PRIVATE
	zyemu::zyemu
	GTest::gtest
)

get_directory_property(CMKR_VS_STARTUP_PROJECT DIRECTORY ${PROJECT_SOURCE_DIR} DEFINITION VS_STARTUP_PROJECT)
if(NOT CMKR_VS_STARTUP_PROJECT)
	set_property(DIRECTORY ${PROJECT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT zyemu-tests)
endif()
