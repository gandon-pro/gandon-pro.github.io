cmake_minimum_required(VERSION 3.21)
project(GandonPRONative LANGUAGES C CXX)

include(CTest)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Source files are UTF-8.  Without this flag MSVC decodes Cyrillic string
# literals using the active ANSI code page, producing mojibake such as "Рџ..."
# in native dialogs.
if (MSVC)
    add_compile_options(/utf-8)
endif()

# Unicorn supplies a real CPU execution engine for safe, isolated analysis.
# Prefer a package already installed by the user; the pinned source build is
# opt-in so offline/default builds remain reproducible.
option(GANDON_FETCH_UNICORN "Fetch and build Unicorn Engine 2.1.4" OFF)
set(GANDON_UNICORN_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/unicorn" CACHE PATH "Unicorn Engine package root")
find_package(unicorn CONFIG QUIET)
set(GANDON_UNICORN_TARGET "")
if (TARGET unicorn::unicorn)
    set(GANDON_UNICORN_TARGET unicorn::unicorn)
elseif (TARGET unicorn)
    set(GANDON_UNICORN_TARGET unicorn)
elseif (EXISTS "${GANDON_UNICORN_ROOT}/include/unicorn/unicorn.h")
    find_library(GANDON_UNICORN_LIBRARY NAMES unicorn PATHS "${GANDON_UNICORN_ROOT}/lib" NO_DEFAULT_PATH)
    if (GANDON_UNICORN_LIBRARY)
        add_library(gandon_unicorn UNKNOWN IMPORTED)
        set_target_properties(gandon_unicorn PROPERTIES
            IMPORTED_LOCATION "${GANDON_UNICORN_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${GANDON_UNICORN_ROOT}/include")
        set(GANDON_UNICORN_TARGET gandon_unicorn)
    endif()
endif()

if (NOT GANDON_UNICORN_TARGET AND GANDON_FETCH_UNICORN)
    include(FetchContent)
    # Keep x86 emulation and include AArch64 so ARM64 images can use the same
    # in-process Unicorn execution backend when the bundled engine is built.
    set(UNICORN_ARCH "x86;aarch64" CACHE STRING "" FORCE)
    set(UNICORN_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(UNICORN_INSTALL OFF CACHE BOOL "" FORCE)
    set(UNICORN_LEGACY_STATIC_ARCHIVE OFF CACHE BOOL "" FORCE)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    if (WIN32)
        find_program(GANDON_GIT_SH sh.exe HINTS "$ENV{ProgramFiles}/Git/bin" "$ENV{ProgramFiles}/Git/usr/bin")
        if (GANDON_GIT_SH)
            get_filename_component(GANDON_GIT_SH_DIR "${GANDON_GIT_SH}" DIRECTORY)
            set(ENV{PATH} "${GANDON_GIT_SH_DIR};$ENV{PATH}")
        endif()
    endif()
    FetchContent_Declare(gandon_unicorn_source
        URL https://github.com/unicorn-engine/unicorn/archive/refs/tags/2.1.4.tar.gz
        URL_HASH SHA256=EA8863F095A0136388694E5A6063AFD9BB7650E30243DD6251AF59C5CE5601F4
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    FetchContent_MakeAvailable(gandon_unicorn_source)
    if (TARGET unicorn)
        set(GANDON_UNICORN_TARGET unicorn)
        target_include_directories(unicorn PUBLIC "${gandon_unicorn_source_SOURCE_DIR}/include")
    endif()
endif()

add_library(gandon_core STATIC
    src/core.cpp
    src/decoder.cpp
    src/decompiler.cpp
    src/image_tables.cpp
    src/ida_views.cpp
    src/types.cpp
    src/binary_diff.cpp
    src/auto_analysis.cpp
    src/emulator.cpp
    src/il_emulator.cpp
    src/il_lifter.cpp
    src/plugin_host.cpp
)
target_include_directories(gandon_core PUBLIC include)
target_compile_definitions(gandon_core PRIVATE GANDON_CORE_BUILD)
if (GANDON_UNICORN_TARGET)
    target_compile_definitions(gandon_core PUBLIC GANDON_HAS_UNICORN=1)
    target_link_libraries(gandon_core PUBLIC ${GANDON_UNICORN_TARGET})
endif()

if (WIN32)
    target_link_libraries(gandon_core PRIVATE dbghelp)
endif()

# Capstone is optional during the migration. When installed through vcpkg,
# the full x86/x64 decoder is enabled; otherwise the small built-in decoder
# keeps the core usable and makes the dependency explicit at configure time.
find_package(capstone CONFIG QUIET)
set(GANDON_CAPSTONE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/capstone" CACHE PATH "Capstone package root")
if (NOT capstone_FOUND AND EXISTS "${GANDON_CAPSTONE_ROOT}/include/capstone/capstone.h")
    find_library(GANDON_CAPSTONE_LIBRARY NAMES capstone PATHS "${GANDON_CAPSTONE_ROOT}/lib" NO_DEFAULT_PATH)
    if (GANDON_CAPSTONE_LIBRARY)
        target_include_directories(gandon_core PRIVATE "${GANDON_CAPSTONE_ROOT}/include")
        target_link_libraries(gandon_core PRIVATE "${GANDON_CAPSTONE_LIBRARY}")
        target_compile_definitions(gandon_core PRIVATE GANDON_HAS_CAPSTONE=1)
    endif()
endif()
if (capstone_FOUND OR TARGET capstone::capstone OR TARGET capstone)
    target_compile_definitions(gandon_core PRIVATE GANDON_HAS_CAPSTONE=1)
    if (TARGET capstone::capstone)
        target_link_libraries(gandon_core PRIVATE capstone::capstone)
    else()
        target_link_libraries(gandon_core PRIVATE capstone)
    endif()
endif()

add_executable(gandon_cli src/main.cpp)
target_link_libraries(gandon_cli PRIVATE gandon_core)
add_executable(gandon_decompile src/decompile_cli.cpp)
add_executable(gandon_auto src/auto_cli.cpp)
target_link_libraries(gandon_auto PRIVATE gandon_core)
add_executable(gandon_diff src/diff_cli.cpp)
target_link_libraries(gandon_diff PRIVATE gandon_core)
add_executable(gandon_types_tests tests/types_tests.cpp)
target_link_libraries(gandon_types_tests PRIVATE gandon_core)
add_executable(gandon_ida_views tests/ida_views_tests.cpp)
target_link_libraries(gandon_ida_views PRIVATE gandon_core)
target_link_libraries(gandon_decompile PRIVATE gandon_core)
add_executable(gandon_mcp_backend src/mcp_backend.cpp)
target_link_libraries(gandon_mcp_backend PRIVATE gandon_core)

if (BUILD_TESTING)
    add_executable(gandon_core_tests tests/core_tests.cpp)
    target_link_libraries(gandon_core_tests PRIVATE gandon_core)
    if (GANDON_CAPSTONE_LIBRARY OR capstone_FOUND OR TARGET capstone::capstone OR TARGET capstone)
        target_compile_definitions(gandon_core_tests PRIVATE GANDON_TEST_HAS_CAPSTONE=1)
    endif()
    if (MSVC)
        target_compile_options(gandon_core_tests PRIVATE /UNDEBUG)
    else()
        target_compile_options(gandon_core_tests PRIVATE -UNDEBUG)
    endif()
    add_test(NAME gandon_core_tests COMMAND gandon_core_tests)
    add_executable(gandon_decompiler_tests tests/decompiler_tests.cpp)
    target_include_directories(gandon_decompiler_tests PRIVATE tests)
    target_link_libraries(gandon_decompiler_tests PRIVATE gandon_core)
    if (NOT MSVC)
        target_compile_options(gandon_decompiler_tests PRIVATE -UNDEBUG)
    else()
        target_compile_options(gandon_decompiler_tests PRIVATE /UNDEBUG)
    endif()
    add_test(NAME gandon_decompiler_tests COMMAND gandon_decompiler_tests)
    if (EXISTS "${GANDON_CAPSTONE_ROOT}/lib/capstone.dll")
        add_custom_command(TARGET gandon_core_tests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${GANDON_CAPSTONE_ROOT}/lib/capstone.dll"
                "$<TARGET_FILE_DIR:gandon_core_tests>/capstone.dll")
    endif()
endif()

if (WIN32)
    enable_language(RC)
    add_executable(gandon_gui WIN32 src/gui_main.cpp src/gandon_gui.rc)
    target_link_libraries(gandon_gui PRIVATE gandon_core comctl32 comdlg32 user32 gdi32 dwmapi dbghelp)
    target_compile_definitions(gandon_gui PRIVATE UNICODE _UNICODE)
    if (MINGW)
        target_link_options(gandon_gui PRIVATE -municode)
        target_link_libraries(gandon_gui PRIVATE ole32 windowscodecs uuid shlwapi)
    endif()
    if (EXISTS "${GANDON_CAPSTONE_ROOT}/lib/capstone.dll")
        add_custom_command(TARGET gandon_gui POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${GANDON_CAPSTONE_ROOT}/lib/capstone.dll"
                "$<TARGET_FILE_DIR:gandon_gui>/capstone.dll")
    endif()
endif()

if (WIN32 AND EXISTS "${GANDON_CAPSTONE_ROOT}/lib/capstone.dll")
    add_custom_command(TARGET gandon_cli POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${GANDON_CAPSTONE_ROOT}/lib/capstone.dll"
            "$<TARGET_FILE_DIR:gandon_cli>/capstone.dll")
endif()

if (WIN32 AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/plugins/python/font_legacy.py")
    add_custom_command(TARGET gandon_gui POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:gandon_gui>/plugins/python"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/plugins/python/font_legacy.py"
            "$<TARGET_FILE_DIR:gandon_gui>/plugins/python/font_legacy.py")
    if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/plugins/python/binary_summary.py")
        add_custom_command(TARGET gandon_gui POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_CURRENT_SOURCE_DIR}/plugins/python/binary_summary.py"
                "$<TARGET_FILE_DIR:gandon_gui>/plugins/python/binary_summary.py")
    endif()
    if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/plugins/python/plugin_window_host.py")
        add_custom_command(TARGET gandon_gui POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_CURRENT_SOURCE_DIR}/plugins/python/plugin_window_host.py"
                "$<TARGET_FILE_DIR:gandon_gui>/plugins/python/plugin_window_host.py")
    endif()
    if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../outputs/gandon_plugins/scyllahide_loader.py")
        add_custom_command(TARGET gandon_gui POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_CURRENT_SOURCE_DIR}/../outputs/gandon_plugins/scyllahide_loader.py"
                "$<TARGET_FILE_DIR:gandon_gui>/plugins/python/scyllahide_loader.py")
    endif()
endif()

find_package(Qt6 COMPONENTS Widgets QUIET)
if (Qt6_FOUND)
    qt_add_executable(gandon_qt src/qt_main.cpp)
    target_link_libraries(gandon_qt PRIVATE gandon_core Qt6::Widgets)
    target_compile_definitions(gandon_qt PRIVATE QT_NO_KEYWORDS)
    if (WIN32 AND EXISTS "${GANDON_CAPSTONE_ROOT}/lib/capstone.dll")
        add_custom_command(TARGET gandon_qt POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${GANDON_CAPSTONE_ROOT}/lib/capstone.dll"
                "$<TARGET_FILE_DIR:gandon_qt>/capstone.dll")
    endif()
endif()

option(GANDON_BUILD_EXAMPLE_PLUGIN "Build the native example plugin" ON)
if (GANDON_BUILD_EXAMPLE_PLUGIN)
    add_library(gandon_example_plugin SHARED plugins/example_plugin.cpp)
    target_include_directories(gandon_example_plugin PRIVATE include)
    set_target_properties(gandon_example_plugin PROPERTIES PREFIX "")
endif()

option(GANDON_BUILD_MCP_PLUGIN "Build the in-process MCP server native plugin" ON)
if (GANDON_BUILD_MCP_PLUGIN AND WIN32)
    add_library(gandon_mcp_plugin SHARED plugins/mcp_plugin.cpp)
    target_include_directories(gandon_mcp_plugin PRIVATE include)
    target_link_libraries(gandon_mcp_plugin PRIVATE ws2_32)
    set_target_properties(gandon_mcp_plugin PROPERTIES PREFIX "")
endif()
