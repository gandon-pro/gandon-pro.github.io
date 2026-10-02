cmake_minimum_required(VERSION 3.21)
project(GandonPRONative LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Source files are UTF-8.  Without this flag MSVC decodes Cyrillic string
# literals using the active ANSI code page, producing mojibake such as "Рџ..."
# in native dialogs.
if (MSVC)
    add_compile_options(/utf-8)
endif()

add_library(gandon_core STATIC
    src/core.cpp
    src/decoder.cpp
    src/plugin_host.cpp
)
target_include_directories(gandon_core PUBLIC include)
target_compile_definitions(gandon_core PRIVATE GANDON_CORE_BUILD)

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

if (WIN32 AND NOT MINGW)
    add_executable(gandon_gui WIN32 src/gui_main.cpp)
    target_link_libraries(gandon_gui PRIVATE gandon_core comctl32 comdlg32 user32 gdi32 dwmapi dbghelp)
    target_compile_definitions(gandon_gui PRIVATE UNICODE _UNICODE)
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
    if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/plugins/python/scyllahide_loader.py")
        add_custom_command(TARGET gandon_gui POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_CURRENT_SOURCE_DIR}/plugins/python/scyllahide_loader.py"
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
