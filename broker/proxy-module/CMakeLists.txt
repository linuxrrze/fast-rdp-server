cmake_minimum_required(VERSION 3.16)
project(fastrdp-proxy-module VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)
find_package(PkgConfig REQUIRED)
pkg_check_modules(FREERDP REQUIRED IMPORTED_TARGET
  freerdp3>=3.27 winpr3 freerdp-server-proxy3 libcjson)

# freerdp-proxy3 loads <plugindir>/libproxy-<name>-plugin.so for "Modules = <name>"
pkg_get_variable(FREERDP_LIBDIR freerdp3 libdir)
set(FASTRDP_PROXY_PLUGINDIR "${FREERDP_LIBDIR}/freerdp3/proxy"
    CACHE PATH "freerdp-proxy plugin directory")

add_library(proxy-fastrdp-plugin MODULE fastrdp_plugin.c)
set_target_properties(proxy-fastrdp-plugin PROPERTIES
  PREFIX "lib" C_STANDARD 11 C_VISIBILITY_PRESET hidden)
target_compile_options(proxy-fastrdp-plugin PRIVATE -Wall -Wextra -Wno-unused-parameter
  -Wno-deprecated-declarations) # FreeRDP 3.31+ headers trip this themselves
target_compile_definitions(proxy-fastrdp-plugin PRIVATE _GNU_SOURCE)
target_link_libraries(proxy-fastrdp-plugin PRIVATE PkgConfig::FREERDP)

install(TARGETS proxy-fastrdp-plugin LIBRARY DESTINATION "${FASTRDP_PROXY_PLUGINDIR}")
