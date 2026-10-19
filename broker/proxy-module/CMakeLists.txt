cmake_minimum_required(VERSION 3.16)
project(fastrdp-proxy-module VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)
find_package(PkgConfig REQUIRED)
pkg_check_modules(FREERDP REQUIRED IMPORTED_TARGET
  freerdp3>=3.27 winpr3 freerdp-server-proxy3 libcjson)

# freerdp-proxy3 loads <plugindir>/libproxy-<name>-plugin.so for "Modules = <name>"
# (fastrdp's own FreeRDP in /opt/fastrdp has relocatable .pc files: prefix=${pcfiledir}/../..)
pkg_get_variable(FREERDP_PROXY_PLUGINDIR_PC freerdp3 proxy_plugindir)
if(NOT FREERDP_PROXY_PLUGINDIR_PC)
  pkg_get_variable(FREERDP_LIBDIR freerdp3 libdir)
  set(FREERDP_PROXY_PLUGINDIR_PC "${FREERDP_LIBDIR}/freerdp3/proxy")
endif()
get_filename_component(FREERDP_PROXY_PLUGINDIR_PC "${FREERDP_PROXY_PLUGINDIR_PC}" ABSOLUTE)
set(FASTRDP_PROXY_PLUGINDIR "${FREERDP_PROXY_PLUGINDIR_PC}"
    CACHE PATH "freerdp-proxy plugin directory")

add_library(proxy-fastrdp-plugin MODULE fastrdp_plugin.c)
set_target_properties(proxy-fastrdp-plugin PROPERTIES
  PREFIX "lib" C_STANDARD 11 C_VISIBILITY_PRESET hidden)
target_compile_options(proxy-fastrdp-plugin PRIVATE -Wall -Wextra -Wno-unused-parameter
  -Wno-deprecated-declarations) # FreeRDP 3.31+ headers trip this themselves
target_compile_definitions(proxy-fastrdp-plugin PRIVATE _GNU_SOURCE)
target_link_libraries(proxy-fastrdp-plugin PRIVATE PkgConfig::FREERDP)

# A FreeRDP outside the default library path (fastrdp's own build in /opt/fastrdp):
# find libfreerdp*/libwinpr relative to the plugin directory, as fastrdp-freerdp3's
# own binaries do ($ORIGIN/../lib). freerdp-proxy has them loaded already, but without
# this the installed module does not resolve on its own (ldd, dlopen outside the proxy).
pkg_get_variable(FREERDP_LIBDIR_PC freerdp3 libdir)
get_filename_component(FREERDP_LIBDIR_PC "${FREERDP_LIBDIR_PC}" ABSOLUTE)
if(NOT FREERDP_LIBDIR_PC IN_LIST CMAKE_C_IMPLICIT_LINK_DIRECTORIES)
  file(RELATIVE_PATH FREERDP_LIBDIR_REL "${FASTRDP_PROXY_PLUGINDIR}" "${FREERDP_LIBDIR_PC}")
  string(REGEX REPLACE "/+$" "" FREERDP_LIBDIR_REL "${FREERDP_LIBDIR_REL}")
  set_target_properties(proxy-fastrdp-plugin PROPERTIES
    INSTALL_RPATH "$ORIGIN/${FREERDP_LIBDIR_REL}")
endif()

install(TARGETS proxy-fastrdp-plugin LIBRARY DESTINATION "${FASTRDP_PROXY_PLUGINDIR}")
