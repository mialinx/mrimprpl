# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.65])
AC_INIT([mrimprpl], [1.2], [mialinx@gmail.com])
AC_PREFIX_DEFAULT(/usr)
AC_CONFIG_SRCDIR([src/proto.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([src/config.h])
AM_INIT_AUTOMAKE
libdir='${exec_prefix}/lib/purple-2'
AC_SUBST(libdir)

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Checks for libraries.

# Check for modules
PKG_CHECK_MODULES(GLIB, [glib-2.0 >= 2.4.0], , [
    AC_MSG_RESULT(no)
    AC_MSG_ERROR([
    You must have GLib 2.4.0 or newer development headers installed to build.
    If you have these installed already you may need to install pkg-config so
    I can find them.
])])
PKG_CHECK_MODULES(PURPLE, [purple >= 2.6.0], , [
    AC_MSG_RESULT(no)
    AC_MSG_ERROR([
    You must have libpurple 2.6.0 or newer development headers installed to build.
    If you have these installed already you may need to install pkg-config so
    I can find them.
])])
         
# Checks for header files.
AC_CHECK_HEADERS([string.h stdarg.h time.h errno.h sys/types.h netinet/in.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for options
AC_ARG_ENABLE([mrim-avatars], [  
  --disable-mrim-avatars        Disable avatars ],[ 
    AC_DEFINE(DISABLE_MRIM_AVATARS, [1], [disable avatars as hotfix for ubuntu])
    ],[
])

# Checks for library functions.
AC_OUTPUT([Makefile src/Makefile img/Makefile])
