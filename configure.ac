#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# vim: set sw=4 ts=4 sts=4 et:

AC_INIT([fastalg-nfqueue], [0.1], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([src/falgnfq-main.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_PROG_RANLIB

if test x"${ac_cv_prog_cc_c99}" = xno; then
    AC_MSG_ERROR([C99 support is required to compile $PACKAGE])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_STRERROR_R

# Enable additional POSIX features
AC_DEFINE([_POSIX_C_SOURCE], [200809L], [Enable POSIX.1-2008 support])
AC_DEFINE([_XOPEN_SOURCE], [700], [Enable X/OPEN system interfaces])
AC_DEFINE([_BSD_SOURCE], [1], [Workaround annoying glibc feature tests])

PKG_CHECK_MODULES(GLIB, [glib-2.0])
PKG_CHECK_MODULES(NETFILTER, [libmnl libnetfilter_queue >= 1.0.0])
PKG_CHECK_MODULES(FALGPROTO, [falgproto-0.1])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
