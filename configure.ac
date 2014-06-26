#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# vim: set sw=4 ts=4 sts=4 et:

AC_INIT([fastalg-nfqueue],
        [m4_esyscmd([build-aux/git-version-gen .tarball-version])],
        [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([src/falgnfq-main.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])

m4_define([package_date_value], [m4_esyscmd([git show -s --format='%ad' --date=short `git rev-parse HEAD`])])
package_date=package_date_value
AC_DEFINE_UNQUOTED([PACKAGE_DATE], ["$package_date"],
          [Define to the date of the version of the package])

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

# Enable additional POSIX features.
AC_DEFINE([_POSIX_C_SOURCE], [200809L], [Enable POSIX.1-2008 support])
AC_DEFINE([_XOPEN_SOURCE], [700], [Enable X/OPEN system interfaces])
AC_DEFINE([_BSD_SOURCE], [1], [Workaround annoying glibc feature tests])

# Checks for required libraries.
PKG_CHECK_MODULES(GLIB, [glib-2.0])
PKG_CHECK_MODULES(NETFILTER, [libmnl libnetfilter_queue >= 1.0.2])
PKG_CHECK_MODULES(FALGPROTO, [falgproto-0.1 >= 0.1.3])

# Checks for libnetfilter_queue GSO handling features.
for libnetfilter_queue_gso_constant in \
    NFQA_CAP_LEN NFQA_SKB_INFO NFQA_SKB_GSO NFQA_CFG_F_GSO; do

    AC_CHECK_DECL([${libnetfilter_queue_gso_constant}],,
        [libnetfilter_queue_support_gso=no; break;],
        [
#include <stdint.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/linux_nfnetlink_queue.h>
        ])
done
if test x${libnetfilter_queue_support_gso} '!=' xno; then
    AC_DEFINE([HAVE_LIBNETFILTER_QUEUE_GSO], [1],
        [Define to 1 if libnetfilter_queue supports GSO packet handling])
else
    echo ''
    echo '  WARNING: GSO packets handling support is DISABLED!'
    echo '  Please update your libnetfilter_queue if you needs it.'
    echo ''
fi

# Debug options.
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--disable-debug],
    [disable debug functions for improved performance])],
    [enable_debug="$enableval"], [enable_debug="yes"])
AS_IF([test x$enable_debug = xno],
    [AC_DEFINE([NDEBUG], [1], [No debug support])])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo ""
echo " Basic configuration:"
echo "  C compiler ................. $CC"
echo "  Debug mode ................. $enable_debug"
echo ""
echo " Libraries configuration:"
echo "  GLIB_CFLAGS ................ $GLIB_CFLAGS"
echo "  GLIB_LIBS .................. $GLIB_LIBS"
echo "  NETFILTER_CFLAGS ........... $NETFILTER_CFLAGS"
echo "  NETFILTER_LIBS ............. $NETFILTER_LIBS"
echo "  FALGPROTO_CFLAGS ........... $FALGPROTO_CFLAGS"
echo "  FALGPROTO_LIBS ............. $FALGPROTO_LIBS"
echo ""
