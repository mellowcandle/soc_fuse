#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([socfs], [v1.0], [rfried.dev@gmail.com])
AC_CONFIG_SRCDIR([socfs.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall -Werror])

# Checks for programs.
AC_PROG_CC

# First try to find FUSE3, if not found go with FUSE2
PKG_CHECK_MODULES([FUSE], [fuse3 >= 3.1],
  [AC_DEFINE([HAVE_FUSE3], [1], [Use FUSE 3])],
  [PKG_CHECK_MODULES(FUSE, [fuse >= 2.9],
    [AC_DEFINE([HAVE_FUSE2], [1], [Use FUSE 2])
  ])
])

AC_SUBST(FUSE_CFLAGS)
AC_SUBST(FUSE_LIBS)

AC_CHECK_LIB([pthread], [pthread_create])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stddef.h stdint.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([getpagesize memset munmap strchr])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
