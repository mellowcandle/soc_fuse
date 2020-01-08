#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([soc_fuse], [v1.0], [rfried.dev@gmail.com])
AC_CONFIG_SRCDIR([soc_fuse.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall -Werror])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
#AC_CHECK_LIB([fuse3], [fuse_main])

PKG_CHECK_MODULES(FUSE3, fuse3 >= 3.0)
AC_SUBST(FUSE3_CFLAGS)
AC_SUBST(FUSE3_LIBS)

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
