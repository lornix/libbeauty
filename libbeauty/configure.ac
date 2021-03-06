AC_INIT([libbeauty],0.2.0)
AM_INIT_AUTOMAKE
AC_PREREQ(2.53)

dnl The libtool version numbers (LT_*); Don't even think about faking this!
dnl
dnl immediately before every release do:
dnl ===================================
dnl if (the interface is totally unchanged from previous release)
dnl    LT_REVISION ++;
dnl else { /* interfaces have been added, removed or changed */
dnl    LT_REVISION = 0;
dnl    LT_CURRENT ++;
dnl    if (any interfaces have been _added_ since last release)
dnl       AGE ++;
dnl    if (any interfaces have been _removed_ or _incompatibly changed_)
dnl       AGE = 0;
dnl }

LT_CURRENT=1
LT_REVISION=0
LT_AGE=0

AC_SUBST(LT_CURRENT)
AC_SUBST(LT_REVISION)
AC_SUBST(LT_AGE)

dnl ------------------------------------
dnl Configure setup
dnl ------------------------------------

AM_CONFIG_HEADER(src/config.h)

AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_CXX
AC_DISABLE_STATIC
AM_PROG_LIBTOOL

dnl ------------------------------------
dnl Flag setup
dnl ------------------------------------

AM_CPPFLAGS="-I\$(top_srcdir)/include"

CXXFLAGS="-O0 -Wall -g3"
DEBUG_CXXFLAGS="-g3 -Wall"

if test "$CXX" = "cxx"; then
   CXXFLAGS="$CXXFLAGS -D__USE_STD_IOSTREAM"
   DEBUG_CXXFLAGS="$DEBUG_CXXFLAGS -D__USE_STD_IOSTREAM"
fi

MODULE_LDFLAGS="-export-dynamic -module -avoid-version"

AC_SUBST(AM_CPPFLAGS)
AC_SUBST(CXXFLAGS)
AC_SUBST(DEBUG_CXXFLAGS)
AC_SUBST(MODULE_LDFLAGS)

dnl ------------------------------------
dnl       Path setup
dnl ------------------------------------
if test "x$prefix" = xNONE; then
   AC_MSG_CHECKING(prefix)
   prefix="${ac_default_prefix}"
   AC_MSG_RESULT($prefix)
fi
if test "x$exec_prefix" = xNONE; then
   AC_MSG_CHECKING(exec_prefix)
   exec_prefix="${prefix}"
   AC_MSG_RESULT($exec_prefix)
fi

dnl ------------------------------------
dnl    Module install path
dnl ------------------------------------
AC_ARG_WITH(modules-path,[  --with-modules-path     where libbeauty modules are installed],modules_path="$withval",modules_path="$libdir/beauty")
ac_modules_path=`eval echo "$modules_path"`
AC_DEFINE_UNQUOTED(MOD_PATH,"$ac_modules_path",[Define the path of the librevenge modules])
MOD_PATH="$ac_modules_path"
AC_SUBST(MOD_PATH)

dnl ------------------------------------
dnl    include install path
dnl ------------------------------------
AC_ARG_WITH(include-path,[  --with-include-path     where librevenge include files are installed],include_path="$withval",include_path="$includedir/beauty")
ac_include_path=`eval echo "$include_path"`
AC_DEFINE_UNQUOTED(INCLUDE_PATH,"$ac_include_path",[Define the path of the libbeauty include files])
INCLUDE_PATH="$ac_include_path"
AC_SUBST(INCLUDE_PATH)

dnl ------------------------------------
dnl ------------------------------------
dnl        Makefiles
dnl ------------------------------------
AC_CONFIG_FILES([
Makefile
misc/Makefile
src/Makefile
src/input/Makefile
src/input/binary_file_decoder/Makefile
src/input/binary_file_decoder/libbfd/Makefile
src/input/instruction_decoder/Makefile
src/input/instruction_decoder/ia32/Makefile
src/input/instruction_decoder/amd64/Makefile
src/input/instruction_decoder/llvm/Makefile
src/input/instruction_decoder/llvm/amd64/Makefile
src/input/convert_ll_inst_to_rtl/Makefile
src/execute/Makefile
src/analyse/Makefile
src/output/Makefile
src/output/cfg/Makefile
src/output/llvm/Makefile
src/output/ast/Makefile
test/Makefile
include/Makefile
])
AC_OUTPUT

echo
echo -----------------
echo    RESULTS
echo -----------------
