include $(top_srcdir)/misc/Makefile.common

#AM_CPPFLAGS = -I$(top_srcdir)/src/input
AM_CFLAGS = -O0 -g3 -Wall -fpic -lbeauty_input_bfd
#CFLAGS = -O0 -g3 -Wall

#modulesdir = $(pkglibdir)/beauty_exe
lib_LTLIBRARIES = libbeauty_exe.la
#bin_PROGRAMS = dis

#include_HEADERS = \
#	exe.h

#noinst_HEADERS = \
#	exe.h

libbeauty_exe_la_SOURCES = \
	exe.c process_block.c

libbeauty_exe_la_LIBADD = -L$(libdir) 

libbeauty_exe_la_LDFLAGS = \
	 -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
	 -lbeauty_input_bfd -L$(top_srcdir)/src/input/binary_file_decoder/libbfd/.libs
