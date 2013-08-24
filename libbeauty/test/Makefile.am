include $(top_srcdir)/misc/Makefile.common

AM_CFLAGS = -I$(top_srcdir)/test -I/usr/include/llvm-c-3.2 -I/usr/include/llvm-3.2 -O0 -g3 -Wall

#bin_PROGRAMS = dis32 dis64 bf
noinst_PROGRAMS = dis64 test_id

#noinst_HEADERS = \
#	dis.h \
#	opcodes.h

#dis32_SOURCES = \
#	dis32.c
#
#dis32_LDADD = -L$(libdir) -lbeauty_input_bfd -lbeauty_decoder_ia32 -lopcodes -liberty -lbeauty_exe -lbfd -lz
#
#dis32_LDFLAGS = @MODULE_LDFLAGS@

dis64_SOURCES = \
	dis64.c

test_id_SOURCES = \
	test_id.c

#dis64_LDADD = -L$(libdir) -lbeauty_input_bfd -lbeauty_decoder_amd64 -lopcodes -liberty -lbeauty_exe -lbeauty_analyse -lbeauty_output -lbeauty_llvm -lbfd -lz -ldl
dis64_LDADD = -L$(libdir) -lbeauty_input_bfd -lbeauty_decoder_amd64 -lbeauty_exe -lbeauty_analyse -lbeauty_output -lbeauty_llvm -lz -ldl
test_id_LDADD = -L$(libdir) -lbeauty_input_bfd -lbeauty_decoder_amd64 -lz -ldl -lLLVM-3.2 -L/usr/lib/llvm-3.2/lib

dis64_LDFLAGS = @MODULE_LDFLAGS@ -O0 -Wall
test_id_LDFLAGS = @MODULE_LDFLAGS@ -O0 -Wall

#bf_SOURCES = \
#	bf.c
#
#bf_LDADD = -L$(libdir) -lbeauty_input_bfd
#
#bf_LDFLAGS = @MODULE_LDFLAGS@
