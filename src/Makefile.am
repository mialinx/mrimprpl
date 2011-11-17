AM_LIBTOOLFLAGS = --quiet

MRIMPRPL_SOURCES = \
    proto.h \
    mrim.h \
    mrim.c \
    pkt.h \
    pkt.c \
    libmrimprpl.c

MRIMPRPL_CFLAGS = -Wall -Wno-int-to-pointer-cast

lib_LTLIBRARIES = libmrimprpl.la
libmrimprpl_la_SOURCES = $(MRIMPRPL_SOURCES)
libmrimprpl_la_LIBADD = $(GLIB_LIBS) $(PURPLE_LIBS)
libmrimprpl_la_CFLAGS = $(GLIB_CFLAGS) $(PURPLE_CFLAGS) $(MRIMPRPL_CFLAGS)
