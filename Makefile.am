# vim: set sw=8 ts=8 sts=8 noet:

NULL =

bin_PROGRAMS = src/fastalg-nfqueue

EXTRA_DIST = \
	autogen.sh		\
	$(NULL)

src_fastalg_nfqueue_SOURCES = \
	src/falgnfq-private.h	\
	src/falgnfq-main.c	\
	src/falgnfq-config.h	\
	src/falgnfq-config.c	\
	src/falgnfq-loop.h	\
	src/falgnfq-loop.c	\
	src/falgnfq-dump.h	\
	src/falgnfq-dump.c	\
	src/falgnfq-tcp.h	\
	src/falgnfq-tcp.c	\
	src/falgnfq-rng.h	\
	src/falgnfq-rng.c	\
	$(NULL)

src_fastalg_nfqueue_CFLAGS = \
	$(GLIB_CFLAGS)		\
	$(NETFILTER_CFLAGS)	\
	$(FALGPROTO_CFLAGS)	\
	$(NULL)

src_fastalg_nfqueue_LDADD = \
	$(GLIB_LIBS)		\
	$(NETFILTER_LIBS)	\
	$(FALGPROTO_LIBS)	\
	$(NULL)
