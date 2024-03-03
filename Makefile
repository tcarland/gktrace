# gktrace Makefile

NEED_SOCKET = 1
NEED_TCANETPP = 1

ifdef USE_PTHREADS
NEED_PTHREADS = 1
endif

ifdef USE_LIBRT
NEED_LIBRT = 1
endif

ifdef TCAMAKE_DEBUG
OPT_FLAGS = 	-g
else
OPT_FLAGS =	-O2
endif

INCLUDES=       -I.
LIBS=

GKTRACE=	gktrace

BIN=		$(GKTRACE)

OBJS=		src/gktrace.o

ALL_OBJS=	$(OBJS) $(COBJS)
ALL_BINS=	$(BIN)


ifeq ($(TCAMAKE_HOME),)
	export TCAMAKE_HOME := $(shell realpath ../tcamake)
endif

include $(TCAMAKE_HOME)/tcamake_include


all: gktrace

gktrace: $(OBJS)
	$(make-cxxbin-rule)
	@echo

clean:
	$(RM) $(ALL_OBJS) \
	*.d *.D *.o src/*.d src/*.D src/*.bd src/*.o
	@echo

distclean: clean
	$(RM) $(ALL_BINS)
	@echo

dist:
ifdef TCAMAKE_DISTDIR
ifdef TCAMAKE_DEBUG
	$(MKDIR) $(TCAMAKE_DISTDIR)/$(TCA_PORT_IDENTIFIER)/debug
	$(CP) $(GKTRACE) $(TCAMAKE_DISTDIR)/$(TCA_PORT_IDENTIFIER)/debug/
else
	$(MKDIR) $(TCAMAKE_DISTDIR)/$(TCA_PORT_IDENTIFIER)/release
	$(CP) $(GKTRACE) $(TCAMAKE_DISTDIR)/$(TCA_PORT_IDENTIFIER)/release/
endif
endif

install:
ifndef TCAMAKE_DEBUG
	( strip $(GKTRACE) )
endif
ifdef TCAMAKE_PREFIX
	$(MKDIR) $(TCAMAKE_PREFIX)/bin
	$(CP) $(GKTRACE) $(TCAMAKE_PREFIX)/bin/
	( sudo chown root $(TCAMAKE_PREFIX)/bin/$(GKTRACE) )
	( sudo chmod u+s $(TCAMAKE_PREFIX)/bin/$(GKTRACE) )
	@echo
else
	( sudo chown root $(GKTRACE) )
	( sudo chmod u+s $(GKTRACE) )
endif

