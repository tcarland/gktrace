ifdef TCAMAKE_PROJECT
    TOPDIR = ../..
else
    TOPDIR = .
endif

USE_PTHREADS = 1

NEED_SOCKET = 1
NEED_TCANETPP = 1
NEED_PTHREADS = 1
NEED_LIBRT = 1

ifdef TNMS_DEBUG
OPT_FLAGS = 	-g
else
OPT_FLAGS =	-O2
endif

INCLUDES=       -I.
LIBS=

GKTRACE=	gktrace

BIN=		$(GKTRACE)

OBJS=		gktrace.o

ALL_OBJS=	$(OBJS) $(COBJS)
ALL_BINS=	$(BIN)

all: gktrace

include $(TOPDIR)/tcamake/project_defs


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
ifdef TNMS_DISTDIR
ifdef TNMS_DEBUG
	$(MKDIR) $(TNMS_DISTDIR)/$(TCA_PORT_IDENTIFIER)/debug
	$(CP) $(GKTRACE) $(TNMS_DISTDIR)/$(TCA_PORT_IDENTIFIER)/debug/
else
	$(MKDIR) $(TNMS_DISTDIR)/$(TCA_PORT_IDENTIFIER)/release
	$(CP) $(GKTRACE) $(TNMS_DISTDIR)/$(TCA_PORT_IDENTIFIER)/release/
endif
endif

install:
ifndef TNMS_DEBUG
	( strip $(GKTRACE) )
endif
ifdef TNMS_PREFIX
	$(MKDIR) $(TNMS_PREFIX)/bin
	$(CP) $(GKTRACE) $(TNMS_PREFIX)/bin/
	( sudo chown root $(TNMS_PREFIX)/bin/$(GKTRACE) )
	( sudo chmod u+s $(TNMS_PREFIX)/bin/$(GKTRACE) )
	@echo
else
	( sudo chown root $(GKTRACE) )
	( sudo chmod u+s $(GKTRACE) )
endif

