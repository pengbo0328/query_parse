PARSER_SUBDIRS = src/parser

PG_CPPFLAGS = -I$(libpq_srcdir) -L$(libdir) -Isrc/include -Isrc/include/parser -Isrc/parser
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

AR = ar rs
RM = rm -f

PROGRAM = query_parse

libsql_parser_a_OBJECTS = \
	$(PARSER_SUBDIRS)/copyfuncs.o \
	$(PARSER_SUBDIRS)/gram.o \
	$(PARSER_SUBDIRS)/keywords.o \
	$(PARSER_SUBDIRS)/list.o \
	$(PARSER_SUBDIRS)/makefuncs.o \
	$(PARSER_SUBDIRS)/nodes.o \
	$(PARSER_SUBDIRS)/outfuncs.o \
	$(PARSER_SUBDIRS)/parser.o \
	$(PARSER_SUBDIRS)/pool_string.o \
	$(PARSER_SUBDIRS)/scansup.o \
	$(PARSER_SUBDIRS)/stringinfo.o \
	$(PARSER_SUBDIRS)/value.o \
	$(PARSER_SUBDIRS)/wchar.o \
	$(PARSER_SUBDIRS)/scan.o \
	$(PARSER_SUBDIRS)/funcs.o \
	src/utils/mmgr/mcxt.o \
	src/utils/mmgr/aset.o \
	src/utils/error/elog.o \
	src/utils/psprintf.o

libsql_parser_a_SOURCES = \
	$(PARSER_SUBDIRS)/copyfuncs.c \
	$(PARSER_SUBDIRS)/gram.y \
	$(PARSER_SUBDIRS)/keywords.c \
	$(PARSER_SUBDIRS)/list.c \
	$(PARSER_SUBDIRS)/makefuncs.c \
	$(PARSER_SUBDIRS)/nodes.c \
	$(PARSER_SUBDIRS)/outfuncs.c \
	$(PARSER_SUBDIRS)/parser.c \
	$(PARSER_SUBDIRS)/pool_string.c \
	$(PARSER_SUBDIRS)/scansup.c \
	$(PARSER_SUBDIRS)/stringinfo.c \
	$(PARSER_SUBDIRS)/value.c \
	$(PARSER_SUBDIRS)/wchar.c \
	$(PARSER_SUBDIRS)/scan.l \
	$(PARSER_SUBDIRS)/funcs.c \
	src/utils/mmgr/mcxt.c \
	src/utils/mmgr/aset.c \
	src/utils/error/elog.c \
	src/utils/psprintf.c

all: $(PROGRAM)

$(PROGRAM): $(PROGRAM).c libsql-parser.a 
	$(CC) -o $(PROGRAM) $(PROGRAM).c $(PG_CPPFLAGS) -L$(PARSER_SUBDIRS) -lsql-parser

libsql-parser.a: $(libsql_parser_a_OBJECTS) $(libsql_parser_a_DEPENDENCIES) $(EXTRA_libsql_parser_a_DEPENDENCIES)
	$(RM) $(PARSER_SUBDIRS)/libsql-parser.a
	$(AR)  $(PARSER_SUBDIRS)/libsql-parser.a $(libsql_parser_a_OBJECTS) $(libsql_parser_a_SOURCES)

clean:
	-@ $(RM) $(PROGRAM) $(PROGRAM).o
	-@ $(RM) $(PARSER_SUBDIRS)/*.o
	-@ $(RM) src/utils/*.o
	-@ $(RM) src/utils/error/*.o
	-@ $(RM) src/utils/mmgr/*.o

