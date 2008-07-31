CFLAGS = -Os -W -Wall -std=gnu99
LDFLAGS = -lpam

DB2MAN=/usr/share/sgml/docbook/stylesheet/xsl/nwalsh/manpages/docbook.xsl
XSLTPROC=xsltproc --nonet

.PHONY: all
all: ulock

ulock: ulock.o

.PHONY: clean
clean:
	rm -f tags ulock *.o *.1

ulock.1: ulock.xml
	$(XSLTPROC) --output $(@) $(DB2MAN) $(<)

# vim:ts=4
