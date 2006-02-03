CFLAGS = -Os -W -Wall -std=gnu99
LDFLAGS = -lpam -lpam_misc

.PHONY: all
all: ulock

ulock: ulock.o

.PHONY: clean
clean:
	rm -f tags ulock *.o

# vim:ts=4
