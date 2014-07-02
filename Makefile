# f-ftpbnc v1.0 Makefile
# $Rev: 1232 $ $Date: 2004-11-09 14:30:45 +0100 (Tue, 09 Nov 2004) $

DFLAGS=-O3 -W -Wall
CFLAGS=$(DFLAGS)
LDFLAGS=
LIBS=

all: f-ftpbnc

new: clean f-ftpbnc

config:
	./mkconfig

clean:
	rm -f *.o f-ftpbnc mkconfig

sha256.o: sha256.c
	$(CC) $(CFLAGS) -c -o $@ $<

f-ftpbnc.o: f-ftpbnc.c xtea-cipher.h inc-config.h
	$(CC) $(CFLAGS) -c -o $@ f-ftpbnc.c

f-ftpbnc: f-ftpbnc.o sha256.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ f-ftpbnc.o sha256.o $(LIBS)
	strip -s $@

mkconfig.o: mkconfig.c xtea-cipher.h
	$(CC) $(CFLAGS) -c -o $@ $<

mkconfig: mkconfig.o sha256.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ mkconfig.o sha256.o $(LIBS)

inc-config.h: mkconfig
	./mkconfig
