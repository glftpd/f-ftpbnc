# f-ftpbnc v1.5 Makefile
# f-ftpbnc--release--1.5 2005-10-30 19:14

DFLAGS=-W -Wall -g
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
