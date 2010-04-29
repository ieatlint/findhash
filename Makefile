PKGLIBS = libcurl
CFLAGS = `pkg-config --cflags ${PKGLIBS}` `libgcrypt-config --cflags`
LIBS = `pkg-config --libs ${PKGLIBS}` `libgcrypt-config --libs` -lmagic -larchive
DEBUG = -g -Wall

GCC = gcc -std=c99

all:
	$(GCC) $(DEBUG) $(CFLAGS) -c rehasher.c
	$(GCC) $(DEBUG) $(LIBS) -o rehasher rehasher.o

clean:
	rm -f rehasher.o rehasher
