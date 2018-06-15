CINCLUDE = -I/opt/local/include -I/usr/local/include/pbc -I/usr/local/openssl/include
LIBS = -lpbc -lgmp -lcrypto
CFLAGS = -w -g $(CINCLUDE)
DEFLIST = -DDEBUG

all: interval

interval: interval.c
	gcc $(CFLAGS) -o $@ $^ $(LIBS)

clean: 
	rm interval

# ./pbc_test <param
