CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lcrypto

TARGET = aspnmy_crypto
SRC = Src/aspnmy_crypto.c
HEADERS=Src/aspnmy_crypto.h

build_DIR = bin

package_DIR = build/packages

INSTALL_DIR = /usr/local/bin

all:
	$(CC) $(CFLAGS) -o $(build_DIR)/$(TARGET) $(SRC) $(LDFLAGS)
	chmod +x $(build_DIR)/$(TARGET)

install:
	cp $(build_DIR)/$(TARGET) $(INSTALL_DIR)

uninstall:
	rm -f $(INSTALL_DIR)/$(TARGET)


clean:
	rm -f $(build_DIR)/$(TARGET)
	rm -f $(package_DIR)/*
	

package:
	bash package.sh 

.PHONY: all install uninstall package