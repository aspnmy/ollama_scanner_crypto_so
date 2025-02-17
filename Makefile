CC = gcc
CFLAGS = -O2 -Wall
LDFLAGS = -lcrypto

TARGET = aspnmy_crypto
SRC = Src/aspnmy_crypto.c

build_DIR = bin

INSTALL_DIR = /usr/local/bin

all:
	$(CC) $(CFLAGS) -o $(build_DIR)/$(TARGET) $(SRC) $(LDFLAGS)

install:
	cp $(build_DIR)/$(TARGET) $(INSTALL_DIR)

uninstall:
	rm -f $(INSTALL_DIR)/$(TARGET)

package:
	bash package.sh 

# 定义伪目标，避免与实际文件冲突
.PHONY: all install uninstall package