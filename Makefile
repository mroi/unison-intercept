ifneq ($(shell uname),Darwin)

LIB = libintercept.so
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)
AUX = encrypt/library/libmbedcrypto.a
TGT = $(HOME)/.unison/$(LIB)

CPPFLAGS = -Iencrypt/include
CFLAGS = -std=c11 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -O3 -fPIC $(WARNINGS)
ifeq ($(shell $(CC) --version | grep -o clang | head -n1),clang)
WARNINGS = -Weverything -Wno-gnu-label-as-value -Wno-poison-system-directories
else
WARNINGS = -Wall -Wextra -Wno-unknown-pragmas
endif

.PHONY: all install clean

all: encrypt/.git $(LIB)
install: $(TGT)

clean:
	rm -f $(LIB) $(OBJ)

$(LIB): $(OBJ) $(AUX)
	$(CC) -shared -o $@ $^ -ldl

$(TGT): $(LIB)
	cp $< $@

encrypt/library/libmbedcrypto.a: encrypt/.git
	$(MAKE) -C $(@D) 'CFLAGS=-O2 -fPIC' $(@F)

encrypt/.git:
	git submodule update --init --depth 1

else

all: build

build install clean:
	xcodebuild $@

endif
