ifneq ($(shell uname),Darwin)

LIB = libintercept.so
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)
AUX = encrypt/library/libmbedcrypto.a
TGT = $(HOME)/.unison/$(LIB)

CFLAGS = -std=c11 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -O3 -fPIC $(WARNINGS)
ifeq ($(shell $(CC) --version | grep -o clang | head -n1),clang)
WARNINGS = -Weverything -Wno-gnu-label-as-value -Wno-poison-system-directories
else
WARNINGS = -Wall -Wextra -Wno-unknown-pragmas
endif

.PHONY: all install clean

all: $(LIB)
install: $(TGT)

clean:
	rm -f $(LIB) $(SBX) $(OBJ)

$(LIB): $(OBJ) $(AUX)
	$(CC) -shared -o $@ $^ -ldl

$(TGT): $(LIB)
	cp $< $@

encrypt/library/libmbedcrypto.a:
	$(MAKE) -C $(@D) $(@F)

else

all: build

build install clean:
	xcodebuild $@

endif
