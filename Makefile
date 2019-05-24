ifneq ($(shell uname),Darwin)

TGT = libintercept.so
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

CFLAGS = -std=c11 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -O3 -fPIC $(WARNINGS)
WARNINGS = -Weverything -Wno-static-in-inline

.PHONY: all install clean

all: $(TGT)

install: all
	cp $(TGT) ~/.unison/

clean:
	rm -f $(TGT) $(OBJ)

$(TGT): $(OBJ)
	$(CC) -shared -o $@ $^ -ldl

else

all: build

build install clean:
	xcodebuild $@

endif
