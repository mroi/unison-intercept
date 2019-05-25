ifneq ($(shell uname),Darwin)

INT = libintercept.so
SBX = libsandbox.so
SRC = $(filter-out sandbox.c,$(wildcard *.c))
OBJ = $(SRC:.c=.o)

CFLAGS = -std=c11 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -O3 -fPIC $(WARNINGS)
WARNINGS = -Weverything -Wno-static-in-inline -Wno-gnu-label-as-value

.PHONY: intercept sandbox all install clean

intercept: $(INT)
sandbox: $(SBX)
all: $(INT) $(SBX)

install: intercept
	cp $(INT) ~/.unison/

clean:
	rm -f $(INT) $(SBX) $(OBJ) sandbox.o

$(INT): $(OBJ)
	$(CC) -shared -o $@ $^ -ldl

$(SBX): sandbox.c
	@CC="$(CC)" CFLAGS="$(CFLAGS)" sh $<

else

all: build

build install clean:
	xcodebuild $@

endif
