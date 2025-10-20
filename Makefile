TARGET=libcj.a
BUILDDIR=bin/
PREFIX=/usr/local/lib/
SOURCES=$(wildcard src/*.c src/arch/*.c src/arch/*/*.c)
override CFLAGS+=-std=c11 -O2 -Wno-gnu
SHARED=-shared
DEVFLAGS=-Werror -Wall -g -fPIC -DNDEBUG -Wfloat-equal -Wundef -Wwrite-strings -Wuninitialized -pedantic -O0

.PHONY: all codegen dev example demo clean install uninstall

all:
	mkdir -p $(BUILDDIR)
	$(CC) $(SOURCES) -o $(BUILDDIR)$(TARGET) $(CFLAGS) $(SHARED)

codegen: codegen_x86 codegen_arm64

codegen_x86:
	@echo "Generating x86-64 backend..."
	node codegen/x86_encoder.js

codegen_arm64:
	@echo "Generating ARM64 backend..."
	node codegen/arm64_encoder.js

dev:
	mkdir -p $(BUILDDIR)
	$(CC) $(SOURCES) -o $(BUILDDIR)$(TARGET) $(CFLAGS) $(DEVFLAGS) $(SHARED)

install: all
	install $(BUILDDIR)$(TARGET) $(PREFIX)$(TARGET)

uninstall:
	rm -rf $(PREFIX)$(TARGET)

clean:
	rm -rf $(BUILDDIR)
