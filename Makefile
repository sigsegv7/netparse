CFLAGS = -Werror=implicit-function-declaration -pedantic -lpcap
CFILES = $(shell find src/ -name "*.c")

bin/netp: $(CFILES)
	mkdir -p $(@D)
	gcc $(CFLAGS) $^ -o $@
