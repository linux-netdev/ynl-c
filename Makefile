# SPDX-License-Identifier: GPL-2.0

CC=gcc
CFLAGS=-std=gnu11 -O2 -W -Wall -Wextra -Wno-unused-parameter -Wshadow
ifeq ("$(DEBUG)","1")
  CFLAGS += -g -fsanitize=address -fsanitize=leak -static-libasan
endif

include $(wildcard *.d)

GEN_SRCS=$(wildcard generated/*.c)
GENERATED=$(patsubst %.c,%.o,${GEN_SRCS})

all: ynl.a

generated:
	$(MAKE) -C $@

ynl.a: ynl.o generated
	@echo -e "\tAR $@"
	@ar rcs $@ ynl.o $(GENERATED)

clean:
	rm -f *.o *.d *~
	$(MAKE) -C generated $@

distclean: clean
	rm -f *.a

%.o: %.c
	@echo -e "\tCC $@"
	@$(COMPILE.c) -MMD -c -o $@ $<

.PHONY: all clean generated
.DEFAULT_GOAL=all
