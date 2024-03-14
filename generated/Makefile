# SPDX-License-Identifier: GPL-2.0

CC=gcc
CFLAGS=-std=gnu11 -O2 -W -Wall -Wextra -Wno-unused-parameter -Wshadow \
	-I../ -idirafter $(UAPI_PATH)
ifeq ("$(DEBUG)","1")
  CFLAGS += -g -fsanitize=address -fsanitize=leak -static-libasan
endif

include ../Makefile.deps

SRCS=$(wildcard *.c)
HDRS=$(wildcard *.h)
OBJS=$(patsubst %-user.c,%-user.o,${SRCS})

all: $(OBJS)

%-user.o: %-user.c %-user.h
	@echo -e "\tCC $@"
	@$(COMPILE.c) $(CFLAGS_$*) -o $@ $<

clean:
	rm -f *.o

.PHONY: all clean
.DEFAULT_GOAL: all
