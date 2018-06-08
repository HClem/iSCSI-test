CC = gcc
CPPFLAGS=$(shell pkg-config --cflags libiscsi)
CFLAGS=-Wall -Wextra -g
LDLIBS= $(shell pkg-config --libs libiscsi)

iscsiclient:
