# Compiler
CC = gcc
CFLAGS = -Wall -Wextra -O2
LIBS = -lpcap -lncurses #-lncurses lpcap - packets, lncurses - interference with terminal
TARGET = isa-top
SRCS = isa-top.c

# Default target
all: $(TARGET)

# Build the target executable
$(TARGET):
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LIBS)

# Clean up the build
clean:
	rm -f $(TARGET)

# Phony targets (not real files)
.PHONY: all clean
