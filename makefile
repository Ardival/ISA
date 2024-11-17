# Compiler
CC = gcc
CFLAGS = -Wall -Wextra -O2
LIBS = -lpcap -lncurses #-lncurses lpcap - packets, lncurses - interference with terminal
TARGET = isa-top
SRCS = isa-top.c
OBJS = $(SRCS:.c=.o)

# Default target
all: $(TARGET)

# Build the target executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

# Compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up the build
clean:
	rm -f $(OBJS) $(TARGET)

# Phony targets (not real files)
.PHONY: all clean
