CC := cc
CFLAGS := -O2 -g -Wall -Wextra -Wshadow -Wconversion -fno-omit-frame-pointer -D_GNU_SOURCE -std=gnu11
LDFLAGS :=

SRC_DIR := src
INC_DIR := include
BIN := userlandmylove

SRCS := $(SRC_DIR)/vdso.c $(SRC_DIR)/sysfp.c $(SRC_DIR)/main.c
OBJS := $(SRCS:.c=.o)

.PHONY: all clean run

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -I$(INC_DIR) -o $@ $^ $(LDFLAGS)

%.o: %.c $(INC_DIR)/vdso.h
	$(CC) $(CFLAGS) -I$(INC_DIR) -c -o $@ $<

run: $(BIN)
	./$(BIN)

clean:
	rm -f $(OBJS) $(BIN)


