CC      = gcc
CFLAGS  = -Wall -Wextra -g
LDFLAGS = -lpcap

SRC_DIR   = src
TEST_DIR  = tests
BUILD_DIR = build

SRCS      = $(SRC_DIR)/main.c $(SRC_DIR)/capture.c $(SRC_DIR)/parser.c
OBJS      = $(BUILD_DIR)/main.o $(BUILD_DIR)/capture.o $(BUILD_DIR)/parser.o
TARGET    = analyzer

TEST_SRCS = $(TEST_DIR)/test_parser.c $(SRC_DIR)/parser.c
TEST_OBJS = $(BUILD_DIR)/test_parser.o $(BUILD_DIR)/parser_test.o
TEST_BIN  = test_runner

.PHONY: all test clean

all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.c $(SRC_DIR)/capture.h $(SRC_DIR)/parser.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/capture.o: $(SRC_DIR)/capture.c $(SRC_DIR)/capture.h $(SRC_DIR)/parser.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/parser.o: $(SRC_DIR)/parser.c $(SRC_DIR)/parser.h
	$(CC) $(CFLAGS) -c -o $@ $<

# Test binary links only parser.c (no libpcap dependency)
test: $(BUILD_DIR) $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/test_parser.o: $(TEST_DIR)/test_parser.c $(SRC_DIR)/parser.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/parser_test.o: $(SRC_DIR)/parser.c $(SRC_DIR)/parser.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(TARGET) $(TEST_BIN) capture.log
