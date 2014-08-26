TARGET := a
SOURCE := parser

CC  := gcc

STD := c99
CFLAGS := -std=$(STD) -O3 -fdata-sections -ffunction-sections -flto
LDFLAGS := -static  -Wl,--gc-sections -s -lz

SOURCES := $(foreach FILE,$(SOURCE),$(FILE).c)

all: $(TARGET).out

$(TARGET).out: $(SOURCES)
	$(CC) $(SOURCES) -o $(TARGET).out $(CFLAGS) $(LDFLAGS)
clean:
	rm -f $(TARGET).out
