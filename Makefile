CC = gcc
CXX = g++
CFLAGS = -D_GNU_SOURCE -ggdb -I.
LDFLAGS = -lusb-1.0 -lstdc++ -lm
TARGET = xperable
SRCS = xperable.c fbusb.c target-so51a.c pe-load.cpp \
       pe-parse/pe-parser-library.cpp pe-parse/parse.cpp \
       pe-parse/nt-headers.cpp pe-parse/to_string.cpp
all: $(TARGET)
$(TARGET): $(SRCS)
	$(CXX) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)
clean:
	rm -f $(TARGET)
