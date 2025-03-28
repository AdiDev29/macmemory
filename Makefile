CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS = -framework Foundation

# For building universal binary
fat:
	$(CXX) -std=c++17 -O2 -arch x86_64 -arch arm64 -o macmemory $(SOURCES) $(LDFLAGS)

TARGET = macmemory
SOURCES = macmemory.cpp

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

clean:
	rm -f $(TARGET)

.PHONY: all clean install