#CC=g++
#CFLAGS=-O3 -Wall -g -L/usr/local/lib/exasock/ -L/usr/local/lib/ -lexasock_ext -lexanic 
#LDFLAGS=-lexanic -Wl --no-whole-archive -L/usr/local/lib/exasock/ -L/usr/local/lib/
#SOURCES=dogpatch_hw.cpp main.cpp
#OBJECTS=$(SOURCES:.cpp=.o)
#EXECUTABLE=main
#
#all: $(EXECUTABLE)
#
#$(EXECUTABLE): $(OBJECTS)
#	$(CC) $(LDFLAGS) $(OBJECTS) -o $@
#
#%.o: %.cpp
#	$(CC) $(CFLAGS) $< -o $@

PREFIX=/usr/local
CC=g++
CFLAGS=-fPIC -O3 -Wall -Wextra -Wno-ignored-qualifiers -Wno-inline -Wno-maybe-uninitialized -Wno-unused -Wno-unused-parameter -fno-trapping-math -g -std=c++23
LDLIBS= -Wl,--whole-archive -lexanic -Wl,--no-whole-archive -lexasock_ext
#LDLIBS= -Wl,--whole-archive -lexanic -Wl,--no-whole-archive -lexasock_preload -L/usr/local/lib/exasock/ -L/usr/local/lib/

libs=libdogpatch_hw.so
all: $(libs)

libdogpatch_hw.so: dogpatch_hw.o
	$(CC) $(CFLAGS) $(LDLIBS) --shared -o $@ $^

dogpatch_hw.o: dogpatch_hw.cpp
	$(CC) $(CFLAGS) $(LDLIBS) -c $^

clean:
	rm -f $(libs) dogpatch_hw.o
