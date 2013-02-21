all: mailrating

CXX=g++
CXXFLAGS=-std=c++11 -W -Wall -Werror -Wextra -ggdb
LIBS=-lmicrohttpd

mailrating: main.o
	$(CXX) $(CXXFLAGS) $< $(LIBS) -o $@

%.o: %.c++ *.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -fv mailrating *.o
