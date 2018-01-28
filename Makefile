all: transproxify

transproxify: main.cpp
	g++ -Wall -Wextra -O3 -o transproxify main.cpp

clean:
	$(RM) transproxify
