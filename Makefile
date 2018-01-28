all: transproxify

transproxify: main.cpp
	g++ -O3 main.cpp -o transproxify

clean:
	$(RM) transproxify
