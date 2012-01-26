tcp_accelerator: split_tcp_gateway.o
		 g++ -o tcp_accelerator split_tcp_gateway.o -lpthread -L lib/ -lpcap

split_tcp_gateway.o: split_tcp_gateway.cpp split_tcp_gateway.h es_TIMER.h
		     g++ -c -O3 split_tcp_gateway.cpp 
clean:
	rm split_tcp_gateway.o 
