TARGET = bdstat
OBJECTS = statmain.o tcp_decode.o strintmap.o strmap.o sessionmap.o udp_decode.o
INCLUDES = 
BDSTATLIB = -lpcap -lpthread

%.o: %.c
	gcc -g -c $< -o $@ $(INCLUDES)

$(TARGET): $(OBJECTS)
	gcc -o $@ -g -Wall $(OBJECTS)  $(BDSTATLIB)


.PHONY: clean
clean:
	-rm -fr *.o $(TARGET)

