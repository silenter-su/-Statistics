TARGET = bdstat
OBJECTS = statmain.o strintmap.o strmap.o
INCLUDES = 
BDSTATLIB = -lpcap -lpthread

%.o: %.c
	gcc -g -c $< -o $@ $(INCLUDES)

$(TARGET): $(OBJECTS)
	gcc -o $@ -g -Wall $(OBJECTS)  $(BDSTATLIB)


.PHONY: clean
clean:
	-rm -fr *.o $(TARGET)

