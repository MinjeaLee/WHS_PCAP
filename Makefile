NAME=pcap

SRC=pcap.c
INC=whspcap.h

OBJ=$(SRC:.c=.o)

name: $(OBJ)
	$(CC) $(CFLAGS) -o $(NAME) $(OBJ) -lpcap

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

re: fclean name

.PHONY: name clean fclean re