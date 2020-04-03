CFLAGS += -I ../include -mclflushopt -mclwb -O2 -fPIC -Wall -Werror

libmcommit.so: mcommit.o
	$(CC) -shared $^ -o $@

clean:
	rm -f mcommit.o libmcommit.so


