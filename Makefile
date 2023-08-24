
all: bin/compr_detect

bin/compr_detect: utils.c compr_detect.c
	gcc -o bin/compr_detect utils.c compr_detect.c -I.

clean:
	rm -rf bin
	mkdir bin
