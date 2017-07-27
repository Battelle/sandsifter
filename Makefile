# sand sifter make file
#
# in x86, instructions run in 32 bit mode sometimes differ from the same
# instructions run in 64 bit mode.  for this reason, it can be beneficial to
# fuzz both 32 and 64 bit instructions.  this requires a 32 and 64 bit binary.
# afaict, capstone will not let you simultaneously install both 32 and 64 bit
# versions.  to overcome this, we statically link to capstone.  to build both a
# 32 bit and 64 bit injector:
#
# - build and install 32 bit capstone:
#   ./make.sh nix32
#   sudo ./make.sh nix32 install
#
# - build the 32 bit injector:
#   make CFLAGS=-m32
#   mv injector injector_32
#
# - build and install 64 bit capstone:
#   ./make.sh
#   sudo ./make.sh install
#
# - build the 64 bit injector:
#   make injector
#   mv injector injector_64
#
# you can now copy injector_32 and injector_64 to 'injector' before running
# ./sifter.py in order to explore that facet of the architecture.
#
#TODO: i don't know if i was ever able to get a statically linked capstone to
# work like i describe above

all: injector

injector: injector.o
	$(CC) $(CFLAGS) $< -O3 -Wall -l:libcapstone.a -o $@ -pthread

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ -Wall

clean:
	rm *.o injector
