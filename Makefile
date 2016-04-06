all: netmonitor

netmonitor: netmonitor.c
	gcc netmonitor.c -o netmonitor -lpcap

clean:
	rm -f netmonitor
