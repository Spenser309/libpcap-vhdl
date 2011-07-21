#include <stdio.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <sys/time.h>

int timeval_subtract(struct timeval*, struct timeval*, struct timeval*);

int main(int argc, char *argv[])
{
   int i;
	char *input_file = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	struct timeval ts_old;	
	struct timeval elapsed_time;

	pcap_t *packets;
	const u_char *packet;
	struct pcap_pkthdr *header = malloc(sizeof(struct pcap_pkthdr));

	
	printf("Input File: %s\n", input_file);

	packets = pcap_open_offline(input_file, errbuf);	

	if(packets == NULL)
	{
		printf("ERROR: Could not open file.  Pcap says - %s", errbuf);
		exit(0);
	}
	
	printf("Opened %s attempting to read packet lengths\n", input_file);

   pcap_next_ex(packets, &header, &packet);
   ts_old = header->ts;

   do
	{
		if(timeval_subtract(&elapsed_time, &(header->ts), &ts_old) == 0)
		{
			printf("Packet of length [%d] arrived %li s and %li us later\n",header->len,  (long int) elapsed_time.tv_sec, (long int) elapsed_time.tv_usec);
         for(i = 0; i < header->len; i++) {
            if (i % 8 == 0 && i != 0) printf("\n");
               printf("%2X ", packet[i]);
         }
         printf("\n");
		}
		ts_old = header->ts;
		getchar();
   } while(pcap_next_ex(packets, &header, &packet) != -2); 

	printf("Thats all she wrote folks\n");
		
	pcap_close(packets);
	return(0);
}

/**
 * this function is for computing the time difference between timeval x and y
 * the result is stored in result
 */
int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
    /* Perform the carry for the later subtraction by updating y. */
    if (x->tv_usec < y->tv_usec) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_usec - y->tv_usec > 1000000) {
        int nsec = (x->tv_usec - y->tv_usec) / 1000000;
        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    /* Compute the time remaining to wait.
    tv_usec is certainly positive. */
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    /* Return 1 if result is negative. */
    return x->tv_sec < y->tv_sec;
}
