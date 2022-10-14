#include "nmap.h"

int timed_out(struct timeval start, struct timeval timeout, int status)
{
	struct timeval end;
	long long start_ms;
	long long end_ms;
	long long to_ms;

	/* Request end time */
	if ((gettimeofday(&end, NULL)) != 0) {
		end.tv_sec = 0;
		end.tv_usec = 0;
	}

	start_ms = start.tv_sec*1000 + start.tv_usec/1000;
	end_ms = end.tv_sec*1000 + end.tv_usec/1000;
	to_ms = timeout.tv_sec*1000 + timeout.tv_usec/1000;

	/* If we already timedout, the timer for timeout should be *2 */
	if (status == TIMEOUT)
		to_ms *= 2;

	if (end_ms - start_ms > to_ms)
		return 1;

	return 0;
}
