#include <sys/time.h>
#include <stdio.h>
#include <stdint.h>

uint64_t		timeval_to_usec(struct timeval t)
{
	return (t.tv_sec * 1000000 + t.tv_usec);
}

uint64_t		get_time(void)
{
	struct timeval	time;

	if (gettimeofday(&time, NULL) == -1)
	{
		perror("gettimeofday");
		return 0;
	}
	return (time.tv_sec * 1000000 + time.tv_usec);
}
