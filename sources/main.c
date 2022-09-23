#include "nmap.h"

int main(int argc, char **argv)
{
	if (argc < 3)
		return 1;

	ft_nmap(argv[1], atoi(argv[2]), argv[0]);
	return 0;
}
