#include "nmap.h"

static int get_args(int argc, char **argv, uint8_t *args)
{
	int i = 1;
	int j = 0;
	int ret = 0;

	*args = 0x00;
	while (i < argc) {
		if (argv[i] && argv[i][0] == '-') {
			j = 0;
			while (argv[i][j]) {
				j++;
			}
		}
		else
			ret = i;
		i += 1;
	}
	return ret;
}

int main(int argc, char **argv)
{
	int arg_index = 0;
	char *destination = NULL;
	uint8_t args = 0;

	arg_index = get_args(argc, argv, &args);

	/* if (arg_index < 0)
		return print_help(); */
	if (arg_index > 0)
		destination = argv[arg_index];

	ft_nmap(destination, args, argv[0]);
	return 0;
}
