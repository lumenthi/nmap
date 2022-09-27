#include "nmap.h"
#include "libft.h"

void	free_all()
{
}

void	free_and_exit(int exit_val)
{
	free_all();
	exit(exit_val);
}
