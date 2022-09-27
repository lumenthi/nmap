#include "libft.h"

/*
**	Tells if a command line argument is an opt
**	Returns 1 if it is, 0 if it is not and 2 if it is an argument required
**	for the opt before
*/

int		is_arg_an_opt(char * const argv[], int argi, const char *optstring,
						const struct option *longopts)
{
	static int	first_double = 1;
	size_t		len = ft_strlen(argv[argi]);

	//	Arg is exactly '--'
	if (len == 2 && argv[argi][0] == '-' && argv[argi][1] == '-')
	{
		if (first_double == 1)
		{
			first_double = 0;
			return 1;
		}
		return 0;
	}

	//	Arg does not start with '-'.
	//	is it an arg for the last opt?
	if (argi <= 1)
	{
		if (len > 1 && argv[argi][0] == '-')
			return 1;
		return 0;
	}

	//	Let's check the last arg
	char *last_arg = argv[argi - 1];
	size_t	last_len = ft_strlen(last_arg);
	if (last_len <= 1)
	{
		if (len > 1 && argv[argi][0] == '-')
			return 1;
		return 0;
	}

	//	Check is the last arg was a short opt that requires an arg
	if (last_arg[0] != '-')
	{
		if (len > 1 && argv[argi][0] == '-')
			return 1;
		return 0;
	}
	size_t	i = 0;
	while (optstring[i])
	{
		//	Found an opt that needs an arg in optstring
		if (optstring[i] == ':' && i > 0)
		{
			//	If the last char of the last arg was this opt
			//	it is not an option line
			if (last_arg[last_len - 1] == optstring[i - 1])
				return 2;
		}
		i++;
	}

	//	Check is the last arg was a long opt that requires an arg
	if (last_arg[1] != '-')
	{
		if (len > 1 && argv[argi][0] == '-')
			return 1;
		return 0;
	}
	i = 0;
	while (1)
	{
		struct option current_opt = longopts[i];
		if (current_opt.name == 0 && current_opt.has_arg == 0
			&& current_opt.flag == 0 && current_opt.val == 0)
			break;
		if (ft_optbegin(current_opt.name, last_arg + 2)
			&& (current_opt.has_arg == required_argument
				|| current_opt.has_arg == optional_argument))
			return 2;
		i++;
	}
	if (len > 1 && argv[argi][0] == '-')
		return 1;
	return 0;
}
