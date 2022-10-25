#include "libft.h"
#include <stdio.h>

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

	//printf("argi = %d\n", argi);
	//	Arg is exactly '--'
	//	We accept this only once
	if (len == 2 && argv[argi][0] == '-' && argv[argi][1] == '-')
	{
		if (first_double == 1)
		{
			first_double = 0;
			//printf("first double\n");
			return 1;
		}
		//printf("not first double\n");
		return 0;
	}

	//	First arg
	if (argi <= 1)
	{
		if (len > 1 && argv[argi][0] == '-')
			return 1;
		return 0;
	}

	//	Check the previous arg
	char *prev_arg = argv[argi - 1];
	size_t	prev_len = ft_strlen(prev_arg);
	//printf("Previous arg = |%s|\n", prev_arg);

	// ?? Special case for previous args of 1 char len ??
	if (prev_len <= 1)
	{
		if (len > 1 && argv[argi][0] == '-')
		{
			//printf("last_len <= 1 1\n");
			return 1;
		}
		//printf("last_len <= 1 2\n");
		return 0;
	}

	//	Prev arg is not an opt
	if (prev_arg[0] != '-')
	{
		if (len > 1 && argv[argi][0] == '-')
		{
			//printf("Prev arg is not an opt. New opt\n");
			return 1;
		}
		//printf("Prev arg is not an opt. New arg\n");
		return 0;
	}
	
	//	Previous arg is a short or long option
	//	Check if it required an opt
	size_t	i = 0;
	while (optstring[i])
	{
		//	Found an opt that needs an arg in optstring
		if (optstring[i] == ':' && i > 0)
		{
			//	If the last char of the last arg was this opt
			//	it is not an option line
			if (prev_arg[prev_len - 1] == optstring[i - 1])
			{
				//	The opt has an optional argument. Only take it if it does
				//	start with an '-'
				if (optstring[i + 1] == ':')
				{
					//printf("%s is the optional arg of %s\n", argv[argi], prev_arg);
					if (argv[argi][0] == '-')
					{
						//printf("%s is a new option\n", argv[argi]);
						return 1;
					}
				}
				//printf("%s is arg of %s\n", argv[argi], prev_arg);
				//	Current arg is the arg of the previous opt
				return 2;
			}
		}
		i++;
	}
	//	If we are here, the previous arg is an opt that did not have an arg

	//	Previous arg is a short option
	if (prev_arg[1] != '-')
	{
		if (len > 1 && argv[argi][0] == '-')
		{
			//printf("Previous arg is a short option and its arg was already given. New opt\n");
			return 1;
		}
		//printf("Previous arg is a short option and its arg was already given. New arg\n");
		return 0;
	}

	//	Check is the previous arg was a long opt that requires an arg
	struct option current_opt;
	i = 0;
	while (1)
	{
		current_opt = longopts[i];
		if (current_opt.name == 0 && current_opt.has_arg == 0
			&& current_opt.flag == 0 && current_opt.val == 0)
			break;
		if (ft_optbegin(current_opt.name, prev_arg + 2)
			&& !ft_strchr(prev_arg, '=')
			&& (current_opt.has_arg == required_argument
				|| current_opt.has_arg == optional_argument))
		{
			//printf("Arg of long opt %s\n", prev_arg);
			//Current arg is the arg of the previous long opt
			return 2;
		}
		i++;
	}
	if (len > 1 && argv[argi][0] == '-')
		return 1;
	return 0;
}
