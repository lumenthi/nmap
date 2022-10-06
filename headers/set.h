#ifndef SET_H
# define SET_H

#include <stdint.h>

typedef struct s_range {
	uint16_t			start;
	uint16_t			end;
	char				padding[0];
} t_range;

typedef struct s_set {
	size_t				nb_ranges;
	size_t				nb_single_values;
	t_range				*ranges;
	int					max;
	int					min;
	int					*single_values;
	char				padding[0];
} t_set;

typedef struct s_ipset {
	char			*string;
	struct s_ipset	*next;
} t_ipset;

#endif
