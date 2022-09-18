/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_delete.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/05/03 14:24:38 by lumenthi          #+#    #+#             */
/*   Updated: 2018/05/03 14:27:00 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

char	*ft_delete(char *line, int pos, int len)
{
	char	*after;
	char	*tmp;
	int		j;

	j = 0;
	line[len] = '\0';
	if (!(after = ft_strdup("")))
		return (NULL);
	while (line[j])
	{
		if (j != pos)
		{
			tmp = ft_strdup(after);
			free(after);
			after = ft_charjoin(tmp, line[j]);
			free(tmp);
		}
		j++;
	}
	if (line)
		free(line);
	return (after);
}
