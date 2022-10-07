/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_rmchar.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lnicosia <lnicosia@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/01/22 13:22:39 by lnicosia          #+#    #+#             */
/*   Updated: 2022/10/06 12:20:34 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

/*
**  Remove all occurences of a char in the given string 
*/

char	*ft_rmchar(char *str, char c)
{
	int 	i;
	int		size;
	int 	j;
	char	*res;

	i = 0;
	j = 0;
	size = ft_strlen(str);
	while (i < size)
	{
		if (str[i] != c)
		{
			str[j] = str[i];
			j++;
		}
		i++;
	}
	str[j] = 0;
	res = ft_strnew(ft_strlen(str));
	res = ft_strcpy(res, str);
	ft_strdel(&str);
	return (res);
}
