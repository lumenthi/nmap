/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strstr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/14 10:29:26 by lumenthi          #+#    #+#             */
/*   Updated: 2017/11/20 12:05:29 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strstr(const char *str, const char *to_find)
{
	int i;
	int	length;

	i = 0;
	length = ft_strlen((char*)to_find);
	if (length == 0)
		return ((char*)str);
	while (*str)
	{
		while (str[i] == to_find[i] && str[i])
			i++;
		if (i == length)
			return ((char*)str);
		else
			i = 0;
		str++;
	}
	return (NULL);
}
