/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/14 10:58:16 by lumenthi          #+#    #+#             */
/*   Updated: 2017/11/20 14:06:39 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strnstr(const char *str, const char *to_find, size_t len)
{
	size_t	size;

	if (*to_find == '\0')
		return ((char*)str);
	size = ft_strlen((char*)to_find);
	while (*str && len >= size)
	{
		if (ft_strncmp(str, to_find, size) == 0)
			return ((char*)str);
		str++;
		len--;
	}
	return (NULL);
}
