/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memcpy.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/11 14:46:54 by lumenthi          #+#    #+#             */
/*   Updated: 2017/11/17 09:59:56 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memcpy(void *str1, const void *str2, size_t n)
{
	size_t		i;
	char		*dest;
	const char	*src;

	i = 0;
	dest = str1;
	src = str2;
	while (i < n)
	{
		dest[i] = src[i];
		i++;
	}
	return (str1);
}
