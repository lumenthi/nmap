/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/11 15:37:46 by lumenthi          #+#    #+#             */
/*   Updated: 2017/11/21 11:52:46 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memmove(void *str1, const void *str2, size_t n)
{
	char		*dest;
	const char	*src;

	dest = (char*)str1;
	src = (char*)str2;
	if (src < dest)
		while (n--)
			dest[n] = src[n];
	else
		ft_memcpy(dest, src, n);
	return (str1);
}
