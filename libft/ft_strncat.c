/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strncat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/13 12:32:20 by lumenthi          #+#    #+#             */
/*   Updated: 2017/11/20 09:50:06 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strncat(char *dest, const char *src, size_t n)
{
	char	*t;

	t = dest;
	while (*t)
		t++;
	while (*src && n > 0)
	{
		*t++ = *src++;
		n--;
	}
	*t = '\0';
	return (dest);
}
