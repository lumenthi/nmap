/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strcat.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/13 11:41:08 by lumenthi          #+#    #+#             */
/*   Updated: 2017/11/17 10:06:15 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strcat(char *dest, const char *src)
{
	char	*d;
	char	*s;
	int		i;
	int		n;

	s = (char*)src;
	d = dest;
	i = ft_strlen(dest);
	n = 0;
	while (s[n])
	{
		d[i] = s[n];
		i++;
		n++;
	}
	d[i] = '\0';
	return (dest);
}
