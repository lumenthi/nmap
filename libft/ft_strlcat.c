/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/13 13:22:16 by lumenthi          #+#    #+#             */
/*   Updated: 2017/11/20 09:50:38 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t	ft_strlcat(char *dest, const char *src, size_t count)
{
	size_t	i;
	size_t	j;

	i = 0;
	j = 0;
	if (count == 0)
		return (ft_strlen((char*)src));
	while (dest[i] && i < count)
		i++;
	if ((count - i) == 0)
		return (i + ft_strlen((char*)src));
	while (src[j] && i < count - 1)
		dest[i++] = src[j++];
	dest[i] = '\0';
	return (ft_strlen((char*)src) + i - j);
}
