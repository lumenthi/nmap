/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_charjoin.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/30 14:02:49 by lumenthi          #+#    #+#             */
/*   Updated: 2018/03/30 14:03:14 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

char	*ft_charjoin(char *s1, char s2)
{
	char	*ptr;
	int		i;

	ptr = (char *)malloc(sizeof(char) * (ft_strlen(s1) + 2));
	i = 0;
	if (ptr == NULL || !s1 || !s2)
		return (NULL);
	while (s1[i])
	{
		ptr[i] = s1[i];
		i++;
	}
	if (s1[i] == '\0')
	{
		ptr[i] = s2;
		i++;
	}
	ptr[i] = '\0';
	return (ptr);
}
