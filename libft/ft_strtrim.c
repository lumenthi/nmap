/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/16 08:58:41 by lumenthi          #+#    #+#             */
/*   Updated: 2017/11/24 10:28:29 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

char			*ft_strtrim(char const *s)
{
	char	*str;
	int		b;
	int		e;
	int		i;

	i = 0;
	b = 0;
	if (!s)
		return (NULL);
	e = ft_strlen(s);
	while (s[e - 1] == ' ' || s[e - 1] == '\n' || s[e - 1] == '\t')
		e--;
	while (s[b] == ' ' || s[b] == '\n' || s[b] == '\t')
	{
		b++;
		e--;
	}
	if (e < 0)
		e = 0;
	if ((str = (char*)malloc(sizeof(char) * (e + 1))) == NULL)
		return (NULL);
	while (i < e)
		str[i++] = s[b++];
	str[i] = '\0';
	return (str);
}
