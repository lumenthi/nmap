/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsplit.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/16 09:36:32 by lumenthi          #+#    #+#             */
/*   Updated: 2017/11/22 12:44:21 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

static int		ft_nb_words(char *str, char c)
{
	int i;
	int count;

	i = 0;
	count = 0;
	while (str[i])
	{
		if (str[i] != c)
		{
			while (str[i] != c && str[i])
				i++;
			count++;
		}
		else
			i++;
	}
	return (count);
}

static char		*next_word(char *str, char c)
{
	while (*str == c && *str)
		str++;
	if (*str != c)
	{
		while (*str != c && *str)
			str++;
		while (*str == c && *str)
			str++;
	}
	return (str);
}

static int		len_word(char *str, char c)
{
	int i;

	i = 0;
	while (str[i] && str[i] != c)
		i++;
	return (i);
}

static char		*ft_fill(char *s, int len)
{
	char	*str;
	int		i;

	str = (char*)malloc(sizeof(*str) * (len + 1));
	if (str == NULL)
		return (NULL);
	i = 0;
	while (i < len)
	{
		str[i] = s[i];
		i++;
	}
	str[i] = '\0';
	return (str);
}

char			**ft_strsplit(char const *s, char c)
{
	char	**tab;
	int		i;
	int		nb_words;
	char	*str;

	if (s == NULL)
		return (NULL);
	str = (char*)s;
	i = 0;
	nb_words = ft_nb_words(str, c);
	tab = (char**)malloc(sizeof(tab) * nb_words + 1);
	if (tab == NULL)
		return (NULL);
	while (*str == c && *str)
		str++;
	while (i < nb_words)
	{
		tab[i] = ft_fill(str, len_word(str, c));
		str = next_word(str, c);
		i++;
	}
	tab[i] = NULL;
	return (tab);
}
