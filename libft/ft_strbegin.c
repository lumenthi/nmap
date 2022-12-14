/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strbegin.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lnicosia <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/08 16:30:57 by lnicosia          #+#    #+#             */
/*   Updated: 2018/11/09 16:20:55 by lnicosia         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		ft_strbegin(char const *s1, char const *s2)
{
	if (!s1 || !s2)
		return (0);
	while (*s1 && *s2)
	{
		if (*s1 != *s2)
			return (0);
		s1++;
		s2++;
	}
	if (*s2)
		return (0);
	return (1);
}

int		ft_optbegin(char const *s1, char const *s2)
{
	if (!s1 || !s2)
		return (0);
	while (*s1 && *s2 && *s2 != '=')
	{
		if (*s1 != *s2)
			return (0);
		s1++;
		s2++;
	}
	if (*s2 && *s2 != '=')
		return (0);
	return (1);
}
