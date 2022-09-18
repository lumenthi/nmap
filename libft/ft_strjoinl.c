/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strjoinl.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/05/03 14:44:37 by lumenthi          #+#    #+#             */
/*   Updated: 2018/05/03 14:57:27 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include "stdlib.h"

char	*ft_strjoinl(char *s1, char *s2)
{
	char	*tmp;

	if (!s1)
		return (NULL);
	if (!(tmp = ft_strdup(s1)))
		return (NULL);
	free(s1);
	if (!(s1 = ft_strjoin(tmp, s2)))
		return (NULL);
	free(tmp);
	return (s1);
}
