/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strrchr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/14 10:09:11 by lumenthi          #+#    #+#             */
/*   Updated: 2017/11/20 09:51:31 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strrchr(const char *str, int c)
{
	if (!ft_strchr(str, c))
		return (NULL);
	while (*str)
		str++;
	while (*str != c)
		str--;
	return ((char*)str);
}
