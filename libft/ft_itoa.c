/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/14 12:26:03 by lumenthi          #+#    #+#             */
/*   Updated: 2017/11/24 10:28:02 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

static int		ft_length(int n)
{
	int count;

	count = 0;
	if (n < 0)
	{
		n = n * -1;
		count++;
	}
	if (n == 0)
		count = 1;
	while (n > 0)
	{
		n = n / 10;
		count++;
	}
	return (count);
}

char			*ft_itoa(int n)
{
	int		length;
	char	*str;

	if (n == -2147483648)
		return (ft_strdup("-2147483648"));
	length = ft_length(n) + 1;
	if (!(str = (char*)malloc(sizeof(char) * (length))))
		return (NULL);
	if (n == 0)
		str[0] = '0';
	if (n < 0)
	{
		str[0] = '-';
		n = n * -1;
	}
	str[length - 1] = '\0';
	while (n > 0)
	{
		length--;
		str[length - 1] = (n % 10) + '0';
		n = n / 10;
	}
	return (str);
}
