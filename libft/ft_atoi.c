/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoi.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/14 13:20:06 by lumenthi          #+#    #+#             */
/*   Updated: 2017/11/17 10:57:34 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int	ft_atoi(const char *str)
{
	int i;
	int sign;
	int nb;

	i = 0;
	nb = 0;
	sign = 1;
	while (str[i] == '\n' || str[i] == '\f' || str[i] == '\v' ||
		str[i] == '\r' || str[i] == '\t' || str[i] == ' ')
		i++;
	if (str[i] == '-')
		sign = -1;
	if (str[i] == '+' || str[i] == '-')
	{
		if (str[i + 1] < '0' || str[i + 1] > '9')
			return (0);
		i++;
	}
	while (str[i] >= '0' && str[i] <= '9')
	{
		nb = nb * 10 + (str[i] - '0');
		i++;
	}
	return (nb * sign);
}

long long	ft_atoll(const char *str)
{
	int i;
	int sign;
	long long nb;

	i = 0;
	nb = 0;
	sign = 1;
	while (str[i] == '\n' || str[i] == '\f' || str[i] == '\v' ||
		str[i] == '\r' || str[i] == '\t' || str[i] == ' ')
		i++;
	if (str[i] == '-')
		sign = -1;
	if (str[i] == '+' || str[i] == '-')
	{
		if (str[i + 1] < '0' || str[i + 1] > '9')
			return (0);
		i++;
	}
	while (str[i] >= '0' && str[i] <= '9')
	{
		nb = nb * 10 + (str[i] - '0');
		i++;
	}
	return (nb * sign);
}
