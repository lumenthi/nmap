/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_puthex.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <lumenthi@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/01/17 12:34:01 by lumenthi          #+#    #+#             */
/*   Updated: 2020/01/17 13:02:48 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	hex_len(size_t input)
{
	int i;

	i = 0;
	while ((input >>= 4) > 0)
		i++;
	return (i);
}

void		ft_puthex(int zero, int caps, size_t input)
{
	char	HEX_ARRAY[17];
	int		i;
	int		len;

	i = 0;
	len = hex_len(input);
	if (caps)
		ft_strcpy(HEX_ARRAY, "0123456789ABCDEF");
	else
		ft_strcpy(HEX_ARRAY, "0123456789abcdef");
	if (zero == 1)
		ft_putstr("0x");
	while (i <= len)
	{
		ft_putchar(HEX_ARRAY[((input >> (4 * (len))) & 0xF)]);
		input <<= 4;
		i++;
	  }
}
