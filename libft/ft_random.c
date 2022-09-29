/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_random.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <lumenthi@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/09/29 12:51:09 by lumenthi          #+#    #+#             */
/*   Updated: 2022/09/29 12:52:44 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <fcntl.h>
#include <unistd.h>

int ft_random(int min, int max)
{
	int fd = open("/dev/urandom", O_RDONLY);
	int data = -1;

	if (fd < 0)
		return -1;
	else {
		while (data < min || data > max) {
			read(fd, &data, 2);
			data *= data < 0 ? -1 : 1;
		}
	}
	close(fd);
	return data;
}
