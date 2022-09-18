/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstnew.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/21 17:19:27 by lumenthi          #+#    #+#             */
/*   Updated: 2017/11/21 18:31:39 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

t_list	*ft_lstnew(void const *content, size_t content_size)
{
	t_list *li;

	li = malloc(sizeof(t_list));
	if (li == NULL)
		return (NULL);
	if (content == NULL)
	{
		li->content = NULL;
		li->content_size = 0;
	}
	else
	{
		li->content = malloc(content_size);
		if (li->content == NULL)
			return (NULL);
		ft_memcpy(li->content, content, content_size);
		li->content_size = content_size;
	}
	li->next = NULL;
	return (li);
}
