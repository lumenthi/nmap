/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/21 18:01:12 by lumenthi          #+#    #+#             */
/*   Updated: 2017/11/21 19:02:05 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

t_list	*ft_lstmap(t_list *lst, t_list *(*f)(t_list *elem))
{
	t_list *first;
	t_list *new;
	t_list *tmp;

	tmp = f(lst);
	new = ft_lstnew(tmp->content, tmp->content_size);
	if (new == NULL)
		return (NULL);
	first = new;
	lst = lst->next;
	while (lst)
	{
		tmp = f(lst);
		new->next = ft_lstnew(tmp->content, tmp->content_size);
		if (new->next == NULL)
			return (NULL);
		new = new->next;
		lst = lst->next;
	}
	return (first);
}
