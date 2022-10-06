/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lnicosia <lnicosia@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/14 11:05:31 by lnicosia          #+#    #+#             */
/*   Updated: 2022/10/06 10:44:11 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "get_next_line.h"
#include "libft.h"
#include <unistd.h>

int		lst_contains(t_list *lst, t_read **curr, int fd)
{
	while (lst != NULL)
	{
		*curr = (t_read*)(lst->content);
		if (*curr != NULL)
		{
			if ((*curr)->fd == fd)
				return (1);
		}
		lst = lst->next;
	}
	return (0);
}

int		contains_zero(char *buf, int size)
{
	int	i;

	i = 0;
	while (i < size)
	{
		if (buf[i] == 0)
			return (1);
		i++;
	}
	return (0);
}

int		set_line(t_read *curr, char **line)
{
	size_t	i;
	char	*tmp;

	i = 0;
	while ((curr->str[i] != NEWLINE) && (curr->str[i]))
		i++;
	if (!(*line = ft_strnew(i)))
		return (-1);
	ft_strncpy(*line, curr->str, i);
	*line = (char *)ft_rmchar(*line, '\r');
	if (i < ft_strlen(curr->str) - 1)
	{
		tmp = curr->str;
		if (!(curr->str = ft_strsub(curr->str, i + 1,
						ft_strlen(curr->str) - i - 1)))
			return (-1);
		ft_strdel(&tmp);
	}
	else
	{
		ft_strdel(&(curr->str));
		if (!(curr->str = ft_strnew(0)))
			return (-1);
	}
	return (0);
}

void	free_datas(t_list **datas)
{
	t_list *tmp = *datas;
	t_list *next;
	t_read *content;

	while (tmp) {
		next = tmp->next;
		if (tmp->content) {
			content = (t_read *)tmp->content;
			if (content->str)
				free(content->str);
			free(content);
		}
		free(tmp);
		tmp = next;
	}
	*datas = NULL;
}

int		set_data(t_list **datas, char **line, t_read *curr, int new)
{
	if (curr->str[0])
	{
		if (set_line(curr, line) == -1) {
			free_datas(datas);
			return (-1);
		}
		if (new == 0)
		{
			ft_lstadd(datas, ft_lstnew(curr, sizeof(*curr)));
			free(curr);
			curr = NULL;
		}
		return (1);
	}
	if (new == 0)
	{
		ft_lstadd(datas, ft_lstnew(curr, sizeof(*curr)));
		free(curr);
		curr = NULL;
	}
	free_datas(datas);
	return (0);
}

int		get_next_line(const int fd, char **line)
{
	static t_list	*datas = NULL;
	int				new;
	t_read			*curr;
	char			buff[BUFF_SIZE + 1];
	int				ret;

	ft_bzero(buff, sizeof(buff));
	if (fd < 0 || line == NULL || BUFF_SIZE == 0 || read(fd, buff, 0) < 0)
		return (-1);
	if ((new = lst_contains(datas, &curr, fd)) == 0)
	{
		if (!(curr = (t_read*)ft_memalloc(sizeof(*curr))))
			return (-1);
		if (!(curr->str = ft_strnew(0)))
			return (-1);
		curr->fd = fd;
	}
	while (!ft_strchr(curr->str, NEWLINE) && (ret = read(fd, buff, BUFF_SIZE))
		&& !contains_zero(buff, ret))
	{
		if (ret < 0 || !(curr->str = (char *)ft_strjoin_free(curr->str, buff)))
			return (-1);
		buff[ret] = '\0';
	}
	return (set_data(&datas, line, curr, new));
}
