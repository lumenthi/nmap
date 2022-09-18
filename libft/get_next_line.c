/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lumenthi <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/12/05 11:54:10 by lumenthi          #+#    #+#             */
/*   Updated: 2018/01/12 11:43:34 by lumenthi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "get_next_line.h"

static int		gnl_strcut(char **line)
{
	char	*cut;

	if (!(cut = ft_strchr(*line, '\n')))
		return (0);
	*line = cut + 1;
	return (1);
}

static int		gnl_get_line(char **line)
{
	char *cut;

	if (*line[0] == '\0')
		return (0);
	if ((cut = ft_strchr(*line, '\n')))
		*cut = '\0';
	return (1);
}

static int		gnl_read(int const fd, char **file)
{
	char	*buf;
	int		len;
	int		ret;

	if (!(buf = ft_strnew(BUFF_SIZE)))
		return (0);
	if (!(*file = ft_strnew(0)))
		return (0);
	while ((ret = read(fd, buf, BUFF_SIZE)))
	{
		if (ret < 0)
			return (0);
		buf[ret] = '\0';
		if (*file[0] == '\0')
			len = ft_strlen(buf) + 1;
		else
			len = ft_strlen(*file) + ft_strlen(buf) + 1;
		if (!(*file = (char*)ft_realloc(*file, len)))
			return (0);
		*file = ft_strcat(*file, buf);
	}
	free(buf);
	return (1);
}

int				get_next_line(int const fd, char **line)
{
	static char	*file[MAX_FD + 1];

	if (!(line) || fd < 0 || BUFF_SIZE < 1 || fd > MAX_FD)
		return (-1);
	*line = NULL;
	if (!(file[fd]))
	{
		if (!(gnl_read(fd, &file[fd])))
			return (-1);
	}
	else
	{
		if (ft_strcmp(file[fd], "") == 0)
		{
			if (!(gnl_read(fd, &file[fd])))
				return (-1);
		}
		else if (!gnl_strcut(&file[fd]))
			return (0);
	}
	if (!(*line = ft_strdup(file[fd])))
		return (-1);
	if (!(gnl_get_line(line)))
		return (0);
	return (1);
}
