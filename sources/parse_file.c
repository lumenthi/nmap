#include "options.h"
#include "libft.h"
#include "nmap.h"

static void	push_ipset(t_ipset **head, t_ipset *new)
{
	t_ipset *tmp = *head;

	if (*head == NULL)
		*head = new;
	else {
		while (tmp->next != NULL)
			tmp = tmp->next;
		tmp->next = new;
	}
}

void	free_ipset(t_ipset **ipset)
{
	t_ipset *current = *ipset;
	t_ipset *next;

	while (current != NULL) {
		next = current->next;
		if (current->string)
			free(current->string);
		free(current);
		current = next;
	}

	*ipset = NULL;
}

static void add_ipset(t_ipset **head, char *ip_string)
{
	t_ipset *tmp = malloc(sizeof(t_ipset));

	if (!tmp)
		return;

	ft_bzero(tmp, sizeof(t_ipset));
	tmp->string = ip_string;
	push_ipset(head, tmp);
}

static int is_empty(char *str)
{
	int i = 0;

	while (str[i]) {
		if (ft_isalnum(str[i]))
			return 0;
		i++;
	}
	return 1;
}

static int valid_extension(char *string, const char *extension)
{
	char *stringext = ft_strrchr(string, '.');

	if (stringext)
		return ft_strcmp(stringext, extension) == 0 ? 1 : 0;
	return 0;
}

int parse_file(char *path, t_ipset **head)
{
	int fd;
	int ret;
	char *ip = NULL;

	if (!valid_extension(path, EXTENSION))
		return FILE_EXTENSION;
	fd = open(path, O_RDONLY);
	if (fd == -1)
		return FILE_INVALID;

	while ((ret = get_next_line(fd, &ip)) != 0) {
		if (ret == -1) {
			close(fd);
			return FILE_INVALID;
		}
		else {
			if (!is_empty(ip))
				add_ipset(head, ip);
			else
				free(ip);
		}
	}

	close(fd);
	return FILE_VALID;
}
