#ifndef SERVICES_H
# define SERVICES_H

#define SERVICES_FILENAME "services"
#define DB_SERVICES DB_PATH SERVICES_FILENAME

struct service {
	char	*name;
	char	*desc;
	int		status;
};

/* services.c */
int		get_services(void);
void	free_services(void);

#endif
