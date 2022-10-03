/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   init_tpool.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: user42 <user42@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/15 20:54:27 by lnicosia          #+#    #+#             */
/*   Updated: 2020/05/23 20:33:03 by user42           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "tpool.h"
#include "libft.h"
#include <stdio.h>

int		init_tpool(t_tpool *tpool, int nb_threads)
{
	int	i;

	ft_bzero(tpool, sizeof(*tpool));
	pthread_mutex_init(&tpool->mutex, NULL);
	pthread_cond_init(&tpool->worker_cond, NULL);
	pthread_cond_init(&tpool->main_cond, NULL);
	tpool->nb_threads = nb_threads;
	if (!(tpool->threads = (pthread_t*)ft_memalloc(nb_threads
		* sizeof(pthread_t))))
	{
		fprintf(stderr, "Could not init threads array\n");
		return -1;
	}
	i = 0;
	while (i < nb_threads)
	{
		if (pthread_create(&tpool->threads[i], NULL, tpool_worker, tpool))
		{
			fprintf(stderr, "Could not create thread %d\n", i);
			return -1;
		}
		i++;
	}
	pthread_mutex_lock(&tpool->mutex);
	while (tpool->nb_alive_threads < tpool->nb_threads - 1)
		pthread_cond_wait(&tpool->main_cond, &tpool->mutex);
	pthread_mutex_unlock(&tpool->mutex);
	return (0);
}
