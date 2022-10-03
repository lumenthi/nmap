/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread_pool_job.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: user42 <user42@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/15 20:54:27 by lnicosia          #+#    #+#             */
/*   Updated: 2020/05/23 20:33:03 by user42           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "tpool.h"
#include "libft.h"
#include <stdlib.h>

/*
**	Creates a new job and adds it to the list
*/

t_job	*create_job(int (*func)(void*), void *param)
{
	t_job	*new;

	if (!func)
		return (0);
	if (!(new = (t_job*)ft_memalloc(sizeof(t_job))))
		return (0);
	new->func = func;
	new->param = param;
	new->next = NULL;
	return (new);
}

/*
**	Free a given job
*/

void	destroy_job(t_job *job)
{
	if (!job)
		return ;
	free(job);
	job = NULL;
}

/*
**	Returns the first job from the list to execute it in an avaible thread
**	When the jobs list is emply, signals the main thread that every job
**	was recovered by the threads
*/

t_job	*get_job(t_tpool *tpool)
{
	t_job	*job;

	if (!tpool || !tpool->jobs)
		return (0);
	job = tpool->jobs;
	tpool->jobs = tpool->jobs->next;
	if (!tpool->jobs)
		pthread_cond_signal(&tpool->main_cond);
	return (job);
}
