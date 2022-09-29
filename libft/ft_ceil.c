double	ft_ceil(double nb)
{
	if (nb > (long long int)nb)
		return (double)((long long int)nb + 1);
	return nb;
}		
