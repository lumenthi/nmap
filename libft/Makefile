# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: lumenthi <lumenthi@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2018/01/04 10:37:11 by lumenthi          #+#    #+#              #
#    Updated: 2022/08/20 09:35:37 by lumenthi         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

.PHONY: all clean fclean re

CC = gcc
FLAGS = -Werror -Wall -Wextra -fPIC

NAME = libft.a

GREEN = '\033[4;32m'
YELLOW = '\033[4;33m'
BLANK = '\033[0m'
RED = '\033[4;31m'

TICK = '\033[1;32m~\033[0m'
CROSS = '\033[1;31mx\033[0m'

INCLUDES = libft.h

SRCS = ft_atoi.c \
		ft_bzero.c \
		ft_isalnum.c \
		ft_isalpha.c \
		ft_isascii.c \
		ft_isdigit.c \
		ft_isprint.c \
		ft_itoa.c \
		ft_memalloc.c \
		ft_memccpy.c \
		ft_memchr.c \
		ft_memcmp.c \
		ft_memcpy.c \
		ft_memdel.c \
		ft_memmove.c \
		ft_memset.c \
		ft_putchar.c \
		ft_putchar_fd.c \
		ft_putendl.c \
		ft_putendl_fd.c \
		ft_putnbr.c \
		ft_putnbr_fd.c \
		ft_putstr.c \
		ft_putstr_fd.c \
		ft_strcat.c \
		ft_strchr.c \
		ft_strclr.c \
		ft_strcpy.c \
		ft_strdel.c \
		ft_strdup.c \
		ft_strequ.c \
		ft_striter.c \
		ft_striteri.c \
		ft_strjoin.c \
		ft_strlcat.c \
		ft_strlen.c \
		ft_strmap.c \
		ft_strmapi.c \
		ft_strncat.c \
		ft_strncpy.c \
		ft_strnequ.c \
		ft_strnew.c \
		ft_strnstr.c \
		ft_strrchr.c \
		ft_strsplit.c \
		ft_strstr.c \
		ft_strsub.c \
		ft_strtrim.c \
		ft_tolower.c \
		ft_toupper.c \
		ft_strcmp.c \
		ft_strncmp.c \
		ft_lstnew.c \
		ft_lstdelone.c \
		ft_lstdel.c \
		ft_lstadd.c \
		ft_lstpush.c \
		ft_lstiter.c \
		ft_lstmap.c \
		ft_power.c \
		ft_count_words.c \
		ft_sqrt.c \
		ft_intlen.c \
		ft_isspace.c \
		ft_realloc.c \
		ft_strchr_index.c \
		ft_strswap.c \
		get_next_line.c \
		ft_charjoin.c \
		ft_delete.c \
		ft_printtab.c \
		ft_isprintable.c \
		ft_strjoinl.c \
		ft_putaddress.c \
		ft_exit.c \
		ft_puthex.c \
		ft_strisnum.c

OBJDIR = objs
OBJS = $(addprefix $(OBJDIR)/, $(SRCS:.c=.o))

all: $(NAME)

$(OBJDIR)/%.o: %.c
	@ mkdir -p $(OBJDIR)
	@ $(CC) -c $(FLAGS) -o $@ $<

$(NAME): $(OBJS)
	@ ar rc $(NAME) $(OBJS)
	@ ranlib $(NAME)
	@ printf " %b | Compiled %blibft%b\n" $(TICK) $(GREEN) $(BLANK)

clean:
	@ test -d $(OBJDIR) && \
	rm -rf $(OBJDIR) && \
	printf " %b | " $(TICK) && \
	printf "Removed %blibft%b object folder\n" $(YELLOW) $(BLANK) \
	|| (printf " %b | " $(CROSS) && \
	printf "No %blibft%b object folder\n" $(YELLOW) $(BLANK))

fclean: clean
	@ test -f $(NAME) && \
	rm -rf $(NAME) && \
	printf " %b | " $(TICK) && \
	printf "Removed %blibft%b library\n" $(RED) $(BLANK) \
	|| (printf " %b | " $(CROSS) && \
	printf "No %blibft%b library\n" $(RED) $(BLANK))

re: fclean all
