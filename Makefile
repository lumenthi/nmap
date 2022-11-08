# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: lumenthi <lumenthi@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2017/12/22 14:06:43 by lumenthi          #+#    #+#              #
#    Updated: 2022/10/25 09:58:45 by lumenthi         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = ft_nmap
SERVER_NAME = ft_server

CC = gcc
FLAGS = -Wall -Werror -Wextra -O3 -flto
LDFLAGS = -lpthread -lm

GREEN = '\033[4;32m'
RED = '\033[4;31m'
BLANK = '\033[0m'
YELLOW = '\033[4;33m'
CYAN = '\033[4;38;5;51m'
WARNING = '\033[1;33m'
RESET = '\033[0m'
COMPILE_COLOR = '\033[0;33m'

TICK = '\033[1;32m~\033[0m'
CROSS = '\033[1;31mx\033[0m'

###### FOLDERS ######

LIBDIR = libft
SRCDIR = sources
HEADDIR = headers
OBJDIR = objs

#####################

###### DATABASE #####

SRC_DB = database
DST_DB = /tmp/ft_nmap

#####################

###### LIBRARY ######

LIBFT = $(LIBDIR)/libft.a

#####################

###### HEADERS ######

HEADS = nmap.h options.h set.h colors.h
HEADERS = $(addprefix $(HEADDIR)/, $(HEADS))

#####################

###### SOURCES ######

SERVER_SRCS = server.c \
				checksum.c \
				addr_config.c

SRCS = main.c \
		nmap.c \
		parse_option_line.c \
		free_and_exit.c \
		list.c \
		payload.c \
		checksum.c \
		addr_config.c \
		print.c \
		help.c \
		parse_file.c \
		craft_packet.c \
		services.c \
		timedout.c \
		udp_scan.c \
		syn_scan.c \
		null_scan.c \
		xmas_scan.c \
		fin_scan.c \
		ack_scan.c \
		tcp_scan.c \
		host_discovery.c

SERVER_SOURCES = $(addprefix $(SRCDIR)/, $(SERVER_SRCS))
SOURCES = $(addprefix $(SRCDIR)/, $(SRCS))

#####################

###### OBJECTS ######

SERVER_OBJS = $(addprefix $(OBJDIR)/, $(SERVER_SRCS:.c=.o))
OBJS = $(addprefix $(OBJDIR)/, $(SRCS:.c=.o))

#####################

###### DEPENDENCIES ######

SERVER_DEP = $(SERVER_OBJS:.o=.d)
DEP = $(OBJS:.o=.d)

#####################

TODOS=$(shell grep -nr "TODO" $(SRCDIR) $(HEADDIR) | wc -l)

SHOULD_COUNT=1
FILES_TO_COMPILE = 0
ifeq ($(SHOULD_COUNT), 1)
	FILES_TO_COMPILE:=$(shell make -n SHOULD_COUNT=0 | grep "gcc -c" | wc -l)
endif

all:
	@ $(MAKE) -s -C $(LIBDIR)
	@ $(MAKE) --no-print-directory server $(NAME)

###### BINARY COMPILATION ######

$(NAME): $(LIBFT) $(OBJS) ${HEADERS} $(DST_DB)
	@ printf "[Linking] "
	$(CC) $(OBJS) -o $(NAME) $(LIBFT) $(LDFLAGS)
	@ printf " %b | Compiled %b%b%b\n" $(TICK) $(GREEN) $(NAME) $(BLANK)
	@ if [ $(TODOS) -gt 0 ]; then\
		printf "%b[WARNING]%b You have %d TODOs pending, run make todo to check them.\n"\
			$(WARNING) $(BLANK) $(TODOS);\
	fi

###############################

$(SERVER_NAME): $(LIBFT) $(SERVER_OBJS) ${HEADERS}
	@ printf "[Linking] "
	$(CC) $(SERVER_OBJS) -o $(SERVER_NAME) $(LIBFT)
	@ printf " %b | Compiled %b%b%b\n" $(TICK) $(GREEN) $(SERVER_NAME) $(BLANK)

$(DST_DB):
	@ printf "[Installing] Creating database...\n"
	@ cp -r $(SRC_DB) $(DST_DB)
	@ printf "[Installing] Done creating database !\n"

$(LIBFT):
	 @ $(MAKE) -s -C $(LIBDIR)

-include $(DEP)

I = 1
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@ mkdir -p $(OBJDIR)
	@ printf "[$(I)/$(FILES_TO_COMPILE)] "
	$(CC) -c -MMD -MF $(patsubst %.o,%.d,$@) $(FLAGS) -I$(HEADDIR) -I$(LIBDIR) -o $@ $<
	$(eval I=$(shell echo $$(($(I) + 1))))

$(DEPDIR)/%.d: $(SRCDIR)/%.c
	@ mkdir -p $(DEPDIR)
	$(CC) -c -MMD $(FLAGS) -I$(HEADDIR) -I$(LIBDIR) -o $@ $<

clean:
	@ $(MAKE) -s -C $(LIBDIR) clean
	@ test -d $(OBJDIR) && \
	rm -rf $(OBJDIR) && \
	printf " %b | " $(TICK) && \
	printf "Removed %bobjects%b folders\n" $(YELLOW) $(BLANK) \
	|| (printf " %b | " $(CROSS) && \
	printf "No %bobjects%b folders\n" $(YELLOW) $(BLANK))

fclean: clean
	@ test -d $(DST_DB) && \
	rm -rf $(DST_DB) && \
	printf " %b | " $(TICK) && \
	printf "Removed %bdatabase%b folder\n" $(YELLOW) $(BLANK) \
	|| (printf " %b | " $(CROSS) && \
	printf "No %bdatabase%b folder\n" $(YELLOW) $(BLANK))
	@ test -f $(LIBFT) && \
	rm -rf $(LIBFT) && \
	printf " %b | " $(TICK) && \
	printf "Removed %blibft%b library\n" $(RED) $(BLANK) \
	|| (printf " %b | " $(CROSS) && \
	printf "No %blibft%b library\n" $(RED) $(BLANK))
	@ test -f $(NAME) && \
	rm -rf $(NAME) && \
	printf " %b | " $(TICK) && \
	printf "Removed %b%b%b binary\n" $(RED) $(NAME) $(BLANK) \
	|| (printf " %b | " $(CROSS) && \
	printf "No %b%b%b binary\n" $(RED) $(NAME) $(BLANK))
	@ test -f $(SERVER_NAME) && \
	rm -rf $(SERVER_NAME) && \
	printf " %b | " $(TICK) && \
	printf "Removed %b%b%b binary\n" $(RED) $(SERVER_NAME) $(BLANK) \
	|| (printf " %b | " $(CROSS) && \
	printf "No %b%b%b binary\n" $(RED) $(SERVER_NAME) $(BLANK))

re: fclean # Make -j support
	@ $(MAKE) all

todo:
	@ printf "%b" $(WARNING)
	@ grep -nr "TODO" $(SRCDIR) $(HEADDIR) || true
	@ printf "%b" $(BLANK)

server: $(SERVER_NAME)

.PHONY: all clean fclean re todo
