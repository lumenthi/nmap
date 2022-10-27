#include "nmap.h"

static void		print_art(char *path)
{
	int fd = open(path, O_RDONLY);
	char *buf;

	if (fd == -1)
		return;

	while (get_next_line(fd, &buf) > 0) {
		printf("%s\n", buf);
		free(buf);
	}

	close(fd);
}

void		print_version(void)
{
	printf("lumenthi and lnicosia's ft_nmap version 1.0 (https://github.com/lumenthi/nmap)\n"
		"This program is free software; you may redistribute it\n"
		"This program has absolutely no warranty\n"
	);
}

void		print_usage(FILE* f)
{
	fprintf(f,
		"USAGE:\n"
		"  ft_nmap [Target(s)] [Options]\n"
	);
}

static void		target_specification()
{
	printf("TARGET SPECIFICATION:\n"
		"  Can pass IPv4 hostnames, networks and IP addresses\n"
		"    Exemple: scanme.org; localhost; 127.0.0.1, 192.168.1/24\n"
		"  -f --file <inputfilename>: Read IPs from a file (must be a .ip file)\n"
		"    Exemple of a file:\n"
		"      $ cat list.ip\n"
		"      localhost\n"
		"      scanme.org\n"
	);
}

static void		scan_techniques()
{
	printf("SCAN TECHNIQUES:\n"
		"  Can specify a single or multiple scan technique(s) -s --scan <type(s)>\n"
		"  Note that the program will run all types of scan if none are specified\n"
		"    Exemple: -s SYN,UDP,FIN; --scan=XMAS,TCP\n"
		"  TCP SCANS:\n"
		"    SYN: SYN scan, requires root privileges\n"
		"    NULL: Null scan, requires root privileges\n"
		"    FIN: FIN scan, requires root privileges\n"
		"    XMAS: Xmas scan, requires root privileges\n"
		"    ACK: ACK scan, requires root privileges\n"
		"    TCP: Connect scan, doesnt not require root privileges\n"
		"  UDP SCANS:\n"
		"    UDP: UDP scan, requires root privileges\n"
	);
}

static void port_specification()
{
	printf("PORT SPECIFICATION:\n"
		"  -p --port <port ranges>: Only scan specified ports\n"
		"  Note that the program will scan from port 1 to port 1024 if none are specified\n"
		"    Exemple: -p 22; -p 1-65535; --port=1,25,4242,3\n"
	);
}

static void service_detection()
{
	printf("SERVICE_DETECTION:\n"
		"  -D --description: Print a description for the service running on the targeted port\n"
		"  Note that by default, ft_nmap only print the name of the service running under the targeted port\n"
	);
}

static void multithreading()
{
	printf("MULTITHREADING:\n"
		"  -t --thread <number of threads>:  To speedup the process, ft_nmap can be executed with multiple threads\n"
		"  By default, the program will run with no threads\n"
		"  Note that the thread number cannot exceed 250\n"
		"    Exemple: -t 5; --thread 250\n"
	);
}

static void verbose()
{
	printf("VERBOSE:\n"
		"  -v --verbose <verbose level>: Specify a verbose level between INFO, DEBUG and PACKET\n"
		"  INFO displays simple informations about what ft_nmap is doing\n"
		"  DEBUG goes deeper and displays more informations\n"
		"  PACKET is as deep as the DEBUG level but the contents of sent/received packets are also displayed\n"
		"  Note that verbose messages are printed on STDERR so you can redirect the output easily for analysis\n"
		"    Exemple: ./ft_nmap localhost -v DEBUG 2>log.txt\n"
	);
}

static void misc()
{
	printf("MISC:\n"
		"  -d --delay: Specify a delay between each packet that are sent by ft_nmap\n"
		"    By default, ft_nmap send packets as fast as possible\n"
		"  --no-progress: Hide the progress bar while scanning, this may result in a performance gain\n"
		"  --ascii: Edit the output of ft_nmap to match terminals that doesnt handle 256 colors\n"
		"  -h --help: Display the help menu\n"
		"  -V --version: Output the current version of this software\n"
	);
}

static void ressources()
{
	printf("RESSOURCES MANAGEMENT:\n"
		"  Before each execution, ft_nmap will check if your hardware can handle the command\n"
		"  Multithreading on a large amount of IPs is not ressources free\n"
		"  If the operation won't be supported by your hardware, ft_nmap will print an error message and exit\n"
	);
}

static void examples()
{
	printf("EXAMPLES:\n"
		"  sudo ./ft_nmap scanme.org -p 1-4242 -t 250\n"
		"  ./ft_nmap 127.0.0.1 -s TCP\n"
		"  sudo ./ft_nmap localhost --scan=FIN,SYN\n"
		"  sudo ./ft_nmap scanme.org localhost --verbose=INFO -t 50 2>log.txt\n"
		"  ./ft_nmap localhost -p 22,25,4242 -s TCP\n"
		"  sudo ./ft_nmap --file=list.ip -s SYN,FIN,NULL,UDP -v PACKET\n"
	);
}

static void discovery()
{
	printf("HOST DISCOVERY:\n"
		"  For each host given in parameter, ft_nmap will perform a recon operation\n"
		"  This proccess allow ft_nmap to determine whether a host is up or down\n"
		"  Dynamic timeout is also calculated by the discovery process\n"
		"  --no-discovery: Treat all hosts as online, skip host discovery\n"
	);
}

static void timeout_payloads()
{
	printf("TIMEOUTS AND PAYLOADS:\n"
		"  Custom payloads:\n"
		"    For some scans ft_nmap might need to send customs payloads depending on the service detected\n"
		"    Theses payloads allows a better accuracy since they give us a better response rate\n"
		"  Dynamic timeout:\n"
		"    Each IP has a specific timeout determined by the host discovery process\n"
		"    So each scans know how many time to wait until they mark a port as FILTERED\n"
	);
}

void		print_help()
{
	/* Header with ascii art and usage */
	print_art(DB_ASCII);
	print_usage(stdout);
	printf("\n");

	/* Content */
	target_specification();
	discovery();
	scan_techniques();
	timeout_payloads();
	port_specification();
	service_detection();
	multithreading();
	verbose();
	ressources();
	misc();
	examples();

	/* Footer with version */
	printf("\n");
	print_version();
	printf("\n");
}
