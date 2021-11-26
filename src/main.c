#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

char *client_path = "/tmp/ss-client.socket";
/* https://www.cnblogs.com/sparkdev/p/8359028.html */

int main( argc, argv ) int argc; char *argv[]; {
	if ( argc < 2 )
	{
		printf( "usage: %s <socket_file> <parametric>\r\n", argv[0] );
		exit( 1 );
	}

	struct  sockaddr_un	cliun, serun;
	char			buf[1024];
	int			sockfd, len;


	/*
	 * SOCK_DGRAM #udp
	 * SOCK_STREAM #tcp
	 */
	if ( (sockfd = socket( AF_UNIX, SOCK_DGRAM, 0 ) ) < 0 )
	{
		perror( "opening stream socket" );
		exit( 1 );
	}

	/* 一般显式调用bind函数，以便服务器区分不同客户端 */
	memset( &cliun, 0, sizeof(cliun) );
	cliun.sun_family = AF_UNIX;
	strcpy( cliun.sun_path, client_path );
	len = offsetof( struct sockaddr_un, sun_path ) + strlen( cliun.sun_path );
	unlink( cliun.sun_path );
	if ( bind( sockfd, (struct sockaddr *) &cliun, len ) < 0 )
	{
		perror( "binding stream socket" );
		exit( 1 );
	}

	struct timeval tv;
	tv.tv_sec	= 1;
	tv.tv_usec	= 0;
	setsockopt( sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tv, sizeof tv );

	memset( &serun, 0, sizeof(serun) );
	serun.sun_family = AF_UNIX;
	strcpy( serun.sun_path, argv[1] );
	len = offsetof( struct sockaddr_un, sun_path ) + strlen( serun.sun_path );
	if ( connect( sockfd, (struct sockaddr *) &serun, len ) < 0 )
	{
		perror( "connecting stream socket" );
		exit( 1 );
	}

	if ( write( sockfd, argv[2], strlen( argv[2] ) ) < 0 )
	{
		perror( "writing on stream socket" );
		exit( 1 );
	}

	if ( read( sockfd, buf, 256 ) < 0 )
	{
		perror( "reading stream message" );
		exit( 1 );
	} else {
		printf( "%s", buf );
	}

	close( sockfd );
	unlink( cliun.sun_path );
	return(0);
}
