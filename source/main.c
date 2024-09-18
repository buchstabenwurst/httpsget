/* client-tls.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <nds.h>
#include <filesystem.h>
#include <fat.h>
#include <dswifi9.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>

// #define HEAP_HINT NONE
// #define WOLFSSL_STATIC_MEMORY
// #define WOLFSSL_NO_MALLOC
#define WOLFSSL_HEAP_TEST

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define CERT_PREFIX "fat:/_nds/"
#define DEFAULT_PORT 443
// #define USE_TLSV13

#define CERT_DIR CERT_PREFIX "/certs"
// the certificate
// example #define CA_FILE CERT_PREFIX "/certs/Baltimore CyberTrust Root.crt"
#define CA_FILE CERT_PREFIX "/certs/example.crt"

int main(int argc, char** argv)
{
    int                sockfd;
    struct sockaddr_in servAddr;
    char               buff[4000];
    size_t             len;
    int                ret;
    const char * host = "www.example.com";

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx;
    WOLFSSL*     ssl;

    
    consoleDemoInit();
    fatInitDefault();
    nitroFSInit(NULL);
	if(!Wifi_InitDefault(WFC_CONNECT)) {
		iprintf("Failed to connect!");
        goto end;
	} else {
		iprintf("Connected\n\n");
    }
    printf("Hello World\n");


        // store the HTTP request for later
    char request_text[300] = 
        "Host: example.com\r\n"
        "User-agent: yes\r\n";


    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        ret = -1;
        goto end;
    }
    printf("Created socket\n");


    // Find the IP address of the server, with gethostbyname
    struct hostent * myhost = gethostbyname( host );
    iprintf("Found IP Address!:\n%s\n", myhost->h_name);
 

    // Tell the socket to connect to the IP address we found, on port 80 (HTTP)
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(DEFAULT_PORT);
    servAddr.sin_addr.s_addr= *( (unsigned long *)(myhost->h_addr_list[0]) );


    /* Connect to the server */
    // connect( sockfd,(struct sockaddr *)&servAddr, sizeof(servAddr));
    for(int i=0;i<10;i++){
        if ((ret = connect( sockfd,(struct sockaddr *)&servAddr, sizeof(servAddr) ))
            == -1) {
            fprintf(stderr, "WARNING: failed to connect, retrying.\n");
            sleep(1);
            continue;
        }else{
            break;
        }
        fprintf(stderr, "ERROR: failed to connect.\n");
        goto end;
    }

    /*---------------------------------*/
    /* Start of wolfSSL initialization and configuration */
    /*---------------------------------*/
    /* Initialize wolfSSL */
    if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        goto socket_cleanup;
    }

    /* Create and initialize WOLFSSL_CTX */
#ifdef USE_TLSV13
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
#else
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
#endif
    if (ctx == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        ret = -1;
        goto socket_cleanup;
    }

    /* Load CA certificate into WOLFSSL_CTX */
    
    if ((ret = wolfSSL_CTX_load_verify_locations(ctx, CA_FILE, NULL))
         != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                CA_FILE);
        goto ctx_cleanup;
    }

    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        // printf("%x",ssl);
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        ret = -1;
        goto ctx_cleanup;
    }

    /* Attach wolfSSL to the socket */
    if ((ret = wolfSSL_set_fd(ssl, sockfd)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        goto cleanup;
    }

    /* Connect to wolfSSL on the server side */
    if ((ret = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
        goto cleanup;
    }

    /* Get a message for the server from stdin */
    printf("Message for server: \n%s", request_text);
    // memset(buff, 0, sizeof(buff));
    // if (fgets(buff, sizeof(buff), stdin) == NULL) {
    //     fprintf(stderr, "ERROR: failed to get message for server\n");
    //     ret = -1;
    //     goto cleanup;
    // }
    len = strnlen(request_text, sizeof(request_text));

    /* Send the message to the server */
    if ((ret = wolfSSL_write(ssl, request_text, len)) != len) {
        fprintf(stderr, "ERROR: failed to write entire message\n");
        fprintf(stderr, "%d bytes of %d bytes were sent", ret, (int) len);
        goto cleanup;
    }

    /* Read the server data into our buff array */
    memset(buff, 0, sizeof(buff));
    if ((ret = wolfSSL_read(ssl, buff, sizeof(buff)-1)) == -1) {
        fprintf(stderr, "ERROR: failed to read\n");
        goto cleanup;
    }

    /* Print to stdout any data the server sends */
    printf("Server: %s\n", buff);

    /* Bidirectional shutdown */
    while (wolfSSL_shutdown(ssl) == WOLFSSL_SHUTDOWN_NOT_DONE) {
        printf("Shutdown not complete\n");
    }

    printf("Shutdown complete\n");

    ret = 0;

    /* Cleanup and return */
cleanup:
    wolfSSL_free(ssl);      /* Free the wolfSSL object                  */
ctx_cleanup:
    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
socket_cleanup:
    close(sockfd);          /* Close the connection to the server       */
end:
	while(1) {
		swiWaitForVBlank();
        int keys = keysDown();
        if(keys & KEY_START) break;
	}
    return ret;               /* Return reporting a success               */
}