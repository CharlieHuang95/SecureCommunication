#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <string.h>

#define HOST "localhost"
#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

#define SERVER_KEYFILE "bob.pem"
#define SERVER_PASSWORD "password"
#define CA_LIST "568ca.pem"

#define DEBUG 0

int berr_exit(char* string);
SSL_CTX *initialize_ctx (char *keyfile, char *cafile, char *password);

int check_cert(SSL* ssl) {
    X509 *peer;
    char peer_CN[256];
    char peer_email[256];

    if(SSL_get_verify_result(ssl)!=X509_V_OK) {
        printf(FMT_ACCEPT_ERR);
        ERR_print_errors();
        berr_exit("");
    }
    peer=SSL_get_peer_certificate(ssl);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
                              NID_commonName, peer_CN, 256);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
                              NID_pkcs9_emailAddress, peer_email, 256);

    /*Check the cert chain. The chain length
      is automatically checked by OpenSSL when
      we set the verify depth in the ctx */
    /*Check the common name*/
    printf(FMT_CLIENT_INFO, peer_CN, peer_email);
    return 0;
}

void http_serve(SSL* ssl, int s, char* answer) {
    char request[256];
    
    // Check the certificate maybe?
    int r = SSL_read(ssl, request, 256);
    switch (SSL_get_error(ssl, r)) {
        case SSL_ERROR_NONE:
            break;
        case SSL_ERROR_ZERO_RETURN:
            goto shutdown;
        case SSL_ERROR_SYSCALL:
            berr_exit(FMT_INCOMPLETE_CLOSE);
            goto done;
        default:
            berr_exit("Incorrect processing of request\n");
    }
    request[r] = '\0';
    printf(FMT_OUTPUT, request, answer);
    
    char response_buf[256];
    sprintf(response_buf, answer);
    char* response;
    int response_len = strlen(response_buf) + strlen(HOST) + 6;
    if (!(response=(char *)malloc(response_len)))
        berr_exit("Couldn't allocate request");
    sprintf(response, response_buf);
    /* Find the exact request_len */
    response_len = strlen(response);
    
    
    r = SSL_write(ssl, response, response_len);
    switch (SSL_get_error(ssl, r)){
        case SSL_ERROR_NONE:
            if (response_len!=r)
                berr_exit("Incomplete write!");
            break;
        case SSL_ERROR_ZERO_RETURN:
            goto shutdown;
        case SSL_ERROR_SYSCALL:
            berr_exit(FMT_INCOMPLETE_CLOSE);
            goto done;
        default:
            berr_exit("SSL write problem");
    }
    
    shutdown:
        r=SSL_shutdown(ssl);
        if(!r){
          /* If we called SSL_shutdown() first then
             we always get return value of '0'. In
             this case, try again, but first send a
             TCP FIN to trigger the other side's
             close_notify*/
            shutdown(s,1);
            r=SSL_shutdown(ssl);
        }
        switch(r){
          case 1:
            if (DEBUG) printf("successful shut down\n");
            break; /* Success */
          case 0:
          case -1:
          default:
            berr_exit(FMT_INCOMPLETE_CLOSE);
        }
    done:
        SSL_free(ssl);
        return 0;
}

int main(int argc, char **argv)
{
  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  
  SSL* ssl;
  BIO* sbio;
  pid_t pid;
  SSL_CTX* context;
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }
  context = initialize_ctx(SERVER_KEYFILE, SERVER_PASSWORD, CA_LIST);
  if (DEBUG) {printf("Initialized context\n"); fflush(stdout);}

  // Only communicate with SSLv3 or TLSv1
  SSL_CTX_set_cipher_list(context, "SSLv2:SSLv3:TLSv1");
  if (DEBUG) {printf("Set cipher list\n"); fflush(stdout);}
  SSL_CTX_set_verify(context,SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
  if (DEBUG) {printf("Set verify\n"); fflush(stdout);}

  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  } 
  
  while(1){
    
    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }
    
    /*fork a child to handle the connection*/
    
    if((pid=fork())){
      close(s);
    } else {
      sbio = BIO_new_socket(s, BIO_NOCLOSE);
      ssl =  SSL_new(context);
      SSL_set_bio(ssl, sbio, sbio);
      if ((SSL_accept(ssl) <= 0))
        berr_exit(FMT_ACCEPT_ERR);
      /*Child code*/
      check_cert(ssl);
      char *answer = "42";
      http_serve(ssl, s, answer);
      close(sock);
      close(s);
      return 0;
    }
  }
  
  close(sock);
  return 1;
}
