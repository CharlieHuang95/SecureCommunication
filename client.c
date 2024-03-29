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
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

#define CLIENT_KEYFILE "alice.pem"
#define CLIENT_PASSWORD "password"
#define CA_LIST "568ca.pem"

#define DEBUG 0

int berr_exit(char* string);
SSL_CTX *initialize_ctx (char *keyfile, char *cafile, char *password);

int check_cert(SSL* ssl) {
    X509 *peer;
    char peer_CN[256];
    char peer_email[256];
    char ca_issuer[256];

    if(SSL_get_verify_result(ssl)!=X509_V_OK)
        berr_exit(FMT_NO_VERIFY);
    /*Check the cert chain. The chain length
      is automatically checked by OpenSSL when
      we set the verify depth in the ctx */
    /*Check the common name*/
    peer=SSL_get_peer_certificate(ssl);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
                              NID_commonName, peer_CN, 256);
    if (strcasecmp(peer_CN, "Bob's Server"))
        berr_exit(FMT_CN_MISMATCH);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),
                              NID_pkcs9_emailAddress, peer_email, 256);
    if (strcasecmp(peer_email, "ece568bob@ecf.utoronto.ca"))
        berr_exit(FMT_EMAIL_MISMATCH);
    // Everything is correct. Get the CA issuer
    X509_NAME_get_text_by_NID(X509_get_issuer_name(peer),
                              NID_commonName, ca_issuer, 256);
    printf(FMT_SERVER_INFO, peer_CN, peer_email, ca_issuer);
    return 0;
}

void communicate_with_server(SSL* ssl, char* request_input) {
  char* request;
  char response[256];
  
  /* Send request to server */
  int request_len = strlen(request_input) + strlen(HOST) + 6;
  if (!(request=(char *)malloc(request_len)))
    berr_exit("Couldn't allocate request");
  sprintf(request, request_input, HOST, PORT);
  /* Find the exact request_len */
  request_len = strlen(request);
  int r = SSL_write(ssl, request, request_len);
  switch (SSL_get_error(ssl, r)){
    case SSL_ERROR_NONE:
        if (request_len!=r)
            berr_exit("Incomplete write!");
        break;
    case SSL_ERROR_ZERO_RETURN:
        if (DEBUG) printf("send req to server: going to shutdown\n");
        goto shutdown;
    case SSL_ERROR_SYSCALL:
        if (DEBUG) printf("send req to server: calling berr exit\n");
        berr_exit(FMT_INCORRECT_CLOSE);
        goto done;
    default:
        berr_exit("SSL write problem");
  }

    
    /* Receive request from server */
    while(1) {
        // Check the certificate maybe?
        int r = SSL_read(ssl, response, 256);
        switch (SSL_get_error(ssl, r)) {
            case SSL_ERROR_NONE:
                response[r] = '\0';
                printf(FMT_OUTPUT, "What's the question?", response);
                break;
            case SSL_ERROR_ZERO_RETURN:
                if (DEBUG) printf("receive req from server: going to shutdown\n");
                goto shutdown;
            case SSL_ERROR_SYSCALL:
                if (DEBUG) printf("receive req from server: calling berr exit\n");
                berr_exit(FMT_INCORRECT_CLOSE);
                goto done;
            default:
                berr_exit("Incorrect processing of request\n");
        }
    }
        
        shutdown:
            if (DEBUG) printf("Shutting down...\n");
            r = SSL_shutdown(ssl);
            switch(r) {
                case 1:
                    if (DEBUG) printf("shutdown: success\n");
                    break; /* Success */
                case 0:
                case -1:
                default:
                    if (DEBUG) printf("shutdown: calling berr exit\n");
                    berr_exit(FMT_INCORRECT_CLOSE);
            }
        
        done:
            SSL_free(ssl);
            return 0;
}

int main(int argc, char **argv) {
  int sock, port=PORT;
  char *host=HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char *secret = "What's the question?";

  SSL_CTX* context;
  BIO* sbio;
  SSL* ssl;

  context = initialize_ctx(CLIENT_KEYFILE, CLIENT_PASSWORD, CA_LIST);
  if (DEBUG) {printf("Initialized Context\n"); fflush(stdout);}
  /* USe SHA1 hash */
  SSL_CTX_set_cipher_list(context, "SHA1");
  if (DEBUG) {printf("Set cipher_list\n"); fflush(stdout);}
  /* Do not support SSLv2 */
  SSL_CTX_set_options(context, SSL_OP_NO_SSLv2);
  if (DEBUG) {printf("Set options\n"); fflush(stdout);}

  /*Parse command line arguments*/  
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
  
  /*get ip address of the host*/
  host_entry = gethostbyname(host);
  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");
  
  /* Connect the SSL socket */
  if (DEBUG) {printf("Opening SSL Socket\n"); fflush(stdout);}

  ssl = SSL_new(context);

  if (DEBUG) {printf("Created new SSL object\n"); fflush(stdout);}

  sbio = BIO_new_socket(sock, BIO_NOCLOSE);
  SSL_set_bio(ssl, sbio, sbio);
  if (DEBUG) {printf("Opened SSL Socket\n"); fflush(stdout);}

  if (SSL_connect(ssl) <= 0)
    berr_exit(FMT_CONNECT_ERR);

  // Check server's certificate 
  if (!check_cert(ssl)) {
    communicate_with_server(ssl, secret);
  }

  // TODO(charlie): remove after enabling SSL channel
  //send(sock, secret, strlen(secret),0);
  //len = recv(sock, &buf, 255, 0);
  //buf[len]='\0';
  
  // this is how you output something for the marker to pick up 
  //printf(FMT_OUTPUT, secret, buf);

  close(sock);
  return 1;
}
