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

#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

#define SERVER_KEYFILE "bob.pem"
#define SERVER_PASSWORD "passwoerd"
#define CA_LIST "568ca.pem"
BIO *bio_err = 0;
static char *pass;

int password_cb(char *buf, int size, int rwflag, void *password)
 {
  strncpy(buf, (char *)(password), size);
  buf[size - 1] = '\0';
  return(strlen(buf));
 }

/* Print SSL errors and exit*/ 
int berr_exit(string) 
  char *string; 
  {

    BIO_printf(bio_err,"%s\n",string); 
    ERR_print_errors(bio_err); 
    exit(0);
  }

// Taken from Tutorial
SSL_CTX *initialize_ctx(keyfile,password)
  char *keyfile;
  char *password;
  {
    SSL_METHOD *meth;
    SSL_CTX *ctx;
    if(!bio_err){
      /* Global system initialization*/
      // Initialize the whole OpenSSL Library 
      SSL_library_init();
      // Useful for reporting of errors
      SSL_load_error_strings();
      /* An error write context */
      bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    }
    /* Set up a SIGPIPE handler */
    //signal(SIGPIPE,sigpipe_handle);
    /* Create our context*/
    meth=SSLv23_method();
    ctx=SSL_CTX_new(meth);
    /* Load our keys and certificates*/
    if(!(SSL_CTX_use_certificate_chain_file(ctx, keyfile)))
      berr_exit("Can't read certificate file");
    pass=password;
    SSL_CTX_set_default_passwd_cb(ctx, password_cb);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, password);
    if(!(SSL_CTX_use_PrivateKey_file(ctx,
      keyfile,SSL_FILETYPE_PEM)))
      berr_exit("Can't read key file");
    /* Load the CAs we trust*/
    if(!(SSL_CTX_load_verify_locations(ctx, CA_LIST,0)))
       berr_exit("Can't read CA list");
#if (OPENSSL_VERSION_NUMBER < 0x0090600fL)
    SSL_CTX_set_verify_depth(ctx, 1);
#endif
    return ctx;
  }

int main(int argc, char **argv)
{
  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
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
  context = initialize_ctx(SERVER_KEYFILE, SERVER_PASSWORD);
  
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
    }
    else {
      /*Child code*/
      int len;
      char buf[256];
      char *answer = "42";

      len = recv(s, &buf, 255, 0);
      buf[len]= '\0';
      printf(FMT_OUTPUT, buf, answer);
      send(s, answer, strlen(answer), 0);
      close(sock);
      close(s);
      return 0;
    }
  }
  
  close(sock);
  return 1;
}
