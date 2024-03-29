#include <string.h>
#include <openssl/ssl.h>

#define DEBUG 0

BIO* bio_err = 0;

int password_cb(char *buf, int size, int rwflag, void *password) {
    strncpy(buf, (char *)(password), size);
    buf[size - 1] = '\0';
    return(strlen(buf));
}

/* Print SSL errors and exit*/ 
int berr_exit(char* string) {
    BIO_printf(bio_err,"%s\n",string); 
    ERR_print_errors(bio_err); 
    exit(0);
}

// Taken from Tutorial
SSL_CTX* initialize_ctx(char* keyfile, char* password, char* ca_list) {
    SSL_METHOD *meth;
    SSL_CTX *ctx;
    if(!bio_err){
        // Global system initialization
        // Initialize the whole OpenSSL Library 
        SSL_library_init();
        if (DEBUG) {printf("CALLED SSL_LIB_INIT\n"); fflush(stdout);}
        // Useful for reporting of errors
        SSL_load_error_strings();
        // An error write context
        bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    }
    // Set up a SIGPIPE handler
    //signal(SIGPIPE,sigpipe_handle);
    // Create our context
    meth=SSLv23_method();
    ctx=SSL_CTX_new(meth);
    // Load our keys and certificates
    if(!(SSL_CTX_use_certificate_chain_file(ctx, keyfile)))
        berr_exit("Can't read certificate file");
    SSL_CTX_set_default_passwd_cb(ctx, password_cb);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)password);
    if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM)))
        berr_exit("Can't read key file");
    // Load the CAs we trust
    if(!(SSL_CTX_load_verify_locations(ctx, ca_list, 0)))
        berr_exit("Can't read CA list");

    return ctx;
}
