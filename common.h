BIO *bio_err;

int password_cb(char *buf, int size, int rwflag, void *password);
int berr_exit(char* string);
SSL_CTX *initialize_ctx(char* keyfile, char* password);