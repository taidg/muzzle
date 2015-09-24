/*
 * Copyright (C) 2015 Bradley Tighe <bradtighe0@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <fcntl.h>
#include <getopt.h>
#include <termios.h>
#include <unistd.h>

#include <assert.h>
#include <stdio.h>

#include <gcrypt.h>

typedef unsigned char byte;

/* The name of this program. */
const char* program_name;

const int MAX_PASS_SIZE = 256;
const int IV_SIZE = 12;
const int TAG_SIZE = 16;

enum Mode {
  kNone = 0,
  kEncryption,
  kDecryption,
};

void printUsage(FILE* stream, int exit_code);
void getPass(char* pass);
void encrypt(char* password, FILE* input_filename, FILE* output_filename);
void decrypt(char* password, FILE* input_filename, FILE* output_filename);

int main(int argc, const char* argv[]) {
  // Check gcrypt library version
  // MUST BE CALLED BEFORE LIBRARY IS USED
  if (!gcry_check_version(GCRYPT_VERSION)) {
    fprintf(stderr, "[%s] libgcrypt version mismatch\n", program_name);
    exit(EXIT_FAILURE);
  }
  
  // Supress warnings until after Secure Memory Allocation
  gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);

  // Allocate a pool of 16k secure memory.
  gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);

  // Allow warnings about Secure Memory again
  gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);

  // Tell libgcrypt that initialization has completed
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);


  // The name of the file to recieve output or NULL for standard out
  const char* output_filename = NULL;
  // The name of the file to retrieve input or NULL for standard in
  const char* input_filename = NULL;

  // Password
  char* pass = NULL;

  // Encryption mode set, set by default, false implies DecryptionMode
  Mode mode = kNone;

  // Remember the name of the program to incorporate in messages.
  program_name = argv[0];

  // A string listing valid short options letters.
  const char* const short_options = "deho:p:";
  // An array describing long options.
  const struct option long_options[] = {
    { "decrypt",    0, NULL, 'd' },
    { "encrypt",    0, NULL, 'e' },
    { "output",     1, NULL, 'o' },
    { "password",   1, NULL, 'p' },
    { "help",       0, NULL, 'h' },
    { NULL,         0, NULL,  0  }
  };

  int next_option;
  do {
    next_option = getopt_long(argc, const_cast<char* const*>(argv),
                              short_options, long_options, NULL);
    switch (next_option) {
      case 'h': // -h or --help
        printUsage(stdout, EXIT_SUCCESS);

      case 'e': // -e or --encrypt
        mode = kEncryption;
        break;

      case 'd': // -d or --decrypt
        mode = kDecryption;
        break;

      case 'o': // -o or --output
        output_filename = optarg;
        break;

      case 'p': // -p or --password
        pass = optarg;
        break;

      case '?': // Invalid option
        printUsage(stderr, EXIT_FAILURE);

      case -1: // Done with options
        break;

      default: // Unexpected
        abort();
    }
  } while (next_option != -1);

  if (mode == kNone) {
      printUsage(stderr, EXIT_FAILURE);
  }

  if (optind < argc){
    input_filename = argv[optind];
  }

  // Set input stream
  FILE* inFile = NULL;
  if (input_filename == NULL) {
    inFile = stdin;
  } else {
    inFile = fopen(input_filename, "r");
  }
  assert(inFile != NULL);

  // Set output stream
  FILE* outFile = NULL;
  if (output_filename == NULL) {
    outFile = stdout;
  } else {
    outFile = fopen(output_filename, "w");
  }
  assert(outFile != NULL);

  // Set password if not set
  if (pass == NULL) {
    pass = new char[MAX_PASS_SIZE];
    getPass(pass);
  }
  assert(pass != NULL);

  switch (mode) {
    case kEncryption:
      encrypt(pass, inFile, outFile);
      break;
    case kDecryption: 
      decrypt(pass, inFile, outFile);
      break;
    default:
      break;
  }
}

void printUsage(FILE* stream, int exit_code) {
  fprintf(stream, "Usage: %s options [file]\n", program_name);
  fprintf(stream,
          "  -h  --help           give this help\n"
          "  -e  --encrypt        encrypt\n"
          "  -d  --decrypt        decrypt\n"
          "  -o  --output FILE    set output file\n"
          "  -p  --password PASS  set password\n");
  exit(exit_code);
}

void getPass(char *pass) {
  // Open terminal
  int tty = open("/dev/tty", O_RDWR | O_APPEND);
  if(tty == -1) {
    fprintf(stderr, "[%s] Could not open tty.", program_name);
    exit(EXIT_FAILURE);
  }

  // Retrieve terminal config
  struct termios tcOrig;
  tcgetattr(tty, &tcOrig);

  // Disable terminal echo, except for newline
  struct termios tcNoEcho;
  tcNoEcho = tcOrig;
  tcNoEcho.c_lflag |= ECHONL;
  tcNoEcho.c_lflag &= ~ECHO;
  tcsetattr(tty, TCSANOW, &tcNoEcho);

  // Get null-terminated password from terminal
  fprintf(stderr, "[%s] Password: ", program_name);
  int bytesRead = read(tty, pass, MAX_PASS_SIZE);
  assert(bytesRead > 0);
  pass[bytesRead - 1 ] = '\0';

  // Restore original terminal config
  tcsetattr(tty, TCSANOW, &tcOrig);
}

void encrypt(char* pass, FILE* input, FILE* output) {
  // Generate IV and write to standard out
  byte iv[IV_SIZE];
  gcry_create_nonce(iv, IV_SIZE);
  fwrite(reinterpret_cast<char*>(iv),1, IV_SIZE, output);

  // Create key by hashing IV and password
  int hashAlgo = GCRY_MD_SHA256;
  gcry_md_hd_t hashHandler;
  gcry_md_open(&hashHandler, hashAlgo, GCRY_MD_FLAG_SECURE);
  gcry_md_write(hashHandler, iv, IV_SIZE);
  gcry_md_write(hashHandler, pass, strlen(pass));
  byte* keygc = gcry_md_read(hashHandler, hashAlgo);

  // Wipe passphrase from memory
  memset(pass, 0, strlen(pass));

  int blockAlgo = GCRY_CIPHER_AES128;
  int blockMode = GCRY_CIPHER_MODE_GCM;
  int blockSize = gcry_cipher_get_algo_keylen(blockAlgo);
  gcry_cipher_hd_t encHandler;

  gcry_cipher_open(&encHandler, blockAlgo, blockMode, GCRY_CIPHER_SECURE);
  gcry_cipher_setkey(encHandler, keygc, blockSize);
  gcry_cipher_setiv(encHandler, iv, IV_SIZE);

  byte *buf = new byte[blockSize*16];
  byte *outbuf = new byte[blockSize*16];
  while (!feof(input)) {
    int bytesRead = fread(buf, 1, blockSize*16, input);
    gcry_cipher_encrypt(encHandler, outbuf, bytesRead, buf, bytesRead);
    fwrite(outbuf, 1, bytesRead, output);
  }
  gcry_cipher_gettag(encHandler, outbuf, TAG_SIZE);
  fwrite(outbuf, 1, TAG_SIZE, output);
}

void decrypt(char* pass, FILE* input, FILE* output) {
  // Retrieve IV from standard in
  byte iv[IV_SIZE];
  fread(iv, 1, IV_SIZE, input);

  // Create key by hashing IV and password
  int hashAlgo = GCRY_MD_SHA256;
  gcry_md_hd_t hashHandler;
  gcry_md_open(&hashHandler, hashAlgo, GCRY_MD_FLAG_SECURE);
  gcry_md_write(hashHandler, iv, IV_SIZE);
  gcry_md_write(hashHandler, pass, strlen(pass));
  byte* keygc = gcry_md_read(hashHandler, hashAlgo);

  // Wipe passphrase from memory
  memset(pass, 0, strlen(pass));

  // Decrypt standard in to standard out
  // Error if Authentication fails
  
  int blockAlgo = GCRY_CIPHER_AES128;
  int blockMode = GCRY_CIPHER_MODE_GCM;
  int blockSize = gcry_cipher_get_algo_keylen(blockAlgo);
  gcry_cipher_hd_t encHandler;

  gcry_cipher_open(&encHandler, blockAlgo, blockMode, GCRY_CIPHER_SECURE);
  gcry_cipher_setkey(encHandler, keygc, blockSize);
  gcry_cipher_setiv(encHandler, iv, IV_SIZE);

  byte *buf = new byte[blockSize*16 + TAG_SIZE];
  byte *bufHead = buf;
  byte *outbuf = new byte[blockSize*16];
  while (!feof(input)) {
    // read from input
    int bytesRead = fread(bufHead, 1, blockSize*16, input);
    
    // leave the last TAG_SIZE bytes at bufHead for tag
    // decrypt and output the rest
    bufHead += bytesRead - TAG_SIZE;
    if (bufHead < buf) {
      fprintf(stderr, "[%s] Insufficent data: Cannot decrypt.\n", program_name);
      exit(EXIT_FAILURE);
    }
    gcry_cipher_decrypt(encHandler, outbuf, bufHead - buf,
                        buf, bufHead - buf);
    fwrite(outbuf, 1, bufHead - buf, output);

    // copy bytes to front of buf
    memcpy(buf, bufHead, TAG_SIZE);

    // set bufHead to end of preserved data;
    bufHead = buf + TAG_SIZE;
  }

  gcry_cipher_gettag(encHandler, outbuf, TAG_SIZE);
  if (memcmp(buf, outbuf, TAG_SIZE)) {
      fprintf(stderr, "[%s] Data Verification Failed.", program_name);
  }
}

