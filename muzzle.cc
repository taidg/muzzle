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
#include <iostream>

#include <crypto++/files.h>
#include <crypto++/gcm.h>
#include <crypto++/osrng.h>

using CryptoPP::AES;
using CryptoPP::ArraySink;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::FileSink;
using CryptoPP::FileSource;
using CryptoPP::GCM;
using CryptoPP::HashFilter;
using CryptoPP::HashVerificationFilter;
using CryptoPP::Redirector;
using CryptoPP::SHA256;
using CryptoPP::SecByteBlock;

/* The name of this program. */
const char* program_name;

const int MAX_PASS_SIZE = 256;
const int IV_SIZE = AES::BLOCKSIZE * 16;

void printUsage(FILE* stream, int exit_code);
void getPass(char *pass);
void encrypt(FILE* input_filename, FILE* output_filename);
void decrypt(FILE* input_filename, FILE* output_filename);

int main(int argc, const char* argv[]) {
  int next_option;

  // A string listing valid short options letters.
  const char* const short_options = "ehd";
  // An array describing long options.
  const struct option long_options[] = {
    { "help",    0, NULL, 'h' },
    { "encrypt", 0, NULL, 'e' },
    { "decrypt", 0, NULL, 'd' },
    { NULL,      0, NULL,  0  }
  };

  // The name of the file to recieve output or NULL for standard out
  const char* output_filename = NULL;
  // The name of the file to retrieve input or NULL for standard in
  const char* input_filename = NULL;

  // Encryption mode set, set by default, false implies DecryptionMode
  bool encryptMode = true;

  // Remember the name of the program to incorporate in messages.
  program_name = argv[0];

  do {
    next_option = getopt_long(argc, const_cast<char* const*>(argv),
                              short_options, long_options, NULL);
    switch (next_option) {
      case 'h': // -h or --help
        printUsage(stdout, EXIT_SUCCESS);

      case 'e': // -e or --encrypt
        encryptMode = true;
        break;

      case 'd': // -d or --decrypt
        encryptMode = false;
        break;

      case '?': // Invalid option
        printUsage(stderr, EXIT_FAILURE);

      case -1: // Done with options
        break;

      default: // Unexpected
        abort();
    }
  } while (next_option != -1);

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

  if (encryptMode) {
    encrypt(inFile, outFile);
  } else {
    decrypt(inFile, outFile);
  }
}

void printUsage(FILE* stream, int exit_code) {
  fprintf(stream, "Usage: %s options\n", program_name);
  fprintf(stream,
          "  -h  --help        give this help\n"
          "  -e  --encrypt     encrypt\n"
          "  -d  --decrypt     decrypt\n");
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

void encrypt(FILE* input, FILE* output) {
  char pass[MAX_PASS_SIZE];
  getPass(pass);

  // Generate IV and write to standard out
  AutoSeededRandomPool rng;
  byte iv[IV_SIZE];
  rng.GenerateBlock(iv, IV_SIZE);
  fwrite(reinterpret_cast<char*>(iv),1, IV_SIZE, output);

  // Create key by hashing IV and password
  SHA256 hash;
  SecByteBlock key(0x00, AES::DEFAULT_KEYLENGTH);
  HashFilter hf(hash, new ArraySink(key, AES::DEFAULT_KEYLENGTH));
  hf.Put(iv, IV_SIZE);
  hf.Put(reinterpret_cast<byte*>(pass), strlen(pass));
  hf.MessageEnd();

  // Wipe passphrase from memory
  memset(pass, 0, strlen(pass));

  // Pipe from standard in, encrypt, and pipe to standard out
  GCM<AES>::Encryption e;
  e.SetKeyWithIV(key, key.size(), iv, IV_SIZE);
  FileSource(
      std::cin, true,
      new AuthenticatedEncryptionFilter(e, new FileSink(std::cout), false, 12));
}

void decrypt(FILE* input_filename, FILE* output_filename) {
  char pass[MAX_PASS_SIZE];
  getPass(pass);

  // Retrieve IV from standard in
  byte iv[IV_SIZE];
  FileSource fs(std::cin, false, new ArraySink(iv, IV_SIZE));
  fs.Pump(IV_SIZE);

  // Create key by hashing IV and password
  SHA256 hash;
  SecByteBlock key(0x00, AES::DEFAULT_KEYLENGTH);
  HashFilter hf(hash, new ArraySink(key, AES::DEFAULT_KEYLENGTH));
  hf.Put(iv, IV_SIZE);
  hf.Put(reinterpret_cast<byte*>(pass), strlen(pass));
  hf.MessageEnd();

  // Wipe passphrase from memory
  memset(pass, 0, strlen(pass));

  // Decrypt standard in to standard out
  // Error if Authentication fails
  GCM<AES>::Decryption d;
  d.SetKeyWithIV(key, key.size(), iv, IV_SIZE);
  AuthenticatedDecryptionFilter adf(
      d, new FileSink(std::cout),
      AuthenticatedDecryptionFilter::MAC_AT_END, 12);
  FileSource(std::cin, true, new Redirector(adf));

  if (!adf.GetLastResult()) {
    fprintf(stderr, "[%s] Verification Failed.", program_name);
    exit(EXIT_FAILURE);
  }
}

