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

#include <iostream>

#include <unistd.h>
#include <termios.h>
#include <fcntl.h>

#include <crypto++/osrng.h>
#include <crypto++/gcm.h>
#include <crypto++/files.h>

using namespace CryptoPP;

const int MAX_PASS_SIZE = 256;
const int IV_SIZE = AES::BLOCKSIZE * 16;

void printUsage();
void getPass(char *pass);
void encryptStdIn();
void decryptStdIn();

int main(int argc, const char* argv[]) {
  if (argc < 2) {
    printUsage();
    return EXIT_FAILURE;
  }

  if (!strcmp(argv[1], "-e") || !strcmp(argv[1], "--encrypt")) {
    encryptStdIn();
  } else if (!strcmp(argv[1], "-d") || !strcmp(argv[1], "--decrypt")) {
    decryptStdIn();
  } else if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
    printUsage();
    return EXIT_SUCCESS;
  } else {
    printUsage();
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

void printUsage() {
  std::cout << "Usage: muzzle [OPTION]" <<std::endl
            << "  -e, --encrypt      encrypt" <<std::endl
            << "  -d, --decrypt      decrypt" <<std::endl
            << "  -h, --help         give this help" <<std::endl;
}

void getPass(char *pass) {
  // Open terminal
  int tty = open("/dev/tty", O_RDWR | O_APPEND);
  if(tty == -1) {
    std::cerr << "[muzzle] Could not open tty.";
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
  write(tty, "[muzzle] Password: ", 19);
  int bytesRead = read(tty, pass, MAX_PASS_SIZE);
  pass[bytesRead - 1 ] = '\0';

  // Restore original terminal config
  tcsetattr(tty, TCSANOW, &tcOrig);
}

void encryptStdIn() {
  char pass[MAX_PASS_SIZE];
  getPass(pass);

  // Generate IV and write to standard out
  AutoSeededRandomPool rng;
  byte iv[IV_SIZE];
  rng.GenerateBlock(iv, IV_SIZE);
  std::cout.write((char *)iv, IV_SIZE);

  // Create key by hashing IV and password
  SHA256 hash;
  SecByteBlock key(0x00, AES::DEFAULT_KEYLENGTH);
  HashFilter hf(hash, new ArraySink(key, AES::DEFAULT_KEYLENGTH));  
  hf.Put(iv, IV_SIZE);
  hf.Put((byte *)pass, strlen(pass));
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

void decryptStdIn() {
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
  hf.Put((byte *)pass, strlen(pass));
  hf.MessageEnd();

  // Wipe passphrase from memory
  memset(pass, 0, strlen(pass));

  // Decrypt standard in to standard out
  // Error if Authentication fails
  GCM<AES>::Decryption d;
  d.SetKeyWithIV(key, key.size(), iv, IV_SIZE);
  try {
    FileSource(std::cin, true,
        new AuthenticatedDecryptionFilter(
            d, new FileSink(std::cout),
            AuthenticatedDecryptionFilter::DEFAULT_FLAGS, 12));
  }
  catch (HashVerificationFilter::HashVerificationFailed er) {
    std::cerr << "[muzzle] Verification Failed.";
    exit(EXIT_FAILURE);
  }
}

