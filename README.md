# muzzle
A command line data encryption tool designed for easy use with data compression tools.

muzzle uses AES encryption in GCM Block Mode to provide authenticated encryption of data.

## Building
Required libraries:
* crypto++

Run make.

## Usage
    muzzle [OPTION]
      -e, --encrypt    encrypt
      -d, --decrypt    decrypt
      -h, --help       show help

## Example
To encrypt a compress and encrypt a file using xz and muzzle run:

    cat myfile | xz --compress --stdout - | muzzle --encrypt > myfile.xz.muz

To decrypt and decompress a file run:

    cat myfile.xz.muz | muzzle --decrypt > myfile.plaintext
