# muzzle
A Linux command line data encryption tool designed for easy use with data compression tools.

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

    xz --compress - < myfile | muzzle --encrypt > myfile.xz.muz

To decrypt and decompress a file run:

    muzzle --decrypt myfile.xz.muz | xz --decompress - > myfile

To create an encrypted and compressed tarball use:

    tar cJ [files ...] | muzzle -e > myfiles.tar.xz.muz

And to decrypt and decompress use:

    muzzle -d < myfiles.tar.xz.muz | tar xJ
