# vlt

## Description

This is a simple text encryption tool.

It could to be make, edit and view encrypted text.

It is also use to launch shell with add vaulted env values.

## Usage

```bash
$ ./vlt init
Enter a passphrase for the new key: my-strong-password
Key generated and saved to private.key

$ ./vlt edit my-secret-vault-file
Enter passphrase for private key: my-strong-password
Secret file does not exist. Creating a new one.
(Edit the secret file in the editor specified in the EDITOR env.)
Secret file updated.

$ ./vlt decode ./my-secret-vault-file
Enter passphrase for private key: my-strong-password
Decoded content:
THIS_IS_ENV=test-env

$ ./vlt env ./my-secret-vault-file
Enter passphrase for private key: my-strong-password
(Shell launched with the environment variable set.)
$ export |grep ENV
declare -x THIS_IS_ENV="test-env"
$ exit
(Exit the shell with the environment variable added.)
```

## Build

- require: go lang.

```bash
$ make
$ ./vlt
<snip>
```


## LICENSE

Copyright 2024 uzulla(aka Junichi Ishida)<zishida@gmail.com>

Released under the MIT license

https://opensource.org/licenses/mit-license.php