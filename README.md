
# SimpleSecrets [![Build Status](https://travis-ci.org/timshadel/simple-secrets.rb.png?branch=master)](https://travis-ci.org/timshadel/simple-secrets.rb)

A Ruby client for [simple-secrets][simple-secrets], the simple, opinionated library for encrypting small packets of data securely.

[simple-secrets]: https://github.com/timshadel/simple-secrets

## Examples

### Basic

Send:

```ruby
require('simple-secrets')

# Try `head /dev/urandom | shasum -a 256` to make a decent 256-bit key
master_key = new Buffer('<64-char hex string (32 bytes, 256 bits)>', 'hex');
# => <Buffer 71 c8 67 56 23 4b fd 3c 37 ... >

var sender = secrets(master_key);
var packet = sender.pack('this is a secret message');
# => 'OqlG6KVMeyFYmunboS3HIXkvN_nXKTxg2yNkQydZOhvJrZvmfov54hUmkkiZCnlhzyrlwOJkbV7XnPPbqvdzZ6TsFOO5YdmxjxRksZmeIhbhLaMiDbfsOuSY1dBn_ZgtYCw-FRIM'
```

Receive:

```js
var secrets = require('simple-secrets');

// Same shared key
var master_key = new Buffer('<shared-key-hex>', 'hex');
var sender = secrets(master_key);
var packet = new Buffer('<read data from somewhere>');
// => 'OqlG6KVMeyFYmunboS3HIXkvN_nXKTxg2yNkQydZOhvJrZvmfov54hUmkkiZCnlhzyrlwOJkbV7XnPPbqvdzZ6TsFOO5YdmxjxRksZmeIhbhLaMiDbfsOuSY1dBn_ZgtYCw-FRIM'
var secret_message = sender.unpack(packet);
// => 'this is a secret message'
```


## Can you add ...

This implementation follows [simple-secrets] for 100% compatibility.

## License 

MIT.
