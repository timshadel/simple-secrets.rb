
# simple-secrets.rb [![Build Status](https://travis-ci.org/timshadel/simple-secrets.rb.png?branch=master)](https://travis-ci.org/timshadel/simple-secrets.rb)

The Ruby implementation of a simple, opinionated library for encrypting small packets of data securely. Designed for exchanging tokens among systems written in a variety of programming languages:

* [Node.js](https://github.com/timshadel/simple-secrets)
* [Ruby](https://github.com/timshadel/simple-secrets.rb)
* [Rust](https://github.com/timshadel/simple-secrets.rs)
* [Objective-C](https://github.com/timshadel/SimpleSecrets)
* [Java](https://github.com/timshadel/simple-secrets.java)
* [Erlang](https://github.com/CamShaft/simple_secrets.erl)

## Examples

### Basic

Send:

```ruby
require 'simple-secrets'

include SimpleSecrets

# Try `head /dev/urandom | shasum -a 256` to make a decent 256-bit key
sender = Packet.new '<64-char hex string master key (32 bytes, 256 bits)>'
# => #<SimpleSecrets::Packet:0x007fec7c198e60 @master_key="d\xDD\xB5...", @identity="B\xBE...">

packet = sender.pack msg: 'this is a secret message'
# => 'Qr4m7AughkcQIRqQvlyXiB67EwHdBf5n9JD2s_Z9NpO4ksPGvLYjNbDm3HRzvFXFSpV2IqDQw_LTamndMh2c7iOQT0lSp4LstqJPAtoQklU5sb7JHYyTOuf-6W-q7W8gAnq1wCs5'
```

Receive:

```ruby
require 'simple-secrets'

include SimpleSecrets

# Same shared key
sender = Packet.new '<64-char hex string master key (32 bytes, 256 bits)>'
# Read data from somewhere
packet = 'OqlG6KVMeyFYmunboS3HIXkvN_nXKTxg2yNkQydZOhvJrZvmfov54hUmkkiZCnlhzyrlwOJkbV7XnPPbqvdzZ6TsFOO5YdmxjxRksZmeIhbhLaMiDbfsOuSY1dBn_ZgtYCw-FRIM'

secret_message = sender.unpack(packet);
# => {"msg"=>"this is a secret message"}
```


## Can you add ...

This implementation follows the spec for the [Node.js](https://github.com/timshadel/simple-secrets) version for 100% compatibility.

## License 

MIT.
