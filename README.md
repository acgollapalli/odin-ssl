# odin-ssl
SSL for Odin based on LibreSSL

We're staticly linked against LibreSSl 4.0.0. We rely on having TLSv1.3 enabled.

The bindings are in ssl/ssl.odin. Wrapper functions to make this nice and clean are in progress.

The LibreSSL binaries go in lib/{platform}/

## How to Use

I would not use this. I mean, _I_ intend to use this. But you shouldn't use it unless you are feeling very adventurous, and possibly willing to do some debugging.