# FastAuth

This is a simple authentication server that can also be used for local development 
with reasonable defaults to kickstart the local development. This server is meant to 
run standalone and handle JWT tokens. It partially supports OAuth.

The server DB is sqlite, thus, use it with fast disks only. The password is protected
with scrypt and for token generation, HS256, RS256 and Ed25519 is supported.

## Setup
To build, run (you should have make installed):

```
make
```

To run with reasonable dev settings, execute:

```
./fastauth -dev myhs256pw
```
