# FastAuth

This is a simple authentication server that can also be used for local development 
with reasonable defaults to kickstart the local development. This server is meant to 
run standalone and handle JWT tokens. It partially supports OAuth.

The default server DB is sqlite (PostgreSQL is supported). The password is protected
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

This inserts the user with the name "user" and the password "pass". 
For **non** PKCE flow, open in browser [http://localhost:8080/oauth/authorize?response_type=code](http://localhost:8080/oauth/authorize?response_type=code). 
The token will use RS256, to use HS256, start fastauth as follows:

```
./fastauth -dev test -rs256 false -ed256 false
```

You should see in your browser the access token:

```
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsibXktYXVkaWVuY2UiXSwiZXhwIjoxNjE2MzMxNTI3LCJpc3MiOiJteS1pc3N1ZXIiLCJzY29wZSI6Im15LXNjb3BlIiwic3ViIjoidXNlciJ9.NPZGkhGdH-mXjJ1mIhCvdnJab27EqPS5KRpDigfBXLs",
 "token_type":"Bearer",
 "refresh_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MzE4ODE3MjcsInJvbGUiOiJ1c2VyIiwidG9rZW4iOiJYMzRRT0dMUktUUTZLN0pPRkhMR0JQMkVPMlM0RTVBSSJ9.I1EpkyHkUe2ch4xfJ-93TqMiCo1ziFOVTnfyV4e4pLU",
 "expires_in":"1631881727"}
```

Test it with 
```
curl -H 'Accept: application/json' http://localhost:8080/authen/logout
```
You should see: "authorization header not set". This means you need to set the 
authorization header (copy the access token you got from the browser):

```
TOKEN=ey..
curl -H 'Accept: application/json' -H "Authorization: Bearer ${TOKEN}" http://localhost:8080/authen/logout
```

For the PKCE flow add the following parameters:

[http://localhost:8080/oauth/authorize?code_challenge=fNcHfbUCOvMuzmkBK7c2MR_8TK_Iq6tHDXTJL6qcAco&code_challenge_method=S256](http://localhost:8080/oauth/authorize?code_challenge=fNcHfbUCOvMuzmkBK7c2MR_8TK_Iq6tHDXTJL6qcAco&code_challenge_method=S256).

In this example, we have the code verifier: HalloDasIstEinTest123456789012345678901234567890 and the
challenge: fNcHfbUCOvMuzmkBK7c2MR_8TK_Iq6tHDXTJL6qcAco ([test it here](https://tonyxu-io.github.io/pkce-generator/)).

This will give us the authorization code, than we need to confirm. Copy the code from the browser. 
To not have the user involved, a redirect is done (not in this example).

Now, we need to confirm the code with the verifier (copy from the browser):

```
CODE=ey....
curl -X POST -H 'Accept: application/json' --data 'grant_type=authorization_code' --data "code=${CODE}" --data 'code_verifier=HalloDasIstEinTest123456789012345678901234567890' http://localhost:8080/oauth/token
```

And we will get the access and refresh token

# Run with docker

```
docker build -t fastauth .
docker run -it --rm fastauth
```
