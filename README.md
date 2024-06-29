# oauth middleware
OAuth 2.0 Authorization Server &amp; Authorization Middleware for [echo](https://echo.labstack.com/)

This library was ported to echo from https://github.com/maxzerbini/oauth & https://github.com/jeffreydwalter/oauth.

This library offers an OAuth 2.0 Authorization Server based on Echo and an Authorization Middleware usable in Resource Servers developed with Echo.


## Build status

[//]: # ([![Build Status]&#40;https://app.travis-ci.com/go-chi/oauth.svg?branch=master&#41;]&#40;https://app.travis-ci.com/github/go-chi/oauth&#41;)

## Authorization Server
The Authorization Server is implemented by the struct _OAuthBearerServer_ that manages two grant types of authorizations (password and client_credentials). 
This Authorization Server is made to provide an authorization token usable for consuming resources API. 

### Password grant type
_OAuthBearerServer_ supports the password grant type, allowing the token generation for username / password credentials.

### Client Credentials grant type
_OAuthBearerServer_ supports the client_credentials grant type, allowing the token generation for client_id / client_secret credentials.

### Authorization Code and Implicit grant type
These grant types are currently partially supported implementing AuthorizationCodeVerifier interface. The method ValidateCode is called during the phase two of the authorization_code grant type evalutations.

### Refresh token grant type
If authorization token will expire, the client can regenerate the token calling the authorization server and using the refresh_token grant type.

## Authorization Middleware 
The go-chi middleware _BearerAuthentication_ intercepts the resource server calls and authorizes only resource requests containing a valid bearer token.

## Token Formatter
Authorization Server crypts the token using the Token Formatter and Authorization Middleware decrypts the token using the same Token Formatter.
This library contains a default implementation of the formatter interface called _SHA256RC4TokenSecureFormatter_ based on the algorithms SHA256 and RC4.
Programmers can develop their Token Formatter implementing the interface _TokenSecureFormatter_ and this is really recommended before publishing the API in a production environment. 

## Credentials Verifier
The interface _CredentialsVerifier_ defines the hooks called during the token generation process.
The methods are called in this order:
- _ValidateUser() or ValidateClient()_ called first for credentials verification
- _AddClaims()_ used for add information to the token that will be encrypted
- _StoreTokenID()_ called after the token generation but before the response, programmers can use this method for storing the generated IDs
- _AddProperties()_ used for add clear information to the response

There is another method in the _CredentialsVerifier_ interface that is involved during the refresh token process. 
In this case the methods are called in this order:
- _ValidateTokenID()_ called first for TokenID verification, the method receives the TokenID related to the token associated to the refresh token
- _AddClaims()_ used for add information to the token that will be encrypted
- _StoreTokenID()_ called after the token regeneration but before the response, programmers can use this method for storing the generated IDs
- _AddProperties()_ used for add clear information to the response

[//]: # (## Authorization Server usage example)

[//]: # (This snippet shows how to create an authorization server)

[//]: # (```Go)

[//]: # (func main&#40;&#41; {)

[//]: # (    r := chi.NewRouter&#40;&#41;)

[//]: # (    r.Use&#40;middleware.Logger&#41;)

[//]: # (    r.Use&#40;middleware.Recoverer&#41;)

[//]: # ()
[//]: # (    s := oauth.NewOAuthBearerServer&#40;)

[//]: # (        "mySecretKey-10101",)

[//]: # (	time.Second*120,)

[//]: # (	&TestUserVerifier{},)

[//]: # (	nil&#41;)

[//]: # (	)
[//]: # (    r.Post&#40;"/token", s.UserCredentials&#41;)

[//]: # (    r.Post&#40;"/auth", s.ClientCredentials&#41;)

[//]: # (    http.ListenAndServe&#40;":8080", r&#41;)

[//]: # (})

[//]: # (```)

[//]: # (See [/test/authserver/main.go]&#40;https://github.com/go-chi/oauth/blob/master/test/authserver/main.go&#41; for the full example.)

[//]: # ()
[//]: # (## Authorization Middleware usage example)

[//]: # (This snippet shows how to use the middleware)

[//]: # (```Go)

[//]: # (    r.Route&#40;"/", func&#40;r chi.Router&#41; {)

[//]: # (	// use the Bearer Authentication middleware)

[//]: # (	r.Use&#40;oauth.Authorize&#40;"mySecretKey-10101", nil&#41;&#41;)

[//]: # ()
[//]: # (	r.Get&#40;"/customers", GetCustomers&#41;)

[//]: # (	r.Get&#40;"/customers/{id}/orders", GetOrders&#41;)

[//]: # (    })

[//]: # (```)

[//]: # (See [/test/resourceserver/main.go]&#40;https://github.com/go-chi/oauth/blob/master/test/resourceserver/main.go&#41; for the full example.)

Note that the authorization server and the authorization middleware are both using the same token formatter and the same secret key for encryption/decryption.

## Reference
- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)
- [OAuth 2.0 Bearer Token Usage RFC](https://tools.ietf.org/html/rfc6750)

[//]: # (## License)

[//]: # ([MIT]&#40;https://github.com/go-chi/oauth/blob/master/LICENSE&#41;)
