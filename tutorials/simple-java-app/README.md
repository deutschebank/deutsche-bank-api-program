# Java application which calls the dbAPI endpoint "cashAccounts" 
 
This small application calls the dbAPI endpoint "cashAccounts" available
in the API Explorer on our [developer portal](https://developer.db.com/apidocumentation/terminal). 
This endpoint is documented in a [swagger definition](https://simulator-api.db.com/gw/dbapi/swaggers/v1/dbapi-cashAccounts-v2/swagger)
 
## What does this example do?
It is a step by step guide executing and explaining what a third party provider
has to do to call the dbAPI cashAccounts endpoint. Specially, it executes and
explains the OAuth2.0 implicit grant flow [described here](https://developer.db.com/apidocumentation/oauthflows/oauthimplicitgrant)
and finally calls the "cashAccounts" endpoint of our dbAPI.

## What is required to run this application?
To run this application Java 8 or higher is required.
This application uses the [JAX-RS 2.1](https://jax-rs.github.io/apidocs/2.1/) because
the dbAPI uses the REST architectural style for all of it's endpoints. Other
libraries are not necessary to run this application. We use [Jersey](https://jersey.github.io/) 
for client configs in this application. 

## Additional information
A proxy configuration is not implemented in this application. If you're behind a
proxy this application might not run!

Licensed under the Apache 2.0 license, for details see LICENSE.txt.