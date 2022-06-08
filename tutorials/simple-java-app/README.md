# Java application which calls the dbAPI endpoint "cashAccounts"

This small application calls the dbAPI endpoint "cashAccounts" available
in the API Explorer on our [developer portal](https://developer.db.com/apidocumentation/terminal).
This endpoint is documented in a [swagger definition](https://simulator-api.db.com/gw/dbapi/swaggers/v1/dbapi-cashAccounts-v2/swagger)

## What does this example do?
It is a step by step guide executing and explaining what a third party provider
has to do to call the dbAPI cashAccounts endpoint. Specially, it executes and
explains the OAuth2.0 authorization grant type with PKCE flow [described here](https://developer.db.com/apidocumentation/oauthflows/oauthcodegrantpkce)
and finally calls the "cashAccounts" endpoint of our dbAPI.

## What is required to run this application?
To run this application Java 8 or higher is required.
This application uses [Jersey 3](https://eclipse-ee4j.github.io/jersey.github.io/documentation/latest3x/index.html) because
the dbAPI uses the REST architectural style for all of it's endpoints. Other libraries are just helper libraries
which are needed by the sample application like [Jakarta Activation](https://github.com/eclipse-ee4j/jaf)
For generating the code challenge [Codec](https://mvnrepository.com/artifact/commons-codec/commons-codec) is used.

## Additional information
A proxy configuration is not implemented in this application. If you're behind a
proxy this application might not run!

Licensed under the Apache 2.0 license, for details see LICENSE.txt.