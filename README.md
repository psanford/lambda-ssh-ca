# lambda-ssh-ca

This is an SSH CA that runs in aws lambda. It uses an ECDSA key stored in KMS for its signing key.

There is an ssh-agent implementation that will generate an ephemeral key and request a cert from the CA. There is also a tool that will load an ephemeral key and cert into your existing ssh-agent.

This code assumes that it is running behind an API Gateway V2 in proxy mode with a lambda authorizer protecting the authorize route. It is probably more useful as a reference than it is to deploy as is.
