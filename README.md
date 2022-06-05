# Simple IDP
This is meant to be a simple modular IDP that supports OIDC and SAML authentication protocols. I would like to use this interally on my home network for different services.
   
This is mainly an experiment and experience implementing different protocols. This will eventually not only be an identity provder, but also just an authentication provider plugged into upstream identity providers like ActiveDirectory. I hope to make this modular enough to slowly develop and add features over time.


## Supported Service Provider Authentication Protocols
- OIDC
- SAML (WIP)

## Supported Identity Provider Protocols
*NONE (yet)*  

## Development
1. `git clone https://github.com/nathangrove/simple-idp.git`
2. `docker-compose run app npm install`
3. `docker-compose up`

## Contribution
Feel free to fork and submit pull requests.