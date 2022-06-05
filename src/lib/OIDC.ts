import { cache } from "@server/services/cache.service";
import { mongo } from "@server/services/mongo.service";
import { createHash, createPrivateKey, createPublicKey, createSign, generateKeyPairSync, KeyObject, randomUUID } from "crypto";
import { Request, Response, Router } from "express";
import { readFileSync, writeFileSync } from "fs";
import { cloneDeep } from "lodash";

const oidcConfg = {
  "issuer": "http://localhost:5000/",
  "authorization_endpoint": "http://localhost:5000/oidc/auth",
  "token_endpoint": "http://localhost:5000/oidc/token",
  "device_authorization_endpoint": "http://localhost:5000/oauth/device/code",
  "userinfo_endpoint": "http://localhost:5000/oidc/userinfo",
  "mfa_challenge_endpoint": "http://localhost:5000/mfa/challenge",
  "jwks_uri": "http://localhost:5000/.well-known/jwks.json",
  "registration_endpoint": "http://localhost:5000/oidc/register",
  "revocation_endpoint": "http://localhost:5000/oauth/revoke",
  "scopes_supported": [
    "openid",
    "profile",
    "offline_access",
    "name",
    "given_name",
    "family_name",
    "nickname",
    "email",
    "email_verified",
    "picture",
    "created_at",
    "identities",
    "phone",
    "address"
  ],
  "response_types_supported": [
    "code",
    "token",
    "id_token",
    "code token",
    "code id_token",
    "token id_token",
    "code token id_token"
  ],
  "code_challenge_methods_supported": [
    "S256",
    "plain"
  ],
  "response_modes_supported": [
    "query",
    "fragment",
    "form_post"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "HS256",
    "RS256"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post"
  ],
  "claims_supported": [
    "aud",
    "auth_time",
    "created_at",
    "email",
    "email_verified",
    "exp",
    "family_name",
    "given_name",
    "iat",
    "identities",
    "iss",
    "name",
    "nickname",
    "phone_number",
    "picture",
    "sub"
  ],
  "request_uri_parameter_supported": false
}


export class OIDCSession {
  type: string = 'oidc';
  scopes: string[];
  responseType: string[];
  redirectUri: string;
  responseMode: string = 'post_form';
  nonce?: string;
  state?: string;
  clientId: string;
  claims?: string[];
  approved?: boolean;
  atHash?: string;
  code?: string;
  start: number = new Date().getTime();
}

class OIDC {

  privateKey: KeyObject;
  publicKey: KeyObject;
  
  public constructor(){
    try {
      this.privateKey = createPrivateKey((readFileSync('keys/jwtRS256.key').toString()));
      this.publicKey = createPublicKey((readFileSync('keys/jwtRS256.key.pub').toString()));
    } catch (e){
      const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 4096, publicKeyEncoding: { type: 'pkcs1', format: 'pem' }, privateKeyEncoding: { type: 'pkcs1', format: 'pem' } });

      writeFileSync('keys/jwtRS256.key', privateKey);
      writeFileSync('keys/jwtRS256.key.pub', publicKey);

      this.privateKey = createPrivateKey(privateKey);
      this.publicKey = createPublicKey(publicKey);
    }
  }

  public routes(){
    let router: Router = Router();
    router.get('/.well-known/openid-configuration', (_req: Request, res: Response, next) => {
      res.json(oidcConfg);
      next();
    })
    
    router.get('/.well-known/jwks.json', ( _req: Request, res: Response, next) => {
      res.json({ keys: [ this.publicKey.export({ format: 'jwk' }) ]});
      next();
    })
    
    router.get('/oidc/auth', (req: Request, res: Response, next): any => {
      
      const responseType: string[] = (req.query.response_type as string)?.toLowerCase().split(' ').map( t => t.trim() ).filter( t => t );
      const scopes: string[] = (req.query.scope as string)?.toLowerCase().split(' ').map( s => s.trim() ).sort() || [];
      const redirectUri = req.query.redirect_uri as string;
      const clientId = req.query.client_id as string;
      const nonce = req.query.nonce as string;
      const responseMode = req.query.response_mode as string || 'post_form';
      const state = req.query.state as string || 'none';
      
      // validate
      if (!clientId 
        || !redirectUri 
        || !responseType 
        || (responseType.length > 1 && responseType.indexOf('none') > -1) ){
        res.statusCode = 400;
        return res.send('Invalid request');
      }
      
      // if not authenticated store it in session and auth
      if (!req.session.userID || !process.env.SSO){
        req.session.request = { 
          type: 'oidc', 
          clientId, 
          scopes, 
          responseType, 
          redirectUri, 
          nonce, 
          responseMode, 
          state, 
          start: new Date().getTime() 
        };
        res.redirect('/auth');
        return res.end();

      }
      
      this.process(req, res, next);
    })

    router.post('/oidc/permissions', async (req: Request, res: Response, next) => {
      if(!req.session) {
        res.sendStatus(401);
        return next();
      }
      if (!req.session.request){
        res.sendStatus(400);
        return next();
      }

      if (req.body.approve){

        let user = await mongo.user(req.session.userID);
        user.approvedClients[req.session.request.clientId] = createHash('sha256').update(req.session.request.scopes.join(',')).digest('base64')
        await user.update();
        this.process(req, res, next);

      } else {
        res.sendStatus(401);
        next();
      }
    })

    router.post('/oidc/token', (req: Request, res: Response, next) => {
      
      let jwt = this._jwt(cache.get(req.body.code));
      res.json({
        "access_token" : req.body.code,
        "token_type"   : "Bearer",
        "expires_in"   : 3600,
        "scope"        : cache.get(req.body.code)?.scopes?.join(' ') ?? '', // "openid email profile app:read app:write",
        "id_token"     : jwt
      });
      next();
    })

    router.get('/oidc/permissions', (req: Request, res: Response, next): any => {
      res.send(`
      The application "${req.session.request.clientId}" is requesting access to  the following:<br/>
      <ul><li>${req.session.request.scopes.join('</li><li>')}</li></ul><br/>
      <form method='POST'>
        <input type='hidden' name='approve' value='true' />
        <button>Click here to approve</button>
      </form>
      `);
      next();
    })

    router.get('/oidc/userinfo', (req: Request, res: Response, next): any => {
      const token = req.headers['authorization'].split('Bearer ')[1];

      if (cache.has(token)){

        res.json({
          sub: "123456",
          given_name: "Nathan",
          family_name: "Grove",
          email: "nathan@nathangrove.com",
        })

      } else if (this._verifyJWT(token)){

        res.json({
          sub: "123456",
          given_name: "Nathan",
          family_name: "Grove",
          email: "nathan@nathangrove.com",
        }).end();

      } else {
        res.sendStatus(401);
      }

      next();
    })

    return router;
  }
  

  async process(req: Request, res: Response, next){
    if (!req.session.userID) {
      res.redirect('/auth');
      return res.end();
                    
    } 

    let user = await mongo.user(req.session.userID);
    if (!user) {
      res.redirect('/auth');
      return res.end();
    }
    
    if (
      req.session.request.responseType.indexOf('code') > -1 
      && user.approvedClients[req.session.request.clientId] != createHash('sha256').update(req.session.request.scopes.join(',')).digest('base64') 
    ){
      res.redirect('/oidc/permissions');
      return res.end();
    }
    
    let responseCodes = '';
    
    let code = randomUUID();
    req.session.request.atHash = this._atHash(code);

    if (req.session.request.responseType.indexOf('id_token') > -1){
      const token = this._jwt(req.session.request);
      responseCodes += `<input type='hidden' name='id_token' value='${token}' />`;
    } 

    if (req.session.request.responseType.indexOf('token') > -1 || req.session.request.responseType.indexOf('id_token') > -1){
      responseCodes += `<input type='hidden' name='access_token' value='${code}' />`;
    }

    if (req.session.request.responseType.indexOf('code') > -1){
      responseCodes += `<input type='hidden' name='code' value='${code}' />`;
    }

    // store the code with its relevant data
    cache.set(code, cloneDeep(req.session.request), 3600);
    req.session.cacheKey = code;

    
    res.send(`
    <html>
    <head><title>Submit This Form</title></head>
    <body onload="javascript:document.forms[0].submit()">
    <form action="${req.session.request.redirectUri}" method="POST">
    <input type="hidden" name="state" value="${req.session.request.state || 'none'}" />
    <input type="hidden" name="nonce" value="${req.session.request.nonce || ''}" />
    ${ responseCodes }
    </form>
    </body>
    </html>
    `)
    // redirect back to the SP
    // res.redirect(`${req.session.request.redirectUri}?code=abc123123`);
    
    return next();
  }

  private _jwt(sessionRequest: OIDCSession){    
    
    const payload = Buffer.from(JSON.stringify({
      "iss": "http://localhost:5000/",
      "sub": "123456",
      "aud": sessionRequest.clientId,
      "exp": new Date().getTime() / 1000 + 86400 ,
      "nonce": sessionRequest.nonce,
      "iat": new Date().getTime() / 1000,
      "claims": sessionRequest.claims,
      "at_hash": sessionRequest.atHash
    })).toString('base64url');
    
    const header = Buffer.from(JSON.stringify({
      alg: 'RS256',
      typ: 'JWT'
    })).toString('base64url');


    const signature = this._signJWT(`${header}.${payload}`);
    return `${header}.${payload}.${signature}`;
  }

  private _atHash(token: string){
    const digest = createHash('sha256').update(token).digest();
    return digest.slice(0, digest.length / 2).toString('base64url');
  }

  private _verifyJWT(jwt: string){
    
    const parts = jwt.split('.');
    const payload = JSON.parse(Buffer.from(parts[1],'base64url').toString());
    const signature = this._signJWT(`${parts[0]}.${parts[1]}`);

    return signature == parts[2] && payload.exp > Date.now() / 1000
  }

  private _signJWT(str: string): string{
    let signatureFunction = createSign('RSA-SHA256');
    signatureFunction.write(str);
    signatureFunction.end();
    return signatureFunction.sign(this.privateKey.export({ format: 'pem', type: 'pkcs1' })).toString('base64url');
  }
  
}

export { OIDC }