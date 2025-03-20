import { NextFunction, Request, Response, Router } from "express";
import { createIdToken, createJwt, requireAuth } from "../services/auth";
import { createHash, createPublicKey } from "crypto";
import { checkAuthenticationCode, checkForUnauthorizedScopes, createAuthenticationCode, createAuthorization, getAuthorizedScopes } from "../services/oidc";
import { ServiceProvider } from "../models/ServiceProvider";
import { Authorization } from "../models/Authorization";
import { User } from "../models/User";


const ALLOWED_SCOPES = ['openid', 'email', 'profile'];
const ALLOWED_RESPONSE_TYPES = ['code', 'id_token'];

const router = Router();

router.get('/authorize', (req, res, next) => {
  // validate the oidc request
  const client_id = String(req.query.client_id);
  const redirect_uri = req.query.redirect_uri as string;
  const response_type = String(req.query.response_type);
  const scope = req.query.scope as string;
  const state = req.query.state as string;

  // check all scopes
  if (scope)
    scope.split(' ').forEach((s: string) => {
      if (ALLOWED_SCOPES.indexOf(s) === -1) {
        res.status(400).json({ message: 'Invalid scope: "' + s + '"' });
        return;
      }
    });

  // validate response type
  if (!response_type || ALLOWED_RESPONSE_TYPES.indexOf(response_type) === -1) {
    res.status(400).json({ message: 'Invalid response type' });
    return;
  }

  // store the request in the session
  req.session.oidc = {
    client_id,
    response_type,
    ...(redirect_uri && { redirect_uri }),
    ...(scope && { scope }),
    ...(state && { state })
  };

  next();

}, requireAuth('session'), async (req, res) => {

  if (!req.user || !req.session.oidc) return res.redirect('/login');

  const serviceProvider = await ServiceProvider.findOne({ where: { client_id: req.session.oidc?.client_id } });
  if (!serviceProvider) {
    res.status(400).json({ message: 'Invalid client_id' });
    return;
  }

  // set the default redirect_uri
  if (!req.session.oidc?.redirect_uri) req.session.oidc.redirect_uri = serviceProvider.toJSON().default_redirect_uri;
  else {
    const redirectUris = serviceProvider.toJSON().redirect_uri.split(' ');
    if (redirectUris.indexOf(req.session.oidc.redirect_uri) === -1) {
      res.status(400).json({ message: 'Invalid redirect_uri' });
      return;
    }
  }

  const unauthorizedScopes = await checkForUnauthorizedScopes(req.user?.id, serviceProvider.toJSON().id, req.session.oidc?.scope);

  if (unauthorizedScopes === undefined || unauthorizedScopes.length > 0) {
    res.render('pages/authorize', {
      title: 'Authorize',
      layout: 'layout',
      user: req.user,
      unauthorizedScopes,
      serviceProviderName: serviceProvider.toJSON().name
    });
  } else {
    if (req.session.oidc?.response_type === 'code') {
      const code = await createAuthenticationCode(req.user?.id, serviceProvider.toJSON().id);
      const redirectUrl = `${req.session.oidc?.redirect_uri}?code=${code}${req.session.oidc?.state ? `&state=${req.session.oidc?.state}` : ''}`;
      req.session.oidc = undefined;
      res.redirect(redirectUrl);

    } else {
      const token = createJwt(req.user?.id, [], serviceProvider.toJSON().client_id);
      const redirctUrl = `${req.session.oidc?.redirect_uri}?id_token=${token}${req.session.oidc?.state ? `&state=${req.session.oidc?.state}` : ''}`;
      req.session.oidc = undefined;
      res.redirect(redirctUrl);
    }
  }
});

// update authorizations that the user has granted
router.post('/authorize', requireAuth('session'), async (req, res) => {
  if (!req.user || !req.session.oidc) {
    res.redirect('/login');
    return;
  }

  const serviceProvider = await ServiceProvider.findOne({ where: { client_id: req.session.oidc?.client_id } });
  if (!serviceProvider) {
    res.status(400).json({ message: 'Invalid client_id' });
    return;
  }

  // create the authorization
  if (req.body.decision === 'allow' && req.body.scopes) await createAuthorization(req.user?.id, serviceProvider.toJSON().id, req.body.scopes.join(' '));
  else await createAuthorization(req.user?.id, serviceProvider.toJSON().id, '');

  // update the session scopes
  req.session.oidc.scope = req.body.decision === 'allow' && req.body.scopes ? req.body.scopes.join(' ') : '';

  // if no scopes are unauthorized, redirect to the redirect_uri with the code
  if (req.session.oidc?.response_type === 'code') {
    const code = await createAuthenticationCode(req.user?.id, serviceProvider.toJSON().id);
    const redirctUrl = `${req.session.oidc?.redirect_uri}?code=${code}${req.session.oidc?.state ? `&state=${req.session.oidc?.state}` : ''}`;
    req.session.oidc = undefined;
    res.redirect(redirctUrl);
  } else {
    const token = createJwt(req.user?.id, req.session.oidc.scope?.split(' ') ?? [], serviceProvider.toJSON().client_id);
    const redirectUrl = `${req.session.oidc?.redirect_uri}?id_token=${token}&state=${req.session.oidc?.state}`;
    req.session.oidc = undefined;
    res.redirect(redirectUrl);
  }
});

router.get('/authorization/revoke/:client_id', requireAuth('session'), async (req, res) => {
  if (!req.user || !req.params.client_id) {
    res.redirect('/login');
    return;
  }

  const sp = await ServiceProvider.findOne({ where: { client_id: req.params.client_id } });
  if (!sp) return res.redirect('/settings');

  await Authorization.destroy({
    where: {
      service_provider: sp?.toJSON().id,
      user: req.user.id
    }
  });

  res.redirect('/settings');
});

router.get('/.well-known/openid-configuration', (req, res) => {
  res.json({
    issuer: process.env.ISSUER,
    authorization_endpoint: `${process.env.DOMAIN}/authorize`,
    token_endpoint: `${process.env.DOMAIN}/token`,
    userinfo_endpoint: `${process.env.DOMAIN} /userinfo`,
    jwks_uri: `${process.env.DOMAIN}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'email', 'profile']
  });
});

router.get('/.well-known/jwks.json', (req, res) => {

  // convert the public key to a JWK

  const publicKey = createPublicKey((process.env.JWT_PUBLIC_KEY as string).replace(/\\n/gm, '\n'));
  const spki = publicKey.export({ format: 'jwk' });

  res.json({
    keys: [
      {
        kty: 'RSA',
        e: spki.e,
        use: 'sig',
        kid: createHash('md5').update(process.env.JWT_PRIVATE_KEY as string).digest('hex'),
        alg: 'RS256',
        n: spki.n
      }
    ]
  });
});

router.post('/token', async (req, res) => {

  const code = req.body.code;
  const client_secret = req.body.client_secret;
  const client_id = req.body.client_id;

  if (!code || !client_secret || !client_id) {
    res.status(400).json({ message: 'Invalid request' });
    return;
  }

  // get the service provider
  const serviceProvider = await ServiceProvider.findOne({ where: { client_secret } });
  if (!serviceProvider) {
    res.status(400).json({ message: 'Invalid client_id or client_secret' });
    return;
  }

  // validate the code
  const userId = await checkAuthenticationCode(code, serviceProvider.toJSON().id);
  if (!userId) {
    res.status(400).json({ message: 'Invalid code' });
    return;
  }

  // get authorized scopes
  const scopes = await getAuthorizedScopes(userId, serviceProvider.toJSON().id);

  let email;
  if (scopes.split(' ').indexOf('email') > -1) {
    const user = await User.findOne({ where: { id: userId } });
    if (!user) {
      res.status(400).json({ message: 'Invalid user' });
      return;
    }
    email = user.toJSON().email;
  }
  // generate an access token
  const token = createJwt(userId, scopes.split(' '), client_id);

  res.json({
    access_token: token,
    id_token: createIdToken({
      userId,
      ...(email && { email })
    }, client_id),
    token_type: 'Bearer',
    expires_in: 3600,
  });

});

router.get('/userinfo', requireAuth(), (req: Request, res: Response) => {
  res.json({
    ...(req.session.authorizedScopes?.some(s => ['profile', 'email'].indexOf(s) > -1) && { email: req.user?.email }),
    sub: req.user?.id
  });
});

export default router;