import { sign, verify } from "jsonwebtoken";
import { User } from "../models/User";
import bcrypt from 'bcrypt';
import { createHash } from "crypto";

export interface AuthJwtPayload {
  sub: string;
  scopes: string[];
}


export const requireAuth = (scope?: string | string[], redirect?: string) => async (req: any, res: any, next: any) => {
  const respondToInvalidCredentials = () => {

    if (redirect) return res.redirect(redirect);

    // if it is a browser request, redirect to login
    else if (scope === 'session' || req.headers.accept?.indexOf('text/html') > -1) res.redirect('/login');

    // if it is an API request, send a 401 response
    else res.status(401).json({ message: 'Unauthorized' });
  }

  // get the token
  const token = req.headers.authorization?.split(' ')?.[1] ?? req.session.token;
  if (!token) return respondToInvalidCredentials();

  try {
    const decoded = verifyJwt(token);
    if (!decoded) return respondToInvalidCredentials();
    else if (Array.isArray(scope) && !scope.some(s => decoded.scopes.includes(s))) return respondToInvalidCredentials();
    else if (typeof scope === 'string' && !decoded.scopes.includes(scope)) return respondToInvalidCredentials();

    req.session.authorizedScopes = decoded?.scopes ?? [];

    const user = await User.findOne({ where: { id: Number(decoded.sub) } });
    if (!user) return respondToInvalidCredentials();

    req.user = user.toJSON();
    next();
  } catch (err) {
    return respondToInvalidCredentials();
  }
}

export const validatePassword = async (email: string, password: string): Promise<Express.User | false> => {
  const user = await User.findOne({ where: { email } });
  if (!user) return false;

  if (await bcrypt.compare(password, user.toJSON().password)) return user.toJSON();
  else return false;
}

export const verifyJwt = (token: string): AuthJwtPayload | null => {
  try {
    return verify(
      token,
      (process.env.JWT_PUBLIC_KEY as string).replace(/\\n/gm, '\n'),
      {
        issuer: 'http://localhost:3000',
        algorithms: ['RS256'],
        maxAge: '7d'
      }
    ) as unknown as AuthJwtPayload;
  } catch (err) {
    console.error(err);
    return null;
  }
}

export const createJwt = (userId: number, scopes: string[]): string => {
  return sign({
    sub: userId.toString(),
    scopes
  }, {
    key: (process.env.JWT_PRIVATE_KEY as string).replace(/\\n/gm, '\n')
  }, {
    // create an md5 of the key for kid
    keyid: createHash('md5').update(process.env.JWT_PRIVATE_KEY as string).digest('hex'),
    issuer: 'http://localhost:3000',
    expiresIn: '7d',
    algorithm: 'RS256'
  });
}