import { Authentication } from "../models/Authentication";
import { Authorization } from "../models/Authorization";

const AUTHENTICATION_CODE_TTL = 300000; // 5 minutes

// check if the user has authorized the service provider for scopes. If no scopes are requested, return true
export const checkForUnauthorizedScopes = async (userId: number, serviceProviderId: number, scopes: string | undefined): Promise<string[] | undefined> => {

  const auth = await Authorization.findOne({ where: { user: userId, service_provider: serviceProviderId } });
  if (!auth) return scopes ? scopes.split(' ') : [];

  if (!scopes) return [];

  const authorizedScopes = auth.toJSON().scopes.split(' ');

  // return the diff of scopes not in authorizedScopes
  const unauthorizedScopes = scopes.split(' ').filter(scope => !authorizedScopes.includes(scope));
  return unauthorizedScopes;
}

export const getAuthorizedScopes = async (userId: number, serviceProviderId: number): Promise<string> => {
  const auth = await Authorization.findOne({ where: { user: userId, service_provider: serviceProviderId } });
  if (!auth) return '';
  return auth.toJSON().scopes;
}

export const createAuthorization = async (userId: number, serviceProviderId: number, scopes: string): Promise<Authorization> => {
  return Authorization.create({
    user: userId,
    service_provider: serviceProviderId,
    scopes
  });
}

export const createAuthenticationCode = async (userId: number, serviceProviderId: number): Promise<string> => {
  const code = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  // save the code to the database
  Authentication.create({
    user: userId,
    service_provider: serviceProviderId,
    code,
    expires: new Date(Date.now() + AUTHENTICATION_CODE_TTL)
  });
  return code;
}

export const checkAuthenticationCode = async (code: string, serviceProviderId: number): Promise<number | null> => {
  const auth = await Authentication.findOne({ where: { code, service_provider: serviceProviderId } });
  if (!auth) return null;

  if (auth.toJSON().expires < new Date()) {
    await auth.destroy();
    return null;
  }

  return auth.toJSON().user;
}
