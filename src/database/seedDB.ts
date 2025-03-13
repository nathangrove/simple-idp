import { ServiceProvider } from "../models/ServiceProvider";
import { User } from "../models/User";
import bcrypt from 'bcrypt';
import { Authorization } from "../models/Authorization";

const TEST_CLIENT_ID = '4fcaba6428ee4e398dfa27c565bec8f8';
const TEST_CLIENT_SECRET = '61fe04a07a3bf12ef9ae496a358ca2c464071fd8c40763dc478691d797edba16';

export const seedDB = async () => {
  // check if the database is already seeded
  const users = await User.findAll();
  if (users.length > 0) {
    return;
  }

  // Create test users
  const user = await User.create({
    email: 'authorized@example.com',
    password: await bcrypt.hash('test', 10)
  }).catch(console.error);

  if (!user) return;

  User.create({
    email: 'unauthorized@example.com',
    password: await bcrypt.hash('test', 10)
  }).catch(console.error);

  // create a service provider(s)
  const provider = await ServiceProvider.create({
    name: 'Test Service Provider',
    client_id: TEST_CLIENT_ID,
    client_secret: TEST_CLIENT_SECRET,
    redirect_uri: 'http://localhost:3000/callback',
    default_redirect_uri: 'http://localhost:3000/callback'
  }).catch(console.error);

  if (!provider) return;

  // authorize the user
  Authorization.create({
    user: user.toJSON().id,
    service_provider: provider.toJSON().id,
    scopes: 'openid profile email'
  }).catch(console.error);
}