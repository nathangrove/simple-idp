import { Router } from "express";
import { User } from "../models/User";
import bcrypt from 'bcrypt';
import { createJwt, requireAuth, validatePassword } from "../services/auth";

const router = Router();

router.post('/login', async (req, res) => {
  const [email, password] = [req.body.email, req.body.password];
  if (!email || !password) return res.redirect('/login?error=true');

  const user = await validatePassword(email, password);
  if (!user) return res.redirect('/login?error=true');

  const token = createJwt(user.id, ['session'], process.env.ISSUER as string);
  req.session.token = token;
  req.user = user;
  res.redirect('/');
});

router.post('/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const newUser = await User.create({
      email,
      password: await bcrypt.hash(password, 10)
    });
    // store the user in the session
    const token = createJwt(newUser.toJSON().id, ['session'], process.env.ISSUER as string);
    req.session.token = token;
    req.user = newUser.toJSON();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error registering user' });
  }
});


router.get('/logout', requireAuth('session'), (req, res) => {
  res.clearCookie('sess');
  res.redirect('/login');
});

export default router;