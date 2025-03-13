import { Router } from "express";
import { User } from "../models/User";
import { requireAuth } from "../services/auth";
import { Authorization } from "../models/Authorization";
import { ServiceProvider } from "../models/ServiceProvider";

const router = Router();


router.get('/login', (req, res) => {
  res.render('pages/login', {
    query: req.query,
    layout: 'layout',
    title: 'Login'
  });
});
router.get('/register', (req, res) => {
  res.render('register');
});


router.get('/', requireAuth('session'), async (req, res) => {
  if (!req.user) return res.redirect('/login');

  // inner join the service_providers and authorizations tables
  const user = await User.findOne({
    include: ServiceProvider,
    where: { id: req.user.id }
  });

  res.render('pages/index', {
    title: 'Home',
    layout: 'layout',
    user
  });
});

router.get('/profile', requireAuth('session'), (req, res) => {
  res.render('pages/profile', {
    title: 'Profile',
    layout: 'layout',
    user: req.user
  });
});

router.get('/settings', requireAuth('session'), async (req, res) => {
  if (!req.user) return res.redirect('/login');

  // inner join the service_providers and authorizations tables
  const user = await User.findOne({
    include: ServiceProvider,
    where: { id: req.user.id }
  });

  res.render('pages/settings', {
    title: 'Settings',
    layout: 'layout',
    user
  });
});


export default router;