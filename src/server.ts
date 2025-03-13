import { config as dotenvConfig } from 'dotenv';
dotenvConfig();

import { sequelize } from './database/sequelize';

import bodyParser from 'body-parser';
import express from 'express';
import path from 'path';
import { seedDB } from './database/seedDB';
import cookieParser from 'cookie-parser';
import frontendRouter from './routers/frontend.router';
import authRouter from './routers/auth.router';
import partials from 'express-partials';
import livereload from 'livereload';
import connectLivereload from 'connect-livereload';
import oidcRouter from './routers/oidc.router';
import cookieSession from 'cookie-session';

interface SessionData {
  user: { [key: string]: any };
  token?: string;
  oidc?: {
    client_id?: string;
    redirect_uri?: string;
    response_type?: string;
    scope?: string;
    state?: string;
  };
  authorizedScopes?: string[];
}
declare global {
  namespace Express {
    interface User {
      id: number;
      email: string;
      password: string;
      createdAt: Date;
    }
    interface Request {
      user?: User;
      session: SessionData;
    }
  }
}

sequelize.sync({ force: true }).then(() => {
  seedDB();
});


const app = express();

// Live reload setup
if (process.env.NODE_ENV === 'development') {
  console.log('Development mode enabled');
  const liveReloadServer = livereload.createServer();
  liveReloadServer.watch(path.join(__dirname, 'views'));
  app.use(connectLivereload());

  liveReloadServer.server.once('connection', () => {
    setTimeout(() => {
      liveReloadServer.refresh('/');
    }, 100);
  });
}



// view engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(partials());

// parsers
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// init session
app.use(cookieSession({
  name: 'sess',
  keys: ['key1', 'key2']
}));

// a simple request logger
app.use((req, res, next) => {
  res.on('finish', () => {
    console.log(`[${new Date().toISOString().split('.')[0]}] ${req.method} ${req.url} ${res.statusCode}`);
  });
  next();
});

// oidc router
app.use(oidcRouter);


app.use(frontendRouter);
app.use(authRouter);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
