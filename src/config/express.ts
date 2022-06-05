import { Authenticator } from '@server/lib/Authenticator';
import express from 'express';
import session, { SessionOptions } from 'express-session';
import { OIDC, OIDCSession } from '@server/lib/OIDC';
import { logger } from './logger';

export class SessionRequest {

  type: string = '';
  connection: string;
  start: number = new Date().getTime();

  constructor(part: Partial<any>){
    for(const key in part){
      this[key] = part[key];
    }
  }

}
declare namespace Express {
  export interface Request {
    session: OIDCSession;
  }
}

const createServer = (): express.Application => {

  const app = express();

  app.use(express.urlencoded({ extended: true }));
  app.use(express.json());

  app.disable('x-powered-by');

  app.use((req, res, next) => {
    const startTime = new Date().getTime();
    res.on('close', () => {
      const current_datetime = new Date();
      const formatted_date =
        current_datetime.getFullYear() +
        "-" +
        (current_datetime.getMonth() + 1) +
        "-" +
        current_datetime.getDate() +
        " " +
        current_datetime.getHours() +
        ":" +
        current_datetime.getMinutes() +
        ":" +
        current_datetime.getSeconds();
      const method = req.method;
      const url = req.url;
      const status = res.statusCode;
      const duration = (new Date().getTime()) - (startTime);
      const log = `[${formatted_date}] ${method}:${url} ${status} ${duration}ms`;
      logger.log('info',log);
    });

    
    next();
  })

  app.get('/health', (_req, res) => {
    res.send('UP');
  });


  // CONFIGURE SESSIONS
  const sessConfig: SessionOptions = {
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: process.env.NODE_ENV === 'production'
    }
  }
  app.use(session(sessConfig));

  // ENABLE PROTOCOL ROUTES
  app.use(new OIDC().routes());

  const authenticator: Authenticator = new Authenticator();
  app.use(authenticator.router);

  return app;
};

export { createServer };
