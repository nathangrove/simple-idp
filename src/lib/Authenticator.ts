import { cache } from "@server/services/cache.service";
import { mongo } from "@server/services/mongo.service";
import { Request, Response, Router } from "express";
import { OIDC } from "./OIDC";


/**
 * Authenticates a user in the IDP and establishes a session. 
 */
class Authenticator {
  page = `
  <h1>Login</h1>
  <form method='POST' action='/auth/login' >
  Username: <input type='text' name='username' required /><br/>
  Password: <input type='password' name='password' required /></br/>
  <button>Login</button>
  </form>
  `;
  
  router: Router = Router();
  constructor(){
    
    this.router.get('/auth', ( _req: Request, res: Response, next) => {
      const auth: Authenticator = new Authenticator();
      res.send(auth.page);
      next();
    })
    
    this.router.post('/auth/login', async (req: Request, res: Response, next) => {
      
      if (!req.session?.request?.clientId) return res.status(400).json({ status: 400, error: "Invalid request" });
      
      let connection = await mongo.connection(req.session.request.clientId)
      let user = await connection.findUserByEmail(req.body.username).catch( console.error );
      
      if (!user) return res.sendStatus(403); 
      else if (!user.checkPassword(req.body.password)) return res.sendStatus(403);
      else req.session.userID = user._id.toString();
      
      if (req.session.request.type === 'oidc'){
        return await new OIDC().process(req, res, next).catch( console.error );
      } else {
        res.sendStatus(400); 
      }

      return next();
    })

    this.router.get('/auth/logout', (req: Request, res: Response, next) => {
      cache.delete(req.session.cacheKey);
      req.session.destroy( err => err ? res.sendStatus(500) : res.sendStatus(200) );
      next();
    });
  }
  
}

export { Authenticator }
