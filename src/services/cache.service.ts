import { randomUUID } from "crypto";
import { NextFunction, Request, Response } from "express";


/**
 * A simple cache service.
 */
export class Cache {
  private cache: { [key: string]: any } = {};

  constructor(){
    setInterval(this._cleanup.bind(this), 1000);
  }

  private _cleanup(): void {
    // console.log('cleaning up', this.cacheID);
    let keysToDelete = Object.keys(this.cache).filter(key => this.cache[key].expire < Date.now());
    keysToDelete.forEach(key => delete this.cache[key]);
  }

  public get(key: string): any {
    return this.cache[key]?.value ?? {};
  }

  public set(key: string, value: any, expire: number): void {
    this.cache[key] = { value, expire };
  }

  public has(key: string): boolean {
    return this.cache[key] !== undefined;
  }

  public delete(key: string): void {
    delete this.cache[key];
  }

  public clear(): void {
    this.cache = {};
  }

}

/**
 *  A middleware to cache session information
 */
export const cacheSessions = (req: Request, res: Response, next: NextFunction) => {
  if (req.cookies.SESS && cache.has(req.cookies.SESS)) {
    req.session = cache.get(req.cookies.SESS);
    return next();
  }

  const sessID = randomUUID();
  res.cookie('SESS', sessID, {
    expires: new Date(Date.now() + 1000 * 60 * 60 * 24),
    httpOnly: true
  });

  cache.set(sessID, req.session, Date.now() + 1000 * 60 * 60 * 24);
  req.session = cache.get(sessID);
}

/**
 * Export a singleton instance of the cache service
 */
export const cache: Cache = new Cache();