import { Collection, Db, MongoClient, MongoError, ObjectId } from "mongodb";
import { Client } from "../models/client";
import { Connection } from "../models/connection";
import { User } from "../models/user";


/**
 * Simple wrapper for mongoDB.
 */
export class Mongo { 
  
  public connections: Collection<Connection>;
  public users: Collection<User>;
  public clients: Collection<Client>;
  
  async connect(): Promise<boolean | MongoError> {
    
    return new Promise( async (resolve, reject) => {
      
      try {

        // Connection URI
        const uri = `mongodb://${process.env.MONGO_USER}:${process.env.MONGO_PASS}@${process.env.MONGO_HOST}/?maxPoolSize=20&w=majority`;
      
        // Create a new MongoClient
        let client = new MongoClient(uri);
        await client.connect();
        let db: Db = await client.db(process.env.MONGO_NAME);
        this.users = db.collection('users');
        this.connections = db.collection('connections');
        this.clients = db.collection('clients');
        resolve(true);

      } catch (e: any){
        reject(e);
      }
    })
    
  }
  
  
  async connection(id: string): Promise<Connection> {
    
    return new Promise( async (resolve, reject) => {
      try {
        let connection = new Connection({
          ...await this.connections.findOne( { _id: new ObjectId(id) } ),
          _users: this.users
        });
        resolve(connection);
      } catch (e) {
        reject(e);
      }
    })
  }

  
  async user(id: string): Promise<User> {
    
    return new Promise( async (resolve, reject) => {
      try {
        let user = new User({
          ...await this.users.findOne( { _id: new ObjectId(id) } ),
          _users: this.users
        });
        resolve(user);
      } catch (e) {
        reject(e);
      }
    })
  }
  
  
  async client(id: string): Promise<Client> {
    
    return new Promise( async (resolve, reject) => {
      try {
        let client = new Client({
          ...await this.clients.findOne( { _id: new ObjectId(id) } ),
          _clients: this.clients
        });
        resolve(client);
      } catch (e) {
        reject(e);
      }
    })
  }
}


/**
 * export a singleton instance of the Mongo class
 */
export const mongo = new Mongo();
