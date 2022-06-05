import { compareSync, genSaltSync, hashSync } from "bcrypt";
import { Collection } from "mongodb";
import { MongoDocument } from "./mongo-document";

export class User extends MongoDocument {
  fname: string;
  lname: string;
  connection: string;
  email: string;
  password: string;
  approvedClients: any; 
  
  _users: Collection<User>;
  

  public checkPassword(password: string): boolean {
    return compareSync(password, this.password);
  }
  
  public async changePassword(password: string): Promise<string> {
    let salt = genSaltSync(10);
    let hash = hashSync(password, salt);
    this.password = hash;
    return await this.update();
  }
  
  public async update(): Promise<string> {
    return new Promise( async (resolve, reject) => {

      try {

        this._users.updateOne({ _id: this._id }, { $set: { 
          password: this.password,
          fname: this.fname,
          lname: this.lname,
          connection: this.connection,
          email: this.email,
          approvedClients: this.approvedClients
        }}).then( () => {

          resolve(null);
          
        }).catch( e => {
          reject(e);
        });

      } catch (error: any) {
        reject(error)
      }
    });
  }
  
}