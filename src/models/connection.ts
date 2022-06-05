import { Collection, FindCursor, WithId } from "mongodb";
import { MongoDocument } from "./mongo-document";
import { User } from "./user";

export class Connection extends MongoDocument {
  name: string;
  type: 'DATABASE' | 'LDAP';
  
  _users: Collection<User>;
  
  public async getUsers(): Promise<FindCursor<WithId<User>>> {
    return await this._users.find({ connection: this._id.id })
  }

  public findUserByEmail(email: string): Promise<User> {
    return new Promise( async (resolve, reject) => {
      let user = await this._users.findOne({ email });
      if (!user) reject();
      user = new User({
        ...user,
        _users: this._users
      })
      resolve(user);
    })
  }
  
  public async addUser(user: User): Promise<User | string> {
    return new Promise( async (resolve, reject) => {
      try {
        let newUser = await this._users.insertOne(user);
        if (newUser){
          user._id = newUser.insertedId;
          user._users = this._users;
          resolve(user);
        } else {
          reject('Insert error')
        }
        
      } catch(e) {
        reject(e);
      }
    })
  }
  
}