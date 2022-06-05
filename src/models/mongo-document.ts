import { ObjectId } from "mongodb";

export class MongoDocument {

  _id: ObjectId;
  created: Date;
  updated: Date;

  constructor(part: Partial<any>){
    for(const key in part){
      this[key] = part[key];
    }
  }
}