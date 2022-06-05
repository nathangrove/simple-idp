import { Collection } from "mongodb";
import { MongoDocument } from "./mongo-document";

export class Client extends MongoDocument {
    name: string;

    _clients: Collection<Client>;

}