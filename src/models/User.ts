import { Model, DataTypes } from 'sequelize';
import { sequelize } from '../database/sequelize';

export class User extends Model { };

User.init({
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false
  }
}, {
  sequelize,
  tableName: 'users',
  modelName: 'User'
})
