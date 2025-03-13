
import { Model, DataTypes } from 'sequelize';
import { sequelize } from '../database/sequelize';

export class Authentication extends Model { }

Authentication.init({
  user: {
    type: DataTypes.INTEGER,
    allowNull: false,
    primaryKey: true
  },
  service_provider: {
    type: DataTypes.INTEGER,
    allowNull: false,
    primaryKey: true
  },
  code: {
    type: DataTypes.STRING,
    allowNull: false,
    primaryKey: true
  },
  expires: {
    type: DataTypes.DATE,
    allowNull: false
  }
}, {
  sequelize,
  tableName: 'authentications',
  modelName: 'Authentication'
});