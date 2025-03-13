
import { Model, DataTypes } from 'sequelize';
import { sequelize } from '../database/sequelize';

export class ServiceProvider extends Model { }

ServiceProvider.init({
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false
  },
  client_id: {
    type: DataTypes.STRING,
    allowNull: false
  },
  client_secret: {
    type: DataTypes.STRING,
    allowNull: false
  },
  redirect_uri: {
    type: DataTypes.STRING,
    allowNull: false
  },
  default_redirect_uri: {
    type: DataTypes.STRING,
    allowNull: true
  }
}, {
  sequelize,
  tableName: 'service_providers',
  modelName: 'ServiceProvider'
});