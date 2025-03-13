
import { Model, DataTypes } from 'sequelize';
import { sequelize } from '../database/sequelize';
import { ServiceProvider } from './ServiceProvider';
import { User } from './User';

export class Authorization extends Model { }

Authorization.init({
  scopes: {
    type: DataTypes.STRING,
    allowNull: true
  }
}, {
  sequelize,
  tableName: 'authorizations',
  modelName: 'Authorization'
});

ServiceProvider.belongsToMany(User, {
  through: Authorization,
  foreignKey: 'service_provider'
});

User.belongsToMany(ServiceProvider, {
  through: Authorization,
  foreignKey: 'user'
});
