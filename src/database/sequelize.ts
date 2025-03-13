import { Sequelize } from 'sequelize';

export const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: ':memory:',
  logging: process.env.NODE_ENV === 'development' ? console.log : false
});
