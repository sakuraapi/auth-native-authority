import {dbs} from '../helpers/db';

module.exports = {
  dbConnections: [
    {
      mongoClientOptions: {},
      name: dbs.authentication.db,
      url: `mongodb://${process.env.TEST_MONGO_DB_ADDRESS}:${process.env.TEST_MONGO_DB_PORT}/user`
    }, {
      mongoClientOptions: {},
      name: dbs.user.db,
      url: `mongodb://${process.env.TEST_MONGO_DB_ADDRESS}:${process.env.TEST_MONGO_DB_PORT}/user`
    }
  ]
};
