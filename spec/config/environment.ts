module.exports = {
  dbConnections: [
    {
      mongoClientOptions: {},
      name: 'greeting',
      url: `mongodb://${process.env.TEST_MONGO_DB_ADDRESS}:${process.env.TEST_MONGO_DB_PORT}/greeting`
    }
  ]
};
