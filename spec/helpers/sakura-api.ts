import {SakuraApi, SakuraApiOptions} from '@sakuraapi/api';
import 'colors';
import {dbs} from './db';
import bodyParser = require('body-parser');

export function testSapi(sapiOptions: SakuraApiOptions): SakuraApi {
  sapiOptions.configPath = sapiOptions.configPath || 'lib/spec/config/environment.json';
  sapiOptions.baseUrl = sapiOptions.baseUrl || '/testApi';

  if (sapiOptions.plugins) {
    for (let plugin of sapiOptions.plugins) {

      if (plugin.plugin.name === 'addAuthenticationAuthority') {
        plugin.options = plugin.options || {};

        plugin.options.authDbConfig = plugin.options.authDbConfig || dbs.authentication;
        plugin.options.userDbConfig = plugin.options.userDbConfig || dbs.user;
      }
    }
  }

  const sapi = new SakuraApi(sapiOptions);
  sapi.addMiddleware(bodyParser.json());

  if (process.env.TRACE_REQ) {
    sapi.addMiddleware((req, res, next) => {
      // tslint:disable:no-console
      console.log(`REQUEST: ${req.method}: ${req.url} (${req.originalUrl}), body: ${JSON.stringify(req.body)}`.blue);
      // tslint:enable:no-console
      next();
    });
  }

  sapi.addLastErrorHandlers((err, req, res, next) => {

    // tslint:disable
    console.log('------------------------------------------------'.red);
    console.log('↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓'.zebra);
    console.log('An error bubbled up in an unexpected way during testing');
    console.log(err);
    console.log('↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑'.zebra);
    console.log('------------------------------------------------'.red);
    // tslint:enable

    next(err);
  });

  return sapi;
}

export function testUrl(endpoint: string, sapi: SakuraApi): string {
  return `${sapi.baseUrl}${endpoint}`;
}
