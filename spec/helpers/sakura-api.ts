import {
  SakuraApi,
  SakuraApiOptions
}             from '@sakuraapi/core';
import {json} from 'body-parser';
import 'colors';
import {dbs}  from './db';

process.on('uncaughtException', (r) => {
  // tslint:disable:no-console
  console.log('Unhandled Rejection'.red.underline);
  console.log('-'.repeat((process.stdout as any).columns).red);
  console.log('↓'.repeat((process.stdout as any).columns).zebra.red);
  console.log('-'.repeat((process.stdout as any).columns).red);
  console.log(r);
  console.log('-'.repeat((process.stdout as any).columns).red);
  console.log('↑'.repeat((process.stdout as any).columns).zebra.red);
  console.log('-'.repeat((process.stdout as any).columns).red);
  // tslint:enable:no-console
  throw r;
});

process.on('unhandledRejection', (r) => {
  // tslint:disable:no-console
  console.log('Unhandled Rejection'.red.underline);
  console.log('-'.repeat((process.stdout as any).columns).red);
  console.log('↓'.repeat((process.stdout as any).columns).zebra.red);
  console.log('-'.repeat((process.stdout as any).columns).red);
  console.log(r);
  console.log('-'.repeat((process.stdout as any).columns).red);
  console.log('↑'.repeat((process.stdout as any).columns).zebra.red);
  console.log('-'.repeat((process.stdout as any).columns).red);
  // tslint:enable:no-console
  throw r;
});

export function testSapi(sapiOptions: SakuraApiOptions): SakuraApi {
  sapiOptions.configPath = sapiOptions.configPath || 'lib/spec/config/environment.json';
  sapiOptions.baseUrl = sapiOptions.baseUrl || '/testApi';

  if (sapiOptions.plugins) {
    for (const plugin of sapiOptions.plugins) {

      if (plugin.plugin.name === 'addAuthenticationAuthority') {
        plugin.options = plugin.options || {};

        plugin.options.authDbConfig = plugin.options.authDbConfig || dbs.authentication;
        plugin.options.userDbConfig = plugin.options.userDbConfig || dbs.user;
      }
    }
  }

  const sapi = new SakuraApi(sapiOptions);
  sapi.addMiddleware(json());

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
