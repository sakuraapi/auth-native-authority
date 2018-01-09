import {SakuraApi}        from '@sakuraapi/api';
import {
  Request,
  Response
}                         from 'express';
import {agent as request} from 'supertest';
import {dbs}              from '../spec/helpers/db';
import {
  testSapi,
  testUrl
}                         from '../spec/helpers/sakura-api';
import {
  addAuthenticationAuthority,
  ICustomTokenResult
}                         from './authentication';

// tslint:disable:no-shadowed-variable
describe('addAuthenticationAuthority', () => {

  describe('AuthenticationAuthorityApi', () => {

    describe('create', () => {
      let sapi;

      beforeEach((done) => {
        sapi = testSapi({
          models: [],
          plugins: [{
            plugin: addAuthenticationAuthority
          }],
          routables: []
        });

        sapi
          .listen({bootMessage: ''})
          .then(() => {
            return sapi
              .dbConnections
              .getDb('user')
              .collection(dbs.user.collection)
              .deleteMany({});
          })
          .then(done)
          .catch(done.fail);
      });

      afterEach((done) => {
        sapi
          .close()
          .then(done)
          .catch(done.fail);
      });

      it('inserts a user when the create endpoint is called', (done) => {
        request(sapi.app)
          .post(testUrl('/auth/native', sapi))
          .send({
            email: 'sakura-test@sakuraapi.com',
            password: '123'
          })
          .expect(200)
          .then(() => {
            return sapi
              .dbConnections
              .getDb('user')
              .collection(dbs.user.collection)
              .find({})
              .limit(1)
              .next();
          })
          .then((user) => {
            expect(user).toBeDefined('user was not inserted');
            expect(user.email).toBe('sakura-test@sakuraapi.com');
            expect(user.emailVerified).toBeFalsy('emailVerified should be false until user verifies');
            expect(user.pw.split('$').length).toBe(4, 'Improperly formatted token, it should be bcrypt hashed');
          })
          .then(done)
          .catch(done.fail);
      });

      it('returns 400 when missing required fields', (done) => {
        request(sapi.app)
          .post(testUrl('/auth/native', sapi))
          .expect(400)
          .then(done)
          .catch(done.fail);
      });
    });

    describe('login', () => {
      const email = 'sakura-test@sakuraapi.com';
      const password = '123';

      let sapi;
      let userCreateMeta = {
        emailVerificationKey: null,
        newUser: null
      };

      afterEach((done) => {
        sapi
          .close()
          .then(done)
          .catch(done.fail);
      });

      function onUserCreated(newUser: any, emailVerificationKey: string, req?: Request, res?: Response) {
        userCreateMeta = {
          emailVerificationKey,
          newUser
        };
      }

      describe('response behavior', () => {
        beforeEach((done) => {
          sapi = testSapi({
            models: [],
            plugins: [{
              options: {
                onUserCreated
              },
              plugin: addAuthenticationAuthority
            }],
            routables: []
          });

          sapi
            .listen({bootMessage: ''})
            .then(() => {
              return sapi
                .dbConnections
                .getDb('user')
                .collection(dbs.user.collection)
                .deleteMany({});
            })
            .then(done)
            .catch(done.fail);
        });

        it('returns 403 for new user who has not yet confirmed email', (done) => {
          request(sapi.app)
            .post(testUrl('/auth/native', sapi))
            .send({
              email,
              password
            })
            .expect(200)
            .then(() => {
              return request(sapi.app)
                .post(testUrl('/auth/native/login', sapi))
                .send({
                  email,
                  password
                })
                .expect(403);
            })
            .then(done)
            .catch(done.fail);
        });

        it('returns authentications tokens for authenticated user', (done) => {
          request(sapi.app)
            .post(testUrl('/auth/native', sapi))
            .send({
              email,
              password
            })
            .expect(200)
            .then(() => {
              return request(sapi.app)
                .get(testUrl(`/auth/native/confirm/${userCreateMeta.emailVerificationKey}`, sapi))
                .expect(200);
            })
            .then(() => {
              return request(sapi.app)
                .post(testUrl('/auth/native/login', sapi))
                .send({
                  email,
                  password
                })
                .expect(200);
            })
            .then((result) => {
              const body = result.body;
              const token = result.body.token['test-issuer'];
              expect(token).toBeDefined();
              expect(token.split('.').length).toBe(3, 'Token should have been JWT formatted');
            })
            .then(done)
            .catch(done.fail);
        });
      });

      describe('onUserLoginSuccess', () => {
        let loginSuccessMeta = {
          jwt: null,
          req: null,
          res: null,
          sapi: null,
          user: null
        };

        let onLoginSuccessFunc;

        function onLoginSuccess(user: any, jwt: any, sapi: SakuraApi, req?: Request, res?: Response): Promise<void> {
          return onLoginSuccessFunc(user, jwt, sapi, req, res);
        }

        beforeEach((done) => {
          sapi = testSapi({
            models: [],
            plugins: [{
              options: {
                onLoginSuccess,
                onUserCreated
              },
              plugin: addAuthenticationAuthority
            }],
            routables: []
          });

          sapi
            .listen({bootMessage: ''})
            .then(() => {
              return sapi
                .dbConnections
                .getDb('user')
                .collection(dbs.user.collection)
                .deleteMany({});
            })
            .then(done)
            .catch(done.fail);
        });

        it('onUserLoginSuccess resolve', (done) => {

          onLoginSuccessFunc = (user: any, jwt: any, sapi: SakuraApi, req?: Request, res?: Response) => {
            loginSuccessMeta = {user, jwt, sapi, req, res};
            return Promise.resolve();
          };

          request(sapi.app)
            .post(testUrl('/auth/native', sapi))
            .send({
              email,
              password
            })
            .expect(200)
            .then(() => {
              return request(sapi.app)
                .get(testUrl(`/auth/native/confirm/${userCreateMeta.emailVerificationKey}`, sapi))
                .expect(200);
            })
            .then(() => {
              return request(sapi.app)
                .post(testUrl('/auth/native/login', sapi))
                .send({
                  email,
                  password
                })
                .expect(200);
            })
            .then(() => {
              expect(loginSuccessMeta.user.constructor.name).toBe('NativeAuthenticationAuthorityUser');
              expect(loginSuccessMeta.sapi.constructor.name).toBe('SakuraApi');
              expect(loginSuccessMeta.req.constructor.name).toBe('IncomingMessage');
              expect(loginSuccessMeta.res.constructor.name).toBe('ServerResponse');
              expect(loginSuccessMeta.jwt['test-issuer']).toBeDefined();
            })
            .then(done)
            .catch(done.fail);
        });

        it('onUserLoginSuccess reject 401', (done) => {
          onLoginSuccessFunc = (user: any, jwt: any, sapi: SakuraApi, req?: Request, res?: Response) => {
            loginSuccessMeta = {user, jwt, sapi, req, res};
            return Promise.reject(401);
          };

          request(sapi.app)
            .post(testUrl('/auth/native', sapi))
            .send({
              email,
              password
            })
            .expect(200)
            .then(() => {
              return request(sapi.app)
                .get(testUrl(`/auth/native/confirm/${userCreateMeta.emailVerificationKey}`, sapi))
                .expect(200);
            })
            .then(() => {
              return request(sapi.app)
                .post(testUrl('/auth/native/login', sapi))
                .send({
                  email,
                  password
                })
                .expect(401);
            })
            .then(done)
            .catch(done.fail);
        });

        it('onUserLoginSuccess reject 403', (done) => {
          onLoginSuccessFunc = (user: any, jwt: any, sapi: SakuraApi, req?: Request, res?: Response) => {
            loginSuccessMeta = {user, jwt, sapi, req, res};
            return Promise.reject(403);
          };

          request(sapi.app)
            .post(testUrl('/auth/native', sapi))
            .send({
              email,
              password
            })
            .expect(200)
            .then(() => {
              return request(sapi.app)
                .get(testUrl(`/auth/native/confirm/${userCreateMeta.emailVerificationKey}`, sapi))
                .expect(200);
            })
            .then(() => {
              return request(sapi.app)
                .post(testUrl('/auth/native/login', sapi))
                .send({
                  email,
                  password
                })
                .expect(403);
            })
            .then(done)
            .catch(done.fail);

        });

        it('onUserLoginSuccess reject sends 500 on non-401/403 reject value', (done) => {
          onLoginSuccessFunc = (user: any, jwt: any, sapi: SakuraApi, req?: Request, res?: Response) => {
            loginSuccessMeta = {user, jwt, sapi, req, res};
            return Promise.reject(778);
          };

          request(sapi.app)
            .post(testUrl('/auth/native', sapi))
            .send({
              email,
              password
            })
            .expect(200)
            .then(() => {
              return request(sapi.app)
                .get(testUrl(`/auth/native/confirm/${userCreateMeta.emailVerificationKey}`, sapi))
                .expect(200);
            })
            .then(() => {
              return request(sapi.app)
                .post(testUrl('/auth/native/login', sapi))
                .send({
                  email,
                  password
                })
                .expect(500);
            })
            .then(done)
            .catch(done.fail);
        });

        it('onUserLoginSuccess reject sends custom error when ' +
          'rejected with {statusCode:number, message:string}', (done) => {
          onLoginSuccessFunc = (user: any, jwt: any, sapi: SakuraApi, req?: Request, res?: Response) => {
            loginSuccessMeta = {user, jwt, sapi, req, res};
            return Promise.reject({statusCode: 777, message: 'test'});
          };

          request(sapi.app)
            .post(testUrl('/auth/native', sapi))
            .send({
              email,
              password
            })
            .expect(200)
            .then(() => {
              return request(sapi.app)
                .get(testUrl(`/auth/native/confirm/${userCreateMeta.emailVerificationKey}`, sapi))
                .expect(200);
            })
            .then(() => {
              return request(sapi.app)
                .post(testUrl('/auth/native/login', sapi))
                .send({
                  email,
                  password
                })
                .expect(777);
            })
            .then(done)
            .catch(done.fail);
        });
      });
    });
  });

  describe('AuthenticationAuthorityApi onInjectCustomToken token customization', () => {
    let sapi;
    let userCreateMeta = {
      emailVerificationKey: null,
      newUser: null
    };

    beforeEach((done) => {
      sapi = testSapi({
        models: [],
        plugins: [{
          options: {
            onInjectCustomToken,
            onUserCreated
          },
          plugin: addAuthenticationAuthority
        }],
        routables: []
      });

      sapi
        .listen({bootMessage: ''})
        .then(() => {
          return sapi
            .dbConnections
            .getDb('user')
            .collection(dbs.user.collection)
            .deleteMany({});
        })
        .then(done)
        .catch(done.fail);
    });

    afterEach((done) => {
      sapi
        .close()
        .then(done)
        .catch(done.fail);
    });

    function onUserCreated(newUser: any, emailVerificationKey: string, req?: Request, res?: Response) {
      userCreateMeta = {
        emailVerificationKey,
        newUser
      };
    }

    function onInjectCustomToken(token: any, key: string, issuer: string,
                                 expiration: string, payload: any, jwtId: string): Promise<ICustomTokenResult[]> {
      return new Promise((resolve, reject) => {
        resolve([{
          audience: 'third-party-audience.com',
          token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
          'eyJ1c2VyIjoiMTIzMTIzIiwiYXBpU2VjcmV0IjoiMzIxMzIxLTMyMS0zMjEtMzIxLTMyMSIsImlhdCI6MTQ4MTE0OTAwMn0.' +
          'Ds_WzcGI4tVq2oqSical36Ej0L12BC6UA-yCUzAfnd4',
          unEncodedToken: {
            apiSecret: '321321-321-321-321-321',
            iat: 1481149002,
            user: '123123'
          }
        }]);
      });
    }

    describe('login', () => {
      const email = 'sakura-test@sakuraapi.com';
      const password = '123';

      it('returns custom tokens for authenticated user', (done) => {
        request(sapi.app)
          .post(testUrl('/auth/native', sapi))
          .send({
            email,
            password
          })
          .expect(200)
          .then(() => {
            return request(sapi.app)
              .get(testUrl(`/auth/native/confirm/${userCreateMeta.emailVerificationKey}`, sapi))
              .expect(200);
          })
          .then(() => {
            return request(sapi.app)
              .post(testUrl('/auth/native/login', sapi))
              .send({
                email,
                password
              })
              .expect(200);
          })
          .then((result) => {
            const body = result.body;
            const testIssuer = body.token['test-issuer'];
            const testAudience = body.token['test-audience'];
            const thirdPartyAudience = body.token['third-party-audience.com'];

            expect(testIssuer).toBeDefined();
            expect(testIssuer.split('.').length).toBe(3, 'Token should have been JWT formatted');

            expect(testAudience).toBeDefined();
            expect(testAudience.split('.').length).toBe(3, 'Token should have been JWT formatted');

            expect(thirdPartyAudience).toBeDefined();
            expect(thirdPartyAudience.split('.').length).toBe(3, 'Token should have been JWT formatted');
            expect(thirdPartyAudience).toBe('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
              '.eyJ1c2VyIjoiMTIzMTIzIiwiYXBpU2VjcmV0IjoiMzIxMzIxLTMyMS0zMjEtMzIxLTMyMSIsImlhdCI6MTQ4MTE0OTAwMn0' +
              '.Ds_WzcGI4tVq2oqSical36Ej0L12BC6UA-yCUzAfnd4');
          })
          .then(done)
          .catch(done.fail);
      });
    });
  });
});
// tslint:enable:no-shadowed-variable
