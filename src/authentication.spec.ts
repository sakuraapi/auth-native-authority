import {IRoutableLocals, SakuraApi} from '@sakuraapi/core';
import {createCipheriv, randomBytes} from 'crypto';
import {Request, Response} from 'express';
import {agent as request} from 'supertest';
import {encode as urlBase64Encode} from 'urlsafe-base64';
import {dbs} from '../spec/helpers/db';
import {testSapi, testUrl} from '../spec/helpers/sakura-api';
import {addAuthenticationAuthority, ICustomTokenResult} from './authentication';

const TEST_DOMAIN = 'default';
const TEST_EMAIL = 'sakura-test@sakuraapi.com';
const TEST_PASSWORD = '123';

describe('addAuthenticationAuthority', () => {

  let sapi: SakuraApi;

  afterEach(async () => {
    if (!sapi) {
      return;
    }

    await sapi
      .dbConnections
      .getDb('user')
      .collection(dbs.user.collection)
      .deleteMany({});

    await sapi.close();
    sapi = null;

  });

  describe('AuthenticationAuthorityApi', () => {

    describe('changePassword', () => {
      const endpoint = '/auth/native/change-password';
      let onChangePasswordEmailRequestCalled = false;
      let onBeforeChangePasswordCalled = false;
      let results: any;

      beforeEach(async () => {

        sapi = testSapi({
          models: [],
          plugins: [{
            options: {
              bcryptHashRounds: 1,
              onChangePasswordEmailRequest: async (user, req, res, domain) => {
                onChangePasswordEmailRequestCalled = true;
                onBeforeChangePasswordCalled = true;
                results = {domain, user};
              },
              onError
            },
            plugin: addAuthenticationAuthority
          }],
          routables: []
        });

        await sapi.listen({bootMessage: ''});

      });

      afterEach(() => {
        onChangePasswordEmailRequestCalled = false;
        onBeforeChangePasswordCalled = false;
      });

      it('returns 400 with invalid body', async () => {
        await request(sapi.app)
          .put(testUrl(endpoint, sapi))
          .expect(400);

      });

      it('returns 401 when user not found', async () => {
        await request(sapi.app)
          .put(testUrl(endpoint, sapi))
          .expect(401)
          .send({
            currentPassword: TEST_PASSWORD,
            email: TEST_EMAIL,
            newPassword: '123'
          });
      });

      it('returns 401 when user password is invalid', async () => {
        await createTestUser(sapi);

        request(sapi.app)
          .put(testUrl(endpoint, sapi))
          .send({
            currentPassword: TEST_PASSWORD + 'fail',
            email: TEST_EMAIL,
            newPassword: '123'
          })
          .expect(401);
      });

      it('calls onChangePasswordEmailRequest when provided', async () => {
        await createTestUser(sapi);

        await request(sapi.app)
          .put(testUrl(endpoint, sapi))
          .send({
            currentPassword: TEST_PASSWORD,
            domain: TEST_DOMAIN,
            email: TEST_EMAIL,
            newPassword: '123'
          })
          .expect(200);

        expect(onChangePasswordEmailRequestCalled).toBeTruthy();
        expect(results.user).toBeDefined();
        expect(results.user.email).toBe(TEST_EMAIL);
        expect(results.domain).toBe(TEST_DOMAIN);

      });

      it('calls onBeforeChangePassword when provided', async () => {
        await createTestUser(sapi);

        await request(sapi.app)
          .put(testUrl(endpoint, sapi))
          .send({
            currentPassword: TEST_PASSWORD,
            domain: TEST_DOMAIN,
            email: TEST_EMAIL,
            newPassword: '123'
          })
          .expect(200);

        expect(onBeforeChangePasswordCalled).toBeTruthy();
        expect(results.user).toBeDefined();
        expect(results.user.email).toBe(TEST_EMAIL);
        expect(results.domain).toBe(TEST_DOMAIN);

      });
    });

    describe('create', () => {
      let onBeforeUserCreateCalled = false;
      let results: any = {};

      beforeEach(async () => {
        sapi = testSapi({
          models: [],
          plugins: [{
            options: {
              bcryptHashRounds: 1,
              onBeforeUserCreate: (req, res, next) => {
                onBeforeUserCreateCalled = true;
                next();
              },
              onUserCreated: async (newUser: any, emailVerificationKey: string, req?: Request, res?: Response, domain?: string) => {
                results = {
                  domain,
                  newUser
                };
              },
              onError
            },
            plugin: addAuthenticationAuthority
          }],
          routables: []
        });

        await sapi.listen({bootMessage: ''});
      });

      afterEach(() => {
        onBeforeUserCreateCalled = false;
        results = null;
      });

      it('returns 400 when missing email', async () => {
        const result = await request(sapi.app)
          .post(testUrl('/auth/native', sapi))
          .expect(400);

        expect(result.body.error).toBe('email address is invalid, check body');
      });

      it('returns 400 when missing password', async () => {

        const result = await request(sapi.app)
          .post(testUrl('/auth/native', sapi))
          .send({
            email: 'test'
          })
          .expect(400);

        expect(result.body.error).toBe('password is invalid, check body');
      });

      it('returns 409 on attempting to create a user that exists', async () => {
        await createTestUser(sapi);

        const result = await request(sapi.app)
          .post(testUrl('/auth/native', sapi))
          .send({
            domain: TEST_DOMAIN,
            email: TEST_EMAIL,
            password: TEST_PASSWORD
          })
          .expect(409);

        expect(result.body.error).toBe('email_in_use');
      });

      it('creates a user', async () => {
        const user = await createTestUser(sapi);

        expect(user).toBeDefined('user was not inserted');
        expect(user.email).toBe(TEST_EMAIL);
        expect(user.emailVerified).toBeFalsy('emailVerified should be false until user verifies');
        expect(user.pw.split('$').length).toBe(4, 'Improperly formatted token, it should be bcrypt hashed');
      });

      it('calls onUserCreated if provided', async () => {
        await createTestUser(sapi);

        expect(results).toBeDefined();
        expect(results.domain).toBe(TEST_DOMAIN);
        expect(results.newUser.email).toBe(TEST_EMAIL);

      });

      it('calls onBeforeUserCreate if provided', async () => {
        await createTestUser(sapi);

        expect(onBeforeUserCreateCalled).toBeTruthy();
      });
    });

    describe('emailVerification', () => {
      const endpoint = '/auth/native/confirm';

      beforeEach(async () => {
        sapi = testSapi({
          models: [],
          plugins: [{
            options: {
              bcryptHashRounds: 1,
              onError
            },
            plugin: addAuthenticationAuthority

          }],
          routables: []
        });

        await sapi.listen({bootMessage: ''});
      });

      it('returns 403 if token is invalid', async () => {
        const result = await request(sapi.app)
          .get(testUrl(`${endpoint}/123`, sapi))
          .expect(403);

        expect(result.body.error).toBe('invalid_token');
      });

      it('returns 403 if it cannot find the user', async () => {

        const token = await encryptToken({userId: '123'}, sapi);

        const result = await request(sapi.app)
          .get(testUrl(`${endpoint}/${token}`, sapi))
          .expect(403);

        expect(result.body.error).toBe('invalid_token');
      });

      it('switches a user to email verified when provided a proper token', async () => {
        const user = await createTestUser(sapi);

        expect(user.emailVerified).toBeFalsy();

        const token = await encryptToken({userId: user._id, test: true}, sapi);

        await request(sapi.app)
          .get(testUrl(`${endpoint}/${token}`, sapi))
          .expect(200);

        const updatedUser = await sapi
          .dbConnections
          .getDb('user')
          .collection(dbs.user.collection)
          .findOne({_id: user._id});

        expect(updatedUser.emailVerified).toBeTruthy();
      });
    });

    describe('forgotPassword', () => {
      const endpoint = '/auth/native/forgot-password';
      let results = null;

      beforeEach(async () => {
        sapi = testSapi({
          models: [],
          plugins: [{
            options: {
              bcryptHashRounds: 1,
              onForgotPasswordEmailRequest: async (user: any, token: string, req?: Request, res?: Response, domain?: string) => {
                results = {
                  domain,
                  token,
                  user
                };
                const locals = res.locals as IRoutableLocals;
                locals.send(222, {pass: true});
              },
              onError
            },
            plugin: addAuthenticationAuthority
          }],
          routables: []
        });

        await sapi.listen({bootMessage: ''});
      });

      afterEach(() => {
        results = null;
      });

      it('calls onForgotPasswordEmailRequest with  user & token null, allowing custom response code', async () => {
        const result = await request(sapi.app)
          .put(testUrl(endpoint, sapi))
          .send({domain: TEST_DOMAIN})
          .expect(222);

        expect(results.domain).toBe(TEST_DOMAIN);
        expect(results.user).toBeUndefined();
        expect(results.token).toBeUndefined();
        expect(result.body.pass).toBeTruthy();
      });

      it('valid request with unknown email/domain calls onForgotPasswordEmailRequest with user & token ' +
        'null, allowing custom response code', async () => {

        const result = await request(sapi.app)
          .put(testUrl(endpoint, sapi))
          .send({
            domain: TEST_DOMAIN,
            email: TEST_EMAIL
          })
          .expect(222);

        expect(results.domain).toBe(TEST_DOMAIN);
        expect(results.user).toBeUndefined();
        expect(results.token).toBeUndefined();
        expect(result.body.pass).toBeTruthy();
      });

      it('generates a forgot password token when provided a valid email', async () => {
        const user = await createTestUser(sapi);

        expect(user.pwResetId).toBeUndefined();

        const result = await request(sapi.app)
          .put(testUrl(endpoint, sapi))
          .send({
            domain: TEST_DOMAIN,
            email: TEST_EMAIL
          })
          .expect(222);

        const updatedUser = await sapi
          .dbConnections
          .getDb('user')
          .collection(dbs.user.collection)
          .findOne({_id: user._id});

        expect(results.domain).toBe(TEST_DOMAIN);
        expect(results.user.id.toString()).toBe(user._id.toString());
        expect(results.token.split('.').length).toBe(3);
        expect(updatedUser.pwResetId).toBeDefined();
        expect(result.body.pass).toBeTruthy();
      });

    });

    describe('login', () => {
      const endpoint = '/auth/native/login';

      let userCreateMeta = {
        emailVerificationKey: null,
        newUser: null
      };

      function onUserCreated(newUser: any, emailVerificationKey: string, req?: Request, res?: Response) {
        userCreateMeta = {
          emailVerificationKey,
          newUser
        };
      }

      describe('response behavior', () => {
        beforeEach(async () => {
          sapi = testSapi({
            models: [],
            plugins: [{
              options: {
                bcryptHashRounds: 1,
                onUserCreated,
                onError
              },
              plugin: addAuthenticationAuthority
            }],
            routables: []
          });

          await sapi.listen({bootMessage: ''});
        });

        it('returns 403 for new user who has not yet confirmed email', async () => {

          await createTestUser(sapi);

          await request(sapi.app)
            .post(testUrl(endpoint, sapi))
            .send({
              domain: TEST_DOMAIN,
              email: TEST_EMAIL,
              password: TEST_PASSWORD
            })
            .expect(403);
        });

        it('returns authentication tokens for authenticated user', async () => {
          await createTestUser(sapi);

          await request(sapi.app)
            .get(testUrl(`/auth/native/confirm/${userCreateMeta.emailVerificationKey}`, sapi))
            .expect(200);

          const result = await request(sapi.app)
            .post(testUrl('/auth/native/login', sapi))
            .send({
              domain: TEST_DOMAIN,
              email: TEST_EMAIL,
              password: TEST_PASSWORD
            });

          const body = result.body;
          const token = body.token['test-issuer'];
          expect(result.status).toBe(200);
          expect(token).toBeDefined();
          expect(token.split('.').length).toBe(3, 'Token should have been JWT formatted');

        });
      });

      describe('onUserLoginSuccess hook', () => {
        let loginSuccessMeta = {
          domain: null,
          jwt: null,
          req: null,
          res: null,
          sapi: null,
          user: null
        };

        let onLoginSuccessFunc;

        function onLoginSuccess(user: any, jwt: any, sApi: SakuraApi, req?: Request, res?: Response, domain?: string): Promise<void> {
          return onLoginSuccessFunc(user, jwt, sApi, req, res, domain);
        }

        beforeEach(async () => {
          sapi = testSapi({
            models: [],
            plugins: [{
              options: {
                bcryptHashRounds: 1,
                onLoginSuccess,
                onUserCreated,
                onError
              },
              plugin: addAuthenticationAuthority
            }],
            routables: []
          });

          await sapi.listen({bootMessage: ''});
        });

        it('onUserLoginSuccess resolve', async () => {

          onLoginSuccessFunc = (user: any, jwt: any, sApi: SakuraApi, req?: Request, res?: Response, domain?: string) => {
            loginSuccessMeta = {user, jwt, sapi: sApi, req, res, domain};
            return Promise.resolve();
          };

          await createTestUser(sapi);

          await request(sapi.app)
            .get(testUrl(`/auth/native/confirm/${userCreateMeta.emailVerificationKey}`, sapi))
            .expect(200);

          await request(sapi.app)
            .post(testUrl('/auth/native/login', sapi))
            .send({
              domain: TEST_DOMAIN,
              email: TEST_EMAIL,
              password: TEST_PASSWORD
            })
            .expect(200);

          expect(loginSuccessMeta.user.constructor.name).toBe('NativeAuthenticationAuthorityUser');
          expect(loginSuccessMeta.sapi.constructor.name).toBe('SakuraApi');
          expect(loginSuccessMeta.req.constructor.name).toBe('IncomingMessage');
          expect(loginSuccessMeta.res.constructor.name).toBe('ServerResponse');
          expect(loginSuccessMeta.jwt['test-issuer']).toBeDefined();
          expect(loginSuccessMeta.domain).toBe(TEST_DOMAIN);

        });

        it('onUserLoginSuccess reject 401', async () => {
          onLoginSuccessFunc = (user: any, jwt: any, sApi: SakuraApi, req?: Request, res?: Response, domain?: string) => {
            loginSuccessMeta = {user, jwt, sapi: sApi, req, res, domain};
            return Promise.reject(401);
          };

          await createTestUser(sapi);

          await request(sapi.app)
            .get(testUrl(`/auth/native/confirm/${userCreateMeta.emailVerificationKey}`, sapi))
            .expect(200);

          await request(sapi.app)
            .post(testUrl('/auth/native/login', sapi))
            .send({
              domain: TEST_DOMAIN,
              email: TEST_EMAIL,
              password: TEST_PASSWORD
            })
            .expect(401);
        });

        it('onUserLoginSuccess reject 403', async () => {
          onLoginSuccessFunc = (user: any, jwt: any, sApi: SakuraApi, req?: Request, res?: Response, domain?: string) => {
            loginSuccessMeta = {user, jwt, sapi: sApi, req, res, domain};
            return Promise.reject(403);
          };

          await createTestUser(sapi);

          await request(sapi.app)
            .get(testUrl(`/auth/native/confirm/${userCreateMeta.emailVerificationKey}`, sapi))
            .expect(200);

          await request(sapi.app)
            .post(testUrl('/auth/native/login', sapi))
            .send({
              domain: TEST_DOMAIN,
              email: TEST_EMAIL,
              password: TEST_PASSWORD
            })
            .expect(403);
        });

        it('onUserLoginSuccess reject sends 500 on non-401/403 reject value', async () => {

          spyOn(console, 'log').and.callFake(() => {
            // noop, suppress expected error from being written to console
          });

          onLoginSuccessFunc = (user: any, jwt: any, sApi: SakuraApi, req?: Request, res?: Response, domain?: string) => {
            loginSuccessMeta = {user, jwt, sapi: sApi, req, res, domain};
            return Promise.reject(778);
          };

          await createTestUser(sapi);

          await request(sapi.app)
            .get(testUrl(`/auth/native/confirm/${userCreateMeta.emailVerificationKey}`, sapi))
            .expect(200);

          await request(sapi.app)
            .post(testUrl('/auth/native/login', sapi))
            .send({
              domain: TEST_DOMAIN,
              email: TEST_EMAIL,
              password: TEST_PASSWORD
            })
            .expect(500);
        });

        it('onUserLoginSuccess reject sends custom error when ' +
          'rejected with {statusCode:number, message:string}', async () => {

          onLoginSuccessFunc = (user: any, jwt: any, sApi: SakuraApi, req?: Request, res?: Response, domain?: string) => {
            loginSuccessMeta = {user, jwt, sapi: sApi, req, res, domain};
            return Promise.reject({statusCode: 777, message: 'test'});
          };

          await createTestUser(sapi);

          await request(sapi.app)
            .get(testUrl(`/auth/native/confirm/${userCreateMeta.emailVerificationKey}`, sapi))
            .expect(200);

          await request(sapi.app)
            .post(testUrl('/auth/native/login', sapi))
            .send({
              domain: TEST_DOMAIN,
              email: TEST_EMAIL,
              password: TEST_PASSWORD
            })
            .expect(777);
        });
      });
      describe('domained-audiences configuration', () => {
        let userCreateResults;
        const sapiConfig = {
          //configPath: 'lib/spec/config/environment-test-domained.json',
          models: [],
          plugins: [{
            options: {
              bcryptHashRounds: 1,
              onUserCreated: async (newUser: any, emailVerificationKey: string, req?: Request, res?: Response, domain?: string) => {
                userCreateResults = {
                  domain,
                  newUser,
                  emailVerificationKey
                };
              },
              onError
            },
            plugin: addAuthenticationAuthority
          }],
          routables: []
        };

        it('returns only domain specific tokens - test 1', async () => {
          sapi = testSapi({configPath: 'lib/spec/config/environment-test-domained.json', ...sapiConfig});
          await sapi.listen({bootMessage: ''});

          const domain = 'domain1';

          await createTestUser(sapi, TEST_EMAIL, TEST_PASSWORD, domain);
          await request(sapi.app)
            .get(testUrl(`/auth/native/confirm/${userCreateResults.emailVerificationKey}/${domain}`, sapi))
            .expect(200);

          const result: any = await request(sapi.app)
            .post(testUrl('/auth/native/login', sapi))
            .send({
              domain,
              email: TEST_EMAIL,
              password: TEST_PASSWORD
            })
            .expect(200);

          const token = result.body.token;

          expect(token['domained-test-issuer'].split('.').length).toBe(3, 'the issuer should have returned its own token');
          expect(token.audience1.split('.').length).toBe(3, 'audience1 should have been included for this domain');
          expect(token.audience2.split('.').length).toBe(3, 'audience2 should have been included for this domain');
          expect(token.audience3.split('.').length).toBe(3, 'audience3 should have been included for this domain');
        });

        it('returns only domain specific tokens - test 2', async () => {
          sapi = testSapi({configPath: 'lib/spec/config/environment-test-domained.json', ...sapiConfig});
          await sapi
            .listen({bootMessage: ''});

          const domain = 'domain2';

          await createTestUser(sapi, TEST_EMAIL, TEST_PASSWORD, domain);
          await request(sapi.app)
            .get(testUrl(`/auth/native/confirm/${userCreateResults.emailVerificationKey}/${domain}`, sapi))
            .expect(200);

          const result: any = await request(sapi.app)
            .post(testUrl('/auth/native/login', sapi))
            .send({
              domain,
              email: TEST_EMAIL,
              password: TEST_PASSWORD
            })
            .expect(200);

          const token = result.body.token;

          expect(token['domained-test-issuer'].split('.').length).toBe(3, 'the issuer should have returned its own token');
          expect(token.audience3.split('.').length).toBe(3, 'audience3 should have been included for this domain');
          expect(token.audience1).toBeUndefined('audience1 should not have been included for this domain');
          expect(token.audience2).toBeUndefined('audience2 should not have been included for this domain');
        });
      });
    });

    describe('newEmailVerificationKey', () => {

      const endpoint = '/auth/native/confirm';
      let results = null;

      beforeEach(async () => {
        sapi = testSapi({
          models: [],
          plugins: [{
            options: {
              bcryptHashRounds: 1,
              onResendEmailConfirmation: async (user, key, req, res, domain) => {
                results = {
                  domain,
                  key,
                  user
                };
                const locals = res.locals as IRoutableLocals;
                locals.send(222, {pass: true});
              },
              onError
            },
            plugin: addAuthenticationAuthority
          }],
          routables: []
        });

        await sapi.listen({bootMessage: ''});
      });

      it('allows integrator to return whatever if account invalid', async () => {

        const result: any = await request(sapi.app)
          .post(testUrl(endpoint, sapi))
          .send({
            domain: TEST_DOMAIN,
            email: TEST_EMAIL
          })
          .expect(222);

        expect(result.body.pass).toBeTruthy();
        expect(results.domain).toBe(TEST_DOMAIN);
        expect(results.key).toBe('');
        expect(results.user).toBeNull();
      });

      it('generates key for valid user', async () => {

        const user = await createTestUser(sapi);
        const result: any = await request(sapi.app)
          .post(testUrl(endpoint, sapi))
          .send({
            domain: TEST_DOMAIN,
            email: TEST_EMAIL
          })
          .expect(222);

        expect(result.body.pass).toBeTruthy();
        expect(results.domain).toBe(TEST_DOMAIN);
        expect(results.key.split('.').length).toBe(3);
        expect(results.user.id.toString()).toBe(user._id.toString());

      });
    });

    describe('resetPassword', async () => {
      const endpoint = '/auth/native/reset-password';
      let token = null;

      beforeEach(async () => {
        sapi = testSapi({
          models: [],
          plugins: [{
            options: {
              bcryptHashRounds: 1,
              onForgotPasswordEmailRequest: async (user, tkn) => {
                token = tkn;
              },
              onError
            },
            plugin: addAuthenticationAuthority
          }],
          routables: []
        });

        await sapi.listen({bootMessage: ''});
      });

      afterEach(() => token = null);

      it('returns 400 if password field is missing', async () => {
        const tkn = '123';

        const result: any = await request(sapi.app)
          .put(testUrl(`${endpoint}/${tkn}`, sapi))
          .expect(400);

        expect(result.body.error).toBe('bad_request');
      });

      it('returns 403 if token is invalid', async () => {
        const tkn = '123';

        const result: any = await request(sapi.app)
          .put(testUrl(`${endpoint}/${tkn}`, sapi))
          .expect(403)
          .send({
            password: TEST_PASSWORD
          });

        expect(result.body.error).toBe('invalid_token');
      });

      it('returns 403 if token is expired', async () => {
        const tkn = await encryptToken({issued: 0}, sapi);

        const result: any = await request(sapi.app)
          .put(testUrl(`${endpoint}/${tkn}`, sapi))
          .expect(403)
          .send({
            password: TEST_PASSWORD
          });

        expect(result.body.error).toBe('invalid_token');
      });

      it('returns 403 if user record does not having matching token hash', async () => {

        const user = await createTestUser(sapi);

        // get password reset token
        await request(sapi.app)
          .put(testUrl(`/auth/native/forgot-password`, sapi))
          .send({
            domain: TEST_DOMAIN,
            email: TEST_EMAIL
          })
          .expect(200);

        await sapi
          .dbConnections
          .getDb('user')
          .collection(dbs.user.collection)
          .updateOne({_id: user._id}, {$unset: {pwResetId: ''}});

        const result: any = await request(sapi.app)
          .put(testUrl(`${endpoint}/${token}`, sapi))
          .send({
            password: TEST_PASSWORD
          })
          .expect(403);

        expect(result.body.error).toBe('invalid_token');
      });

      it('updates the user password', async () => {

        const user = await createTestUser(sapi);

        // get password reset token
        await request(sapi.app)
          .put(testUrl(`/auth/native/forgot-password`, sapi))
          .send({
            domain: TEST_DOMAIN,
            email: TEST_EMAIL
          })
          .expect(200);

        const result: any = await request(sapi.app)
          .put(testUrl(`${endpoint}/${token}`, sapi))
          .send({
            password: TEST_PASSWORD + 'new'
          })
          .expect(200);

        await request(sapi.app)
          .post(testUrl('/auth/native/login', sapi))
          .send({
            domain: TEST_DOMAIN,
            email: TEST_EMAIL,
            password: TEST_PASSWORD
          })
          .expect(401);

        await request(sapi.app)
          .post(testUrl('/auth/native/login', sapi))
          .send({
            domain: TEST_DOMAIN,
            email: TEST_EMAIL,
            password: TEST_PASSWORD + 'new'
          })
          .expect(200);
      });

    });
  });

  describe('AuthenticationAuthorityApi onInjectCustomToken token customization', () => {
    let userCreateMeta = {
      emailVerificationKey: null,
      newUser: null
    };

    beforeEach(async () => {
      sapi = testSapi({
        models: [],
        plugins: [{
          options: {
            bcryptHashRounds: 1,
            onInjectCustomToken,
            onUserCreated,
            onError
          },
          plugin: addAuthenticationAuthority
        }],
        routables: []
      });

      await sapi.listen({bootMessage: ''});

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

      it('returns custom tokens for authenticated user', async () => {
        await request(sapi.app)
          .post(testUrl('/auth/native', sapi))
          .send({
            email,
            password
          })
          .expect(200);

        await request(sapi.app)
          .get(testUrl(`/auth/native/confirm/${userCreateMeta.emailVerificationKey}`, sapi))
          .expect(200);

        const result = await request(sapi.app)
          .post(testUrl('/auth/native/login', sapi))
          .send({
            email,
            password
          })
          .expect(200);

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

      });
    });
  });
});

function createTestUser(sapi: SakuraApi, email = TEST_EMAIL, password = TEST_PASSWORD, domain = TEST_DOMAIN): Promise<any> {
  return request(sapi.app)
    .post(testUrl('/auth/native', sapi))
    .send({
      domain,
      email,
      password
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
    });
}

function encryptToken(keyContent: { [key: string]: any }, sapi: SakuraApi): Promise<string> {
  return new Promise((resolve, reject) => {
    try {
      const iv = randomBytes(16);
      let cipher;

      try {
        cipher = createCipheriv('aes-256-gcm', sapi.config.authentication.jwt.key, iv);
      } catch (err) {
        throw new Error(`Invalid JWT private key set in SakuraApi's authorization.jwt.key setting: ${err}`);
      }

      const emailKeyBuffer = Buffer.concat([
        cipher.update(JSON.stringify(keyContent), 'utf8'),
        cipher.final()
      ]);
      const emailKeyHMACBuffer = cipher.getAuthTag();

      resolve(`${urlBase64Encode(emailKeyBuffer)}.${urlBase64Encode(emailKeyHMACBuffer)}.${urlBase64Encode(iv)}`);
    } catch (err) {
      reject(err);
    }
  });
}

async function onError(err) {
  console.log(`unexpecetd auth error------------------------`.red);
  console.log(err);
  console.log(`^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^`.red);
}
