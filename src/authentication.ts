import {
  Db,
  IRoutableLocals,
  Json,
  Model,
  Routable,
  Route,
  SakuraApi,
  SakuraApiModel,
  SakuraApiPluginResult,
  SakuraApiRoutable
} from '@sakuraapi/api';
import {compare, hash as bcryptHash} from 'bcrypt';
import {createCipheriv, createDecipheriv, createHash, createHmac, randomBytes} from 'crypto';
import {Handler, NextFunction, Request, Response} from 'express';
import {decode as decodeToken, sign as signToken} from 'jsonwebtoken';
import {ObjectID} from 'mongodb';
import {decode as urlBase64Decode, encode as urlBase64Encode, validate as urlBase64Validate} from 'urlsafe-base64';
import {v4 as uuid} from 'uuid';
import pwStrength = require('zxcvbn');

const IV_LENGTH = 16;

/**
 * The shame of objects resolved in the Promise returned from [[IAuthenticationAuthorityOptions.onInjectCustomToken]].
 */
export interface ICustomTokenResult {
  /**
   * The JWT audience this token is being issued for.
   */
  audience: string;
  /**
   * The JWT (or really anything if your client knows how to deal with it).
   */
  token: string;
  /**
   * The JWT in its unencoded form. `auth-native-authority` logs tokens in the database upon their creation.
   * If you include `unEncodedToken`, it will log that. Otherwise, it logs the encoded token.
   */
  unEncodedToken?: any;
}

/**
 * Various options that can be set for initializing the AuthNativeAuthorityApi Module
 */
export interface IAuthenticationAuthorityOptions {
  /**
   * The database where authTokens are stored so that you have a record of tokes that are issued.
   */
  authDbConfig: {
    collection: string
    db: string;
  };

  /**
   * The exponent portion of how many rounds of hashing that bcrypt should go through. Defaults to 12 if not set. See:
   * https://github.com/kelektiv/node.bcrypt.js
   *
   * Set this to something high enough to thwart brute force attacks, but not so high that you cripple your server(s) under
   * the computational load.
   */
  bcryptHashRounds?: number;

  /**
   * Configuration for user creation
   */
  create?: {
    /**
     * An object of key / value pairs defining custom fields to store in the user collectiion. By default email and password
     * are stored (they're required) and domain is stored (if the feature is enabled). The keys should be the expected field
     * names in the json body. The values should be the database field names where the field should be stored. If you want to
     * have custom validation or manipulation of these fields, use [[onBeforeUserCreate]] and modify the `res.locals.reqBody`
     * object.
     */
    acceptFields?: any;
  };

  /**
   * If set, the system will require email & domain to login the user (a user can belong to multiple domains). If the domain
   * is not provided, this default value is substituted when looking up the user.
   */
  defaultDomain?: string;

  /**
   * Optionally override the various endpoints that make up the different parts of the native auth API. By default,
   * the following endpoints are assigned:
   *
   *    changePassword:          [put] auth/native/change-password
   *    create:                  [post] auth/native
   *    emailVerification:       [get] auth/native/confirm/:token
   *    forgotPassword:          [put] auth/native/forgot-password
   *    login:                   [post] auth/native/login
   *    newEmailVerificationKey: [post] auth/native/confirm
   *    resetPassword:           [put] auth/native/reset-password/:token
   *
   *    Remember, these are always built "on top" of your base url set in SakuraApi.
   *
   *    Note: if you don't include `:token` in `emailVerification` and `resetPassword`, you're going to have
   *    a bad time.
   */
  endpoints?: {
    changePassword?: string;
    create?: string;
    emailVerification?: string;
    forgotPassword?: string;
    login?: string;
    newEmailVerificationKey?: string;
    resetPassword?: string;
  };

  /**
   * Lets you override the DB and JSON field names that the auth-native-authority plugin uses.
   */
  model?: {
    email?: {
      dbField?: string;
      jsonField?: string;
    },
    domain?: {
      dbField?: string;
      jsonField?: string;
    },
    password?: {
      dbField?: string;
    },
    emailVerified?: {
      dbField?: string;
      jsonField?: string;
    },
    emailVerificationKey?: {
      dbField?: string;
      jsonField?: string;
    },
    passwordResetHash?: {
      dbField?: string;
    },
    lastLoginDb?: {
      dbField?: string;
    },
    passwordStrength?: {
      dbField?: string;
    }
  };

  /**
   * Accepts a Express Handler, or an array of them, to run before user creation. This is helpful if you want to do
   * custom validation.
   */
  onBeforeUserCreate?: Handler | Handler[];

  /**
   * Called when the user changes his or her password, allowing the integrator to send an email
   * to the user notifying them of the password change.
   * @param user
   */
  onChangePasswordEmailRequest?: (user: any, req?: Request, res?: Response) => Promise<any>;

  /**
   * Called when the user requests a "forgot password" email. It will generate a one time use password reset token. Only the
   * last one used is valid and it must be used within the time-to-live.
   * @param user
   * @param token
   */
  onForgotPasswordEmailRequest: (user: any, token: string, req?: Request, res?: Response) => Promise<any>;

  /**
   * Receives the current payload and the current db results from the user lookup. If you implement this, you should
   * modify the payload with whatever fields you need then resolve the promise with the new payload as the value. This
   * allows you to insert additional information in the resulting JWT token from whatever source you deem appropriate.
   * @param payload
   * @param dbResult
   */
  onJWTPayloadInject?: (payload: any, dbResult: any) => Promise<any>;

  /**
   * Called when a user has successfully logged in. Do whatever you need to, then either resolve the promise to
   * continue, or reject the promise with either the number 401 or 403 to send an unauthorized or forbidden
   * response. Any other rejection value will result in a 500. You can also reject with {statusCode:number,
   * message:string} to have the plugin send the statusCode and message as the response message.
   * @returns {Promise<void>}
   */
  onLoginSuccess?: (user: any, jwt: any, sapi: SakuraApi, req?: Request, res?: Response) => Promise<void>;

  /**
   * Called when the user needs the email verification key resent.. note that
   * @param user note: if the requested user doesn't exist, this will be undefined
   * @param emailVerificationKey note: if the requested user doesn't exist, this will be undefined
   */
  onResendEmailConfirmation: (user: any, emailVerificationKey: string, req?: Request, res?: Response) => Promise<any>;

  /**
   * If implemented, allows custom tokens to be included in the token dictionary sent back to an authenticated user
   * upon login.
   *
   * @param token The current token dictionary that's being returned to the authenticated user. This will contain the
   * tokens generated up to this point.
   * @param {string} key The private key that was used to generate the tokens in the token dictionary
   * @param {string} issuer The issuer that was used to generate the tokens in the token dictionary
   * @param {string} expiration The expiration that was used to generate the tokens in the token dictionary
   * @param payload The payload of the tokens generated in the token dictionary
   * @param {string} jwtId The id that was assigned to the tokens in the token dictionary up to this point
   * @returns {Promise<ICustomTokenResult[]>} A promise that should resolve an array of ICustomTokenResult which will
   * be used to add your custom tokens to the token dictionary returned to the user.
   */
  onInjectCustomToken?: (token: any, key: string, issuer: string, expiration: string, payload: any, jwtId: string)
    => Promise<ICustomTokenResult[]>;

  /**
   * Receives an object of the user just created. Of greatest importance here is validation key. You need to generate
   * an email and send that to the user in order for them to verify that they have access to the email address they're
   * claiming.
   * @param newUser an object of the user just created, minus the hashed password field.
   */
  onUserCreated: (newUser: any, emailVerificationKey: string, req?: Request, res?: Response) => Promise<any>;

  /**
   * The same database configuration that you're using for your model that represents the collection of MongoDB documents that
   * store your users.
   */
  userDbConfig: {
    collection: string
    db: string;
  };
}

/**
 * Adds native authentication (email, password, domain) settings to your SakuraApi application.
 *
 * ### Example (sakura-api.ts)
 * <pre>
 *    ...
 *    addAuthenticationAuthority(sapi, {
 *      dbConfig: dbs.user
 *    });
 *    ...
 * </pre>
 *
 * This will add several endpoints to your server (subordinate to sapi.baseUrl):
 * * POST auth/native - attempts to authenticate a user based on the credentials provided and returns a JWT if authentication
 *   succeeds.
 *
 *   body content: {
 *      email: string,
 *      password: string,
 *      domain: string
 *   }
 *
 *
 * @param sapi your server's SakuraApi instance.
 * @param options
 */
export function addAuthenticationAuthority(sapi: SakuraApi, options: IAuthenticationAuthorityOptions): SakuraApiPluginResult {

  const endpoints = options.endpoints || {};

  if (!sapi) {
    throw new Error('auth-native-authority must have a valid instance of SakuraApi');
  }

  if (!options.userDbConfig || !options.userDbConfig.db || !options.userDbConfig.collection) {
    throw new Error('auth-native-authority addAuthenticationAuthority options parameter must have a valid ' +
      `'userDbConfig' configuration in 'IAuthenticationAuthorityOptions. Provided options ${JSON.stringify(options)}`);
  }

  // note, though sapi.config.native is overridden by the options parameter, and the dbConfig must always come from the
  // options parameter.
  const nativeAuthConfig = ((sapi.config.authentication || {} as any).native || null) as IAuthenticationAuthorityOptions;
  const jwtAuthConfig = (sapi.config.authentication || {} as any).jwt || null;

  if (!nativeAuthConfig) {
    throw new Error('auth-native-authority requires SakuraApi\'s configuration to have ' +
      '`authentication.native` set.');
  }

  if (!jwtAuthConfig) {
    throw new Error('auth-native-authority requires SakuraApi\'s configuration to have `authentication.jwt` set.');
  }

  if (!jwtAuthConfig.key) {
    throw new Error('auth-native-authority requires SakuraApi\'s configuration to have `authentication.jwt.key` set ' +
      'to a valid AES 256 private key');
  }

  if (jwtAuthConfig.key.length !== 32) {
    throw new Error('auth-native-authority requires SakuraApi\'s configuration\'s `authentication.jwt.key` to be ' +
      `be 32 characters long. The provided key is ${jwtAuthConfig.key.length} characters long`);
  }

  const bcryptHashRounds = options.bcryptHashRounds || nativeAuthConfig.bcryptHashRounds || 12;

  // Model Field Name Configuration
  const fields = {
    domainDb: ((options.model || {} as any).domain || {} as any).dbField
    || ((nativeAuthConfig.model || {} as any).domain || {} as any).dbField
    || 'domain',

    domainJson: ((options.model || {} as any).domain || {} as any).jsonField
    || ((nativeAuthConfig.model || {} as any).domain || {} as any).jsonField
    || 'domain',

    emailDb: ((options.model || {} as any).email || {} as any).dbField
    || ((nativeAuthConfig.model || {} as any).email || {} as any).dbField
    || 'email',

    emailJson: ((options.model || {} as any).email || {} as any).jsonField
    || ((nativeAuthConfig.model || {} as any).email || {} as any).jsonField
    || 'email',

    emailVerifiedDb: ((options.model || {} as any).emailVerified || {} as any).dbField
    || ((nativeAuthConfig.model || {} as any).emailVerified || {} as any).dbField
    || 'emailVerified',

    emailVerifiedJson: ((options.model || {} as any).emailVerified || {} as any).jsonField
    || ((nativeAuthConfig.model || {} as any).emailVerified || {} as any).jsonField
    || 'emailVerified',

    lastLoginDb: ((options.model || {} as any).passwordResetHash || {} as any).dbField
    || ((nativeAuthConfig.model || {} as any).passwordResetHash || {} as any).dbField
    || 'lastLogin',

    passwordDb: ((options.model || {} as any).password || {} as any).dbField
    || ((nativeAuthConfig.model || {} as any).password || {} as any).dbField
    || 'pw',

    passwordResetHashDb: ((options.model || {} as any).passwordResetHash || {} as any).dbField
    || ((nativeAuthConfig.model || {} as any).passwordResetHash || {} as any).dbField
    || 'pwResetId',

    passwordSetDateDb: ((options.model || {} as any).password || {} as any).dbField
    || ((nativeAuthConfig.model || {} as any).password || {} as any).dbField
    || 'pwSet',

    passwordStrengthDb: ((options.model || {} as any).passwordStrength || {} as any).dbField
    || ((nativeAuthConfig.model || {} as any).passwordStrength || {} as any).dbField
    || 'pwStrength'

  };

  @Model({
    dbConfig: {
      collection: options.userDbConfig.collection,
      db: options.userDbConfig.db,
      promiscuous: true
    }
  })
  class NativeAuthenticationAuthorityUser extends SakuraApiModel {
    @Db(fields.emailDb) @Json(fields.emailJson)
    email: string;

    @Db(fields.domainDb) @Json(fields.domainJson)
    domain: string = options.defaultDomain || nativeAuthConfig.defaultDomain || undefined;

    @Db({field: fields.passwordDb, private: true})
    password: string;

    @Db({field: fields.passwordSetDateDb})
    passwordSet = new Date();

    @Db({field: fields.passwordStrengthDb})
    passwordStrength: number;

    @Db(fields.emailVerifiedDb) @Json(fields.emailVerifiedJson)
    emailVerified = false;
  }

  @Model({
    dbConfig: {
      collection: options.authDbConfig.collection,
      db: options.authDbConfig.db,
      promiscuous: true
    }
  })
  class AuthenticationLog extends SakuraApiModel {
    @Db('uid') @Json()
    userId: ObjectID;

    @Db('jti') @Json()
    jwTokenId: string;

    @Db('tkn') @Json()
    token: any;

    @Db() @Json()
    created;

    @Db() @Json()
    authType = 'native';

    @Db() @Json()
    ip = '';

    @Db() @Json()
    port = null;

    @Db() @Json()
    url = '';

    @Db() @Json()
    hostName = '';

    @Db() @Json()
    invalidated = false;

    @Db() @Json()
    audience: any[] = [];
  }

  @Routable({
    model: NativeAuthenticationAuthorityUser,
    suppressApi: true
  })
  class AuthenticationAuthorityApi extends SakuraApiRoutable {

    /**
     * Change password
     */
    @Route({
      method: 'put',
      path: endpoints.changePassword || 'auth/native/change-password'
    })
    changePassword(req: Request, res: Response, next: NextFunction) {
      const locals = res.locals as IRoutableLocals;

      const email = `${locals.reqBody.email}`;
      const currentPassword = `${locals.reqBody.currentPassword}`;
      const newPassword = `${locals.reqBody.newPassword}`;
      const domain = `${locals.reqBody.domain || options.defaultDomain || nativeAuthConfig.defaultDomain}`;

      let user;
      Promise
        .resolve()
        .then(() => {
          if (!locals.reqBody.email || !locals.reqBody.currentPassword || !locals.reqBody.newPassword) {
            locals.send(400, {error: 'invalid_body'});
            throw 400;
          }

          const query = {
            [fields.emailDb]: email,
            [fields.domainDb]: domain
          };

          return NativeAuthenticationAuthorityUser.getOne(query);
        })
        .then((usr) => {
          user = usr;
          if (!user) {
            locals.send(401, {error: 'unauthorized'});
            throw 401;
          }
        })
        .then(() => compare(currentPassword, user.password))
        .then((pwMatch) => {
          if (!pwMatch) {
            locals.send(401, {error: 'unauthorized'});
            throw 401;
          }
        })
        .then(() => bcryptHash(newPassword, bcryptHashRounds))
        .then((pwHash) => {
          return user.save({
            [fields.passwordDb]: pwHash,
            [fields.passwordSetDateDb]: new Date(),
            [fields.passwordStrengthDb]: this.getPasswordStrength(newPassword, user)
          });
        })
        .then(() => (options.onChangePasswordEmailRequest)
          ? options.onChangePasswordEmailRequest(user, req, res)
          : Promise.resolve())
        .then(() => next())
        .catch((err) => {
          if (err === 400 || err === 401) {
            return next();
          }
          next(err);
        });
    }

    /**
     * Create a User
     */
    @Route({
      before: (options.onBeforeUserCreate as any),
      method: 'post', path: endpoints.create || 'auth/native'
    })
    create(req: Request, res: Response, next: NextFunction) {
      const locals = res.locals as IRoutableLocals;
      const customFields = (options.create || {} as any).acceptFields
        || (((sapi.config.authentication || {} as any).native || {} as any).create || {} as any).acceptFields;

      const email = `${locals.reqBody.email}`;
      const password = `${locals.reqBody.password}`;
      const domain = `${locals.reqBody.domain || options.defaultDomain || nativeAuthConfig.defaultDomain}`;

      if (!email || email === 'undefined') {
        locals.send(400, {error: 'email address is invalid, check body'});
        return next();
      }

      if (!password || password === 'undefined') {
        locals.send(400, {error: 'password is invalid, check body'});
        return next();
      }

      let user;
      NativeAuthenticationAuthorityUser
        .getOne({
          [fields.emailDb]: email,
          [fields.domainDb]: domain
        })
        .then((existingUser) => {
          // Make sure the user doesn't already exist
          if (existingUser) {
            locals.send(409, {error: 'email_in_use'});
            throw 409;
          }
        })
        .then(() => bcryptHash(password, bcryptHashRounds))
        .then((pwHash) => {
          user = new NativeAuthenticationAuthorityUser();

          user.email = email;
          user.password = pwHash;
          user.domain = domain;
          user.emailVerified = false;
          user.passwordSet = new Date();

          if (customFields) {
            for (const jsonField of Object.keys(customFields)) {
              if (locals.reqBody[jsonField] === undefined) {
                continue;
              }
              user[customFields[jsonField]] = locals.reqBody[jsonField];
            }
          }

          user.passwordStrength = this.getPasswordStrength(password, user);
        })
        .then(() => user.create())
        .then(() => this.encryptToken({userId: user.id}))
        .then((emailVerificationKey) =>
          (options.onUserCreated && typeof options.onUserCreated === 'function')
            ? options.onUserCreated(user.toJson(), emailVerificationKey, req, res)
            : Promise.resolve())
        .then(() => next())
        .catch((err) => {
          if (err === 409) {
            return next();
          }
          locals.send(500, {error: 'internal_server_error'});
          next(err);
        });
    }

    /**
     * Verify email - authenticates that user has access to provided email address
     */
    @Route({
      method: 'get',
      path: endpoints.emailVerification || 'auth/native/confirm/:token'
    })
    emailVerification(req: Request, res: Response, next: NextFunction) {
      const locals = res.locals as IRoutableLocals;

      Promise
        .resolve()
        .then(() => {
          const tokenParts = req.params.token.split('.');
          if (tokenParts && tokenParts.length !== 3) {
            throw 403;
          }
          return tokenParts;
        })
        .then(this.decryptToken)
        .then((token) => NativeAuthenticationAuthorityUser.getById(token.userId, {[fields.emailVerifiedDb]: 1}))
        .then((user: any) => {
          if (!user) {
            throw 403;
          }

          if (!user.emailVerified) {
            return user.save({[fields.emailVerifiedDb]: true});
          }
        })
        .then(() => next())
        .catch((err) => {
          if (err === 403) {
            locals.send(403, {error: 'invalid_token'});
            return next();
          }
          locals.send(500, {error: 'internal_server_error'});
          return next(err);
        });
    }

    /**
     * Forgot password
     */
    @Route({
      method: 'put',
      path: endpoints.forgotPassword || 'auth/native/forgot-password'
    })
    forgotPassword(req: Request, res: Response, next: NextFunction) {
      const locals = res.locals as IRoutableLocals;

      const email = `${locals.reqBody.email}`;
      const domain = `${locals.reqBody.domain || options.defaultDomain || nativeAuthConfig.defaultDomain}`;

      const query = {
        [fields.emailJson]: email,
        [fields.domainJson]: domain
      };

      let user;
      let token;
      let tokenHash;
      Promise
        .resolve()
        .then(() => {
          if (!locals.reqBody.email) {
            // let the integrator decide what to do in this circumstance
            return options
              .onForgotPasswordEmailRequest(undefined, undefined, req, res)
              .then(() => {
                throw new Error('invalid');
              });
          }
        })
        .then(() => NativeAuthenticationAuthorityUser.getOne(query))
        .then((usr) => user = usr)
        .then(() => (user)
          ? this.encryptToken({
            issued: new Date().getTime(),
            userId: user.id
          })
          : null)
        .then((tkn) => {
          if (!tkn) {
            return;
          }
          token = tkn;
          tokenHash = this.hashToken(token);

          return user.save({[fields.passwordResetHashDb]: tokenHash});
        })
        .then(() => options.onForgotPasswordEmailRequest(user, token, req, res))
        .then(() => next())
        .catch((err) => {
          if (err === 'invalid') {
            return next();
          }
          locals.send(500, {error: 'internal_server_error'});
          next(err);
        });
    }

    /**
     * Login a user
     */
    @Route({
      method: 'post',
      path: endpoints.login || 'auth/native/login'
    })
    login(req: Request, res: Response, next: NextFunction) {

      const locals = res.locals as IRoutableLocals;

      const email = `${locals.reqBody.email}`;
      const password = `${locals.reqBody.password}`;
      const domain = `${locals.reqBody.domain || options.defaultDomain || nativeAuthConfig.defaultDomain}`;

      if (!email || email === 'undefined') {
        locals.send(400, {error: 'email address is invalid, check body'});
        return next();
      }

      if (!password || password === 'undefined') {
        locals.send(400, {error: 'password is invalid, check body'});
        return next();
      }

      const query = {
        [fields.emailDb]: email,
        [fields.domainDb]: domain
      };

      let dbDoc;
      let userInfo;

      NativeAuthenticationAuthorityUser
        .getCursor(query)
        .limit(1)
        .next()
        .then((result) => {
          dbDoc = result;
          userInfo = NativeAuthenticationAuthorityUser.fromDb(dbDoc);

          if (!userInfo) {
            locals.send(401, {error: 'login_failed'});
            throw 401;
          }
        })
        .then(() => compare(password, userInfo.password))
        .then((pwMatch) => {
          if (!pwMatch) {
            locals.send(401, {error: 'login_failed'});
            throw 401;
          }

          if (!userInfo.emailVerified) {
            locals.send(403, {error: 'email_validation_required'});
            throw 403;
          }

          const payload = {
            [fields.emailJson]: email,
            [fields.domainJson]: domain
          };

          // Allows the inclusion of other fields from the User collection
          const fieldInclusion = ((sapi.config.authentication || {} as any).jwt || {} as any).fields;
          if (fieldInclusion) {
            for (const dbbField of Object.keys(fieldInclusion)) {
              const payloadField = fieldInclusion[dbbField];

              if (typeof payloadField !== 'string') {
                return Promise
                  .reject(new Error('unable to proceed, server misconfiguration. authentication.jwt.fields must be' +
                    `a key value pair of strings. key '${dbbField}' has a value typeof '${typeof payloadField}'`));
              }
              payload[payloadField] = dbDoc[dbbField];
            }
          }

          // Integrator provided function that injects arbitrary fields into the payload from "other" sources
          if (options.onJWTPayloadInject) {
            return options
              .onJWTPayloadInject(payload, dbDoc)
              .then((updatedPayload) => {
                return updatedPayload;
              });
          } else {
            return payload;
          }
        })
        .then(buildJwtToken)
        .then((token) =>
          (options.onLoginSuccess)
            ? new Promise((resolve, reject) =>
              options
                .onLoginSuccess(userInfo, token, sapi, req, res)
                .then(() => resolve(token))
                .catch(reject))
            : Promise.resolve(token))
        .then((token) => locals.send(200, {token}))
        .then(() => userInfo.save({[fields.lastLoginDb]: new Date()}))
        .then(() => next())
        .catch((err) => {
          if (err.statusCode) {
            locals.send(err.statusCode, {error: err.message});
            return next();
          }

          if (err === 401 || err === 403) {
            locals.status = err;
            return next();
          }

          locals.send(500, {error: 'internal_server_error'});
          return next(err);
        });

      //////////

      /**
       * Takes an object that defines the payload of the token, then generates a token for the issuer
       * and each of the audience servers supported by this issuer server.
       * @param payload the JWT payload
       * @returns {any} An object with each of its properties representing an audience server and each of the values
       * being the JWT token signed for that audience server.
       */
      function buildJwtToken(payload): Promise<any> {
        const key = jwtAuthConfig.key;
        const issuer = jwtAuthConfig.issuer;
        const exp = jwtAuthConfig.exp || '48h';

        if (!key || key === '' || !issuer || issuer === '') {
          return Promise
            .reject(new Error(`Unable to proceed, server misconfiguration. 'authentication.jwt.key' length?: ` +
              `'${key.length}' [note: value redacted for security], ` +
              `authentication.jwt.issuer value?: '${issuer || '>VALUE MISSING<'}'. These are required fields.`));
        }

        // self sign the payload - the issuer should never trust a token passed to it by an audience server since
        // they share a common private key - i.e., the audience server could be compromised and modify the token
        // before passing it to the issuing server. This only applies with server to server communication. For example,
        // Client authenticates with issuer, getting a key for an audience server. It passes the token to the audience
        // server, which then uses that token in a direct communication to the issuer. The client can't modify the
        // payload, but since the audience server has the private key, it could. The issSig allows the issuer to verify
        // that the payload hasn't been tampered with by the audience server.
        const hmac = createHmac('sha256', key);
        hmac.update(JSON.stringify(payload));
        (payload as any).issSig = hmac.digest('hex');

        const wait = [];
        const audiences = [];

        const jti = uuid();

        // Issuer Token
        wait.push(generateToken(key, issuer, issuer, exp, payload, jti));
        audiences.push(issuer);

        // Audience Tokens
        const audienceConfig = jwtAuthConfig.audiences;
        if (audienceConfig) {
          for (const jwtAudience of Object.keys(audienceConfig)) {
            const audienceKey = audienceConfig[jwtAudience];
            if (typeof audienceKey !== 'string') {
              return Promise.reject(new Error('Invalid authentication.jwt.audiences key defined. The value must be a '
                + 'secret key in the form of a string.'));
            }

            wait.push(generateToken(audienceKey, issuer, jwtAudience, exp, payload, jti));
            audiences.push(jwtAudience);
          }
        }

        return Promise
          .all(wait)
          .then((jwtTokens) => {
            const token = {};

            let i = 0;
            for (const result of jwtTokens) {
              token[audiences[i]] = result;
              i++;
            }

            return (() => (options.onInjectCustomToken)
              ? options.onInjectCustomToken(token, key, issuer, exp, payload, jti)
              : Promise.resolve([]))
            ()
              .then((customTokens: ICustomTokenResult[]) => {

                const customTokensForLog = [];
                for (const customToken of customTokens) {
                  token[customToken.audience] = customToken.token;

                  customTokensForLog.push({
                    audience: `${customToken.audience}`,
                    token: customToken.unEncodedToken || customToken.token
                  });
                }

                const logAuth = new AuthenticationLog();
                logAuth.userId = userInfo.id;

                logAuth.token = [{
                  audience: `${audiences.join(',')}`,
                  token: decodeToken(jwtTokens[0])
                }, ...customTokensForLog];

                logAuth.ip = req.ip;
                logAuth.port = req.connection.remotePort;
                logAuth.url = req.originalUrl;
                logAuth.hostName = req.hostname;

                logAuth.audience = audiences;

                logAuth.jwTokenId = jti;
                logAuth.created = new Date();

                return logAuth
                  .create()
                  .then(() => {
                    return token;
                  });
              });
          });
      }

      function generateToken(key: string, issuer: string, audience: string,
                             exp: string, payload: any, jti: string): Promise<string> {
        return new Promise((resolve, reject) => {
          signToken(payload, key, {
            audience,
            expiresIn: exp,
            issuer,
            jwtid: jti
          }, (err, token) => {
            if (err) {
              reject(err);
            }
            resolve(token);
          });
        });
      }
    }

    /**
     * send a new email verification key
     */
    @Route({
      method: 'post',
      path: endpoints.newEmailVerificationKey || 'auth/native/confirm'
    })
    newEmailVerificationKey(req: Request, res: Response, next: NextFunction) {
      const locals = res.locals as IRoutableLocals;

      const email = `${locals.reqBody.email}`;
      const password = `${locals.reqBody.password}`;
      const domain = `${locals.reqBody.domain || options.defaultDomain || nativeAuthConfig.defaultDomain}`;

      const query = {
        [fields.emailJson]: email,
        [fields.domainJson]: domain
      };

      let user;
      NativeAuthenticationAuthorityUser
        .getOne(query)
        .then((userFound) => {
          if (userFound) {
            user = userFound;
            return this.encryptToken({userId: user.id});
          }
        })
        .then((key) => options.onResendEmailConfirmation(user, key, req, res))
        .then(() => next())
        .catch((err) => {
          locals.send(500, {error: 'internal_server_error'});
          next(err);
        });
    }

    /**
     * resets a forgotten password and sets email verified to true... a user should only be able to peform this task
     * if he/she received a token at their email that let to a portal that send that token back into this
     * endpoint... so, if the user's email verified was false, there's no reason to further pester them to verify their
     * email.
     */
    @Route({
      method: 'put',
      path: endpoints.resetPassword || 'auth/native/reset-password/:token'
    })
    resetPassword(req: Request, res: Response, next: NextFunction) {
      const locals = res.locals as IRoutableLocals;

      const password = `${locals.reqBody.password}`;

      let user;
      let token;
      Promise
        .resolve()
        .then(() => {
          if (!locals.reqBody.password || typeof locals.reqBody.password !== 'string') {
            throw 400;
          }

          const tokenParts = req.params.token.split('.');
          if (tokenParts && tokenParts.length !== 3) {
            throw 403;
          }
          return tokenParts;
        })
        .then(this.decryptToken)
        .then((tkn) => {
          const elapsedTime = new Date().getTime() - tkn.issued;
          if (elapsedTime > 24 * 3600000) { // 24 * 1 hour
            throw 403;
          }
          token = tkn;
        })
        .then(() => NativeAuthenticationAuthorityUser.getById(token.userId, {
          [fields.passwordDb]: 1,
          [fields.passwordResetHashDb]: 1
        }))
        .then((usr) => {
          if (!usr) {
            throw 403;
          }

          if (usr[fields.passwordResetHashDb] !== this.hashToken(req.params.token)) {
            throw 403;
          }
          user = usr;
        })
        .then(() => bcryptHash(password, bcryptHashRounds))
        .then((pwHash) => user.save({
          [fields.emailVerifiedDb]: true, // in theory, the only way they got the token to do this was with their email
          [fields.passwordDb]: pwHash,
          [fields.passwordResetHashDb]: null,
          [fields.passwordSetDateDb]: new Date(),
          [fields.passwordStrengthDb]: pwStrength(password).score
        }))
        .then(() => next())
        .catch((err) => {
          if (err === 400) {
            locals.send(400, {error: 'bad_request'});
            return next();
          }
          if (err === 403) {
            locals.send(403, {error: 'invalid_token'});
            return next();
          }
          locals.send(500, {error: 'internal_server_error'});
          return next(err);
        });

    }

    //////////

    private encryptToken(keyContent: { [key: string]: any }): Promise<string> {
      return new Promise((resolve, reject) => {
        try {
          const iv = randomBytes(IV_LENGTH);
          let cipher;

          try {
            cipher = createCipheriv('aes-256-gcm', jwtAuthConfig.key, iv);
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

    private decryptToken(tokenParts: any[]): Promise<any> {
      return new Promise((resolve, reject) => {
        const tokenBase64 = tokenParts[0];
        const hmacBase64 = tokenParts[1];
        const ivBase64 = tokenParts[2];

        if (!urlBase64Validate(tokenBase64) || !urlBase64Validate(hmacBase64) || !urlBase64Validate(ivBase64)) {
          return reject(403);
        }

        const encryptedToken = urlBase64Decode(tokenBase64);
        const hmacBuffer = urlBase64Decode(hmacBase64);
        const ivBuffer = urlBase64Decode(ivBase64);

        let token;
        try {
          const decipher = createDecipheriv('aes-256-gcm', jwtAuthConfig.key, ivBuffer);
          decipher.setAuthTag(hmacBuffer);
          const tokenBuffer = Buffer.concat([
            decipher.update(encryptedToken),
            decipher.final()
          ]);
          token = JSON.parse(tokenBuffer.toString('utf8'));
          resolve(token);
        } catch (err) {
          return reject(403);
        }
      });
    }

    private hashToken(token): string {
      return createHash('sha256').update(JSON.stringify(token)).digest('base64');
    }

    private getPasswordStrength(password: string, user: any): number {

      const cd = []; // custom dictionary

      for (const key of Object.keys(user)) {
        const value = user[key];
        if (typeof value === 'string' && key !== 'password') {
          cd.push(user[key]);
        }
      }

      /** See: https://github.com/dropbox/zxcvbn
       * 0 # too guessable: risky password. (guesses < 10^3)
       * 1 # very guessable: protection from throttled online attacks. (guesses < 10^6)
       * 2 # somewhat guessable: protection from unthrottled online attacks. (guesses < 10^8)
       * 3 # safely unguessable: moderate protection from offline slow-hash scenario. (guesses < 10^10)
       * 4 # very unguessable: strong protection from offline slow-hash scenario. (guesses >= 10^10)
       */
      const pwValue = ((password || {} as any).length > 99) ? password.substring(0, 99) : password;
      return pwStrength(pwValue, cd).score;
    }
  }

  return {
    models: [
      AuthenticationLog,
      NativeAuthenticationAuthorityUser
    ],
    routables: [
      AuthenticationAuthorityApi
    ]
  };
}
