import {
  Db,
  IAuthenticatorConstructor,
  Id,
  IRoutableLocals,
  Json,
  Model,
  Routable,
  Route,
  SakuraApi,
  SakuraApiPluginResult,
  SapiModelMixin,
  SapiRoutableMixin
} from '@sakuraapi/core';
import { compare, hash as bcryptHash } from 'bcrypt';
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'crypto';
import * as debugInit from 'debug';
import { Handler, NextFunction, Request, Response } from 'express';
import { decode as decodeToken, sign as signToken } from 'jsonwebtoken';
import { ObjectID } from 'mongodb';
import { decode as urlBase64Decode, encode as urlBase64Encode, validate as urlBase64Validate } from 'urlsafe-base64';
import { v4 as uuid } from 'uuid';
import * as pwStrength from 'zxcvbn';

const debug = debugInit('sapi:auth-native-authority');

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
 * Domained audiences
 */
export interface IAudiences {
  [domain: string]: {
    [server: string]: string,
    issuer: string,
    key: string
  };
}

/**
 * Various options that can be set for initializing the AuthNativeAuthorityApi Module
 */
export interface IAuthenticationAuthorityOptions {
  /**
   * The authenticators to use for various endpoints that ought to be secure.
   */
  authenticator: IAuthenticatorConstructor[] | IAuthenticatorConstructor;

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
   * Accepts a Express Handler, or an array of them, to run before change password. This is helpful if you want to do
   * custom validation.
   */
  onBeforeChangePassword?: Handler | Handler[];

  /**
   * Called when the user changes his or her password, allowing the integrator to send an email
   * to the user notifying them of the password change.
   * @param user the user requesting the password change
   * @param domain the domain for which the hook is being called
   */
  onChangePasswordEmailRequest?: (user: any, req?: Request, res?: Response, domain?: string) => Promise<void>;

  /**
   * Called when an error is caught - usually used for logging
   * @param {Error} err
   */
  onError?: (err: Error) => Promise<void>;

  /**
   * Called when the user requests a "forgot password" email. It will generate a one time use password reset token. Only the
   * last one used is valid and it must be used within the time-to-live.
   * @param user
   * @param token
   * @param domain the domain for which the hook is being called
   */
  onForgotPasswordEmailRequest: (user: any, token: string, req?: Request, res?: Response, domain?: string) => Promise<void>;

  /**
   * Receives the current payload and the current db results from the user lookup. If you implement this, you should
   * modify the payload with whatever fields you need then resolve the promise with the new payload as the value. This
   * allows you to insert additional information in the resulting JWT token from whatever source you deem appropriate.
   * @param payload
   * @param dbResult
   * @param domain the domain for which the hook is being called
   * @returns {Promise<any>} contains the payload that will be the JWT payload
   */
  onJWTPayloadInject?: (payload: any, dbResult: any, domain?: string) => Promise<any>;

  /**
   * Called when a user has successfully logged in. Do whatever you need to, then either resolve the promise to
   * continue, or reject the promise with either the number 401 or 403 to send an unauthorized or forbidden
   * response. Any other rejection value will result in a 500. You can also reject with {statusCode:number,
   * message:string} to have the plugin send the statusCode and message as the response message.
   * @param domain the domain for which the hook is being called
   * @returns {Promise<void>} Resolve, or reject the promise with either the number 401 or 403 to send an unauthorized
   * or forbidden response. Any other rejection value will result in a 500.
   */
  onLoginSuccess?: (user: any, jwt: any, sapi: SakuraApi, req?: Request, res?: Response, domain?: string) => Promise<void>;

  /**
   * Called when the user needs the email verification key resent.
   * @param user note: if the requested user doesn't exist, this will be undefined
   * @param emailVerificationKey the key you should build into your link back for email confirmation
   * @param domain the domain for which the hook is being called
   * @param emailVerificationKey note: if the requested user doesn't exist, this will be undefined
   */
  onResendEmailConfirmation: (user: any, emailVerificationKey: string, req?: Request, res?: Response, domain?: string) => Promise<void>;

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
   * @param domain the domain for which the hook is being called
   * @returns {Promise<ICustomTokenResult[]>} A promise that should resolve an array of ICustomTokenResult which will
   * be used to add your custom tokens to the token dictionary returned to the user.
   */
  onInjectCustomToken?: (token: any, key: string, issuer: string, expiration: string, payload: any, jwtId: string, domain?: string)
    => Promise<ICustomTokenResult[]>;

  /**
   * Receives an object of the user just created. Of greatest importance here is validation key. You need to generate
   * an email and send that to the user in order for them to verify that they have access to the email address they're
   * claiming.
   * @param newUser an object of the user just created, minus the hashed password field.
   * @param emailVerificationKey the key that should be part of the link back to allow user emails to be confirmed
   * @param domain the domain for which the hook is being called
   */
  onUserCreated: (newUser: any, emailVerificationKey: string, req?: Request, res?: Response, domain?: string) => Promise<void>;

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

  debug('.addAuthenticationAuthority called');
  debug('options:', options);

  const endpoints = options.endpoints || {};

  if (!sapi) {
    throw new Error('auth-native-authority must have a valid instance of SakuraApi');
  }

  if (!options.userDbConfig || !options.userDbConfig.db || !options.userDbConfig.collection) {
    throw new Error('auth-native-authority addAuthenticationAuthority options parameter must have a valid ' +
      `'userDbConfig' configuration in 'IAuthenticationAuthorityOptions. Provided options ${JSON.stringify(options)}`);
  }

  // note: dbConfig for models below will always come from options, not from JSON config
  const nativeAuthConfig = ((sapi.config.authentication || {} as any).native || null) as IAuthenticationAuthorityOptions;
  const jwtAuthConfig = (sapi.config.authentication || {} as any).jwt || null;
  debug('jwtAuthConfig ', jwtAuthConfig);

  if (!nativeAuthConfig) {
    throw new Error('auth-native-authority requires SakuraApi\'s configuration to have ' +
      '`authentication.native` set.');
  }

  if (!jwtAuthConfig) {
    throw new Error('auth-native-authority requires SakuraApi\'s configuration to have `authentication.jwt` set.');
  }

  if (!jwtAuthConfig.key) {
    if (jwtAuthConfig.domainedAudiences) {
      const domains = Object.keys(jwtAuthConfig.domainedAudiences);
      for (const domain of domains) {
        if (!jwtAuthConfig.domainedAudiences[domain].key) {
          throw new Error('auth-native-authority requires SakuraApi\'s configuration to have `authentication.jwt.key` ' +
            'set to a valid AES 256 private key');
        } else {
          debug('jwtAuthConfig.domainedAudiences[domain].key', jwtAuthConfig.domainedAudiences[domain].key);
          if (jwtAuthConfig.domainedAudiences[domain].key.length !== 32) {
            throw new Error('auth-native-authority requires SakuraApi\'s configuration\'s `authentication.jwt.key` to be ' +
              `be 32 characters long. The key for ${domain} is ${jwtAuthConfig.key.length} characters long`);
          }
        }
      }
    }
  } else {
    debug('jwtAuthConfig.key', jwtAuthConfig.key);
    if (jwtAuthConfig.key.length !== 32) {
      throw new Error('auth-native-authority requires SakuraApi\'s configuration\'s `authentication.jwt.key` to be ' +
        `be 32 characters long. The provided key is ${jwtAuthConfig.key.length} characters long`);
    }
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

  debug('fields', fields);

  @Model({
    dbConfig: {
      collection: options.userDbConfig.collection,
      db: options.userDbConfig.db,
      promiscuous: true
    }
  })
  class NativeAuthenticationAuthorityUser extends SapiModelMixin() {

    @Id() @Json()
    id: ObjectID;

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
  class AuthenticationLog extends SapiModelMixin() {

    @Id() @Json()
    id: ObjectID;

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
  class AuthenticationAuthorityApi extends SapiRoutableMixin() {

    /**
     * Change password
     */
    @Route({
      authenticator: options.authenticator,
      before: (options.onBeforeChangePassword as any),
      method: 'put',
      path: endpoints.changePassword || 'auth/native/change-password'
    })
    async changePassword(req: Request, res: Response, next: NextFunction): Promise<void> {
      debug('.changePassword called');

      const locals = res.locals as IRoutableLocals;

      const email = `${locals.reqBody.email}`;
      const currentPassword = `${locals.reqBody.currentPassword}`;
      const newPassword = `${locals.reqBody.newPassword}`;
      const domain = `${locals.reqBody.domain || options.defaultDomain || nativeAuthConfig.defaultDomain}`;

      try {
        if (!locals.reqBody.email || !locals.reqBody.currentPassword || !locals.reqBody.newPassword) {
          locals.send(400, {error: 'invalid_body'});
          throw 400;
        }

        const query = {
          [fields.emailDb]: email,
          [fields.domainDb]: domain
        };

        const user = await NativeAuthenticationAuthorityUser.getOne(query);
        if (!user) {
          locals.send(401, {error: 'unauthorized'});
          throw 401;
        }

        const pwMatch = await compare(currentPassword, user.password);
        if (!pwMatch) {
          locals.send(401, {error: 'unauthorized'});
          throw 401;
        }

        const pwHash = await bcryptHash(newPassword, bcryptHashRounds);

        await user.save({
          [fields.passwordDb]: pwHash,
          [fields.passwordSetDateDb]: new Date(),
          [fields.passwordStrengthDb]: this.getPasswordStrength(newPassword, user)
        });

        if (options.onChangePasswordEmailRequest && typeof options.onChangePasswordEmailRequest === 'function') {
          await options.onChangePasswordEmailRequest(user, req, res, domain);
        }

        next();
      } catch (err) {
        if (err === 400 || err === 401) {
          return next();
        }

        if (options.onError) {
          await options.onError(err);
        }
        next();
      }
    }

    /**
     * Create a User
     */
    @Route({
      before: (options.onBeforeUserCreate as any),
      method: 'post', path: endpoints.create || 'auth/native'
    })
    async create(req: Request, res: Response, next: NextFunction): Promise<void> {
      debug('.create called');

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

      if (domain && jwtAuthConfig.domainedAudiences) {
        const domains = Object.keys(jwtAuthConfig.domainedAudiences);
        if (domains.indexOf(domain) < 0) {
          locals.send(400, {error: 'domain does not exist'});
          return next();
        }
      }

      try {

        const existingUser = await NativeAuthenticationAuthorityUser
          .getOne({
            [fields.emailDb]: email,
            [fields.domainDb]: domain
          });

        // Make sure the user doesn't already exist
        if (existingUser) {
          locals.send(409, {error: 'email_in_use'});
          throw 409;
        }

        const pwHash = await bcryptHash(password, bcryptHashRounds);

        const user = new NativeAuthenticationAuthorityUser();

        user.email = email;
        user.password = pwHash;
        user.domain = domain;
        user.emailVerified = false;
        user.passwordSet = new Date();

        if (customFields) {
          const keys = Object.keys(customFields);
          for (const jsonField of keys) {
            if (locals.reqBody[jsonField] === undefined) {
              continue;
            }
            user[customFields[jsonField]] = locals.reqBody[jsonField];
          }
        }

        user.passwordStrength = this.getPasswordStrength(password, user);

        await user.create();
        let domainKey = '';
        if (domain && jwtAuthConfig.domainedAudiences && jwtAuthConfig.domainedAudiences[domain]) {
          domainKey = jwtAuthConfig.domainedAudiences[domain].key;
        }
        const encryptionKey = jwtAuthConfig.key || domainKey;
        debug('encryptionKey', encryptionKey);
        const emailVerificationKey = await this.encryptToken({userId: user.id}, encryptionKey);

        if (options.onUserCreated && typeof options.onUserCreated === 'function') {
          debug('.onUserCreated triggered');
          await options.onUserCreated(user.toJson(), emailVerificationKey, req, res, domain);
        }

        next();
      } catch (err) {
        if (err === 409) {
          return next();
        }

        locals.send(500, {error: 'internal_server_error'});

        if (options.onError) {
          await options.onError(err);
        }

        next();
      }
    }

    /**
     * Verify email - authenticates that user has access to provided email address
     */
    @Route({
      method: 'get',
      path: endpoints.emailVerification || 'auth/native/confirm/:token/:domain?'
    })
    async emailVerification(req: Request, res: Response, next: NextFunction): Promise<void> {
      debug('.emailVerification called');

      const locals = res.locals as IRoutableLocals;
      const domain = `${req.params.domain || locals.reqBody.domain || options.defaultDomain || nativeAuthConfig.defaultDomain}`;

      debug('locals.reqBody', locals.reqBody);
      try {

        const tokenParts = req.params.token.split('.');
        if (tokenParts && tokenParts.length !== 3) {
          throw 403;
        }

        let user: NativeAuthenticationAuthorityUser;
        let key: string;

        if (jwtAuthConfig.key) {
          key = jwtAuthConfig.key;
        }

        // try all the issuer-keys in the domains
        if (domain && jwtAuthConfig.domainedAudiences) {
          key = jwtAuthConfig.domainedAudiences[domain].key;
        }

        let token;
        try {
          token = await this.decryptToken(tokenParts, key);
        } catch {
          throw 403;
        }

        user = await NativeAuthenticationAuthorityUser.getById(token.userId, {[fields.emailVerifiedDb]: 1});

        if (!user) {
          throw 403;
        }

        if (!user.emailVerified) {
          await user.save({[fields.emailVerifiedDb]: true});
        }

        next();
      } catch (err) {
        if (err === 403) {
          locals.send(403, {error: 'invalid_token'});
          return next();
        }

        locals.send(403, {error: 'invalid_token'});

        if (options.onError) {
          await options.onError(err);
        }

        next();
      }
    }

    /**
     * Forgot password
     */
    @Route({
      method: 'put',
      path: endpoints.forgotPassword || 'auth/native/forgot-password'
    })
    async forgotPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
      debug('.forgotPassword called');

      const locals = res.locals as IRoutableLocals;

      const email = `${locals.reqBody.email}`;
      const domain = `${locals.reqBody.domain || options.defaultDomain || nativeAuthConfig.defaultDomain}`;

      const query = {
        [fields.emailJson]: email,
        [fields.domainJson]: domain
      };

      try {

        if (!locals.reqBody.email) {
          // let the integrator decide what to do in this circumstance. `user` and `token` are undefined, which
          // the integrator can use to determine the invalid email body state has occurred. The system
          // will default to next() (200 OK) unless the integrator sets res.locals.send...
          await options
            .onForgotPasswordEmailRequest(undefined, undefined, req, res, domain)
            .then(() => {
              throw 'invalid';
            });
        }

        const user = await NativeAuthenticationAuthorityUser.getOne(query);

        if (!user) {
          await options
            .onForgotPasswordEmailRequest(undefined, undefined, req, res, domain)
            .then(() => {
              throw 'invalid';
            });
        }

        const token = await this
          .encryptToken({
            issued: new Date().getTime(),
            userId: user.id
          });

        const tokenHash = (token)
          ? this.hashToken(token)
          : null;

        await user.save({[fields.passwordResetHashDb]: tokenHash});
        await options.onForgotPasswordEmailRequest(user, token, req, res, domain);

        next();

      } catch (err) {

        if (err === 'invalid') {
          return next();
        }

        locals.send(500, {error: 'internal_server_error'});

        if (options.onError) {
          await options.onError(err);
        }

        next();
      }
    }

    /**
     * Login a user
     */
    @Route({
      method: 'post',
      path: endpoints.login || 'auth/native/login'
    })
    async login(req: Request, res: Response, next: NextFunction): Promise<void> {
      debug('.login called');

      const locals = res.locals as IRoutableLocals;

      const email = `${locals.reqBody.email}`;
      const password = `${locals.reqBody.password}`;
      const domain = `${locals.reqBody.domain || options.defaultDomain || nativeAuthConfig.defaultDomain}`;

      debug('email: ', email);
      debug('password: ', password);
      debug('domain: ', domain);

      if (!email || email === 'undefined') {
        locals.send(400, {error: 'email address is invalid, check body'});
        return next();
      }

      if (!password || password === 'undefined') {
        locals.send(400, {error: 'password is invalid, check body'});
        return next();
      }
      try {

        const query = {
          [fields.emailDb]: email,
          [fields.domainDb]: domain
        };

        debug('query: ', query);

        const dbDoc = await NativeAuthenticationAuthorityUser
          .getCursor(query)
          .limit(1)
          .next();

        debug('query result: ', dbDoc);

        const userInfo = await NativeAuthenticationAuthorityUser.fromDb(dbDoc);

        debug('userInfo: ', userInfo);

        if (!userInfo) {
          locals.send(401, {error: 'login_failed'});
          throw 401;
        }

        const pwMatch = await compare(password, userInfo.password);

        if (!pwMatch) {
          locals.send(401, {error: 'login_failed'});
          throw 401;
        }

        if (!userInfo.emailVerified) {
          locals.send(403, {error: 'email_validation_required'});
          throw 403;
        }

        let payload = {
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
          payload = await options.onJWTPayloadInject(payload, dbDoc, domain);
        }

        debug('payload: ', payload);

        const token = await buildJwtToken(payload, userInfo, domain);

        debug('token: ', token);

        if (options.onLoginSuccess) {
          debug('calling onLoginSuccess');
          await options.onLoginSuccess(userInfo, token, sapi, req, res, domain);
        }

        debug('sending 200 OK');
        locals.send(200, {token});

        debug('saving userInfo: ', userInfo);
        await userInfo.save({[fields.lastLoginDb]: new Date()});

        next();
      } catch (err) {
        if (err.statusCode) {
          locals.send(err.statusCode, {error: err.message});
          return next();
        }

        if (err === 401 || err === 403) {
          locals.status = err;
          return next();
        }

        locals.send(500, {error: 'internal_server_error'});

        if (options.onError) {
          await options.onError(err);
        }

        next();
      }

      //////////

      /**
       * Takes an object that defines the payload of the token, then generates a token for the issuer
       * and each of the audience servers supported by this issuer server.
       * @param payload the JWT payload
       * * @param {NativeAuthenticationAuthorityUser} userInfo
       * @returns {any} An object with each of its properties representing an audience server and each of the values
       * being the JWT token signed for that audience server.
       */
      async function buildJwtToken(payload: any, userInfo: NativeAuthenticationAuthorityUser, domain?: string): Promise<any> {
        debug('.buildJwtToken called');

        let key = jwtAuthConfig.key;
        let issuer = jwtAuthConfig.issuer;

        if (domain && jwtAuthConfig.domainedAudiences) {
          key = jwtAuthConfig.domainedAudiences[domain].key;
          issuer = jwtAuthConfig.domainedAudiences[domain].issuer;
        }

        const exp = jwtAuthConfig.exp || '48h';

        try {
          if (!key || key === '' || !issuer || issuer === '') {
            throw new Error(`Unable to proceed, server misconfiguration. 'authentication.jwt.key' length?: ` +
              `'${key.length}' [note: value redacted for security], ` +
              `authentication.jwt.issuer value?: '${issuer || '>VALUE MISSING<'}'. These are required fields.`);
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
          payload.issSig = hmac.digest('hex');

          const wait = [];
          const audiences = [];
          const jti = uuid();

          // Issuer Token
          wait.push(generateToken(key, issuer, issuer, exp, payload, jti));
          audiences.push(issuer);

          // Audience Tokens
          let audienceConfig;
          if (jwtAuthConfig.domainedAudiences) {
            audienceConfig = jwtAuthConfig.domainedAudiences[domain];
          } else if (jwtAuthConfig.audiences) {
            audienceConfig = jwtAuthConfig.audiences;
          }
          debug('audienceConfig', audienceConfig);

          if (audienceConfig) {
            const keys = Object.keys(audienceConfig);
            for (const jwtAudience of keys) {
              const audienceKey = audienceConfig[jwtAudience];
              if (typeof audienceKey !== 'string') {
                throw new Error('Invalid authentication.jwt.audiences key defined. The value must be a '
                  + 'secret key in the form of a string.');
              }
              if (jwtAudience !== 'issuer' && jwtAudience !== 'key') {
                wait.push(generateToken(audienceKey, issuer, jwtAudience, exp, payload, jti));
                audiences.push(jwtAudience);
              }
            }
          }

          const jwtTokens = await Promise.all(wait);
          const token = {};

          let i = 0;
          for (const result of jwtTokens) {
            token[audiences[i]] = result;
            i++;
          }

          let customTokens: ICustomTokenResult[] = [];
          if (options.onInjectCustomToken) {
            customTokens = await options.onInjectCustomToken(token, key, issuer, exp, payload, jti, domain);
          }

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

          debug('logAuth create: ', logAuth);
          await logAuth.create();
          return token;

        } catch (err) {
          throw err;
        }
      }

      function generateToken(key: string, issuer: string, audience: string,
                             exp: string, payload: any, jti: string): Promise<string> {
        debug('.generateToken called');
        return new Promise((resolve, reject) => {
          signToken(payload,
            key,
            {
              audience,
              expiresIn: exp,
              issuer,
              jwtid: jti
            }, (err, token) => {
              (err)
                ? reject(err)
                : resolve(token);
            });
        });
      }
    }

    /**
     * send a new email verification key. If the email/domain is not found, `onResendEmailConfirmation` is still
     * called. It's up to the integrator to determine the desired behavior in terms of what should be returned
     * in this circumstance. We'd suggest 200 + whatever you normally return so as to not hint
     * to a bad guy that they stumbled upon a valid email/domain pair.
     *
     * You can set the return behavior of newEmailVerificationKey with res.locals.
     */
    @Route({
      method: 'post',
      path: endpoints.newEmailVerificationKey || 'auth/native/confirm'
    })
    async newEmailVerificationKey(req: Request, res: Response, next: NextFunction): Promise<void> {
      debug('.newEmailVerificationKey called');

      const locals = res.locals as IRoutableLocals;

      const email = `${locals.reqBody.email}`;
      const domain = `${locals.reqBody.domain || options.defaultDomain || nativeAuthConfig.defaultDomain}`;

      const query = {
        [fields.emailJson]: email,
        [fields.domainJson]: domain
      };

      try {
        const user = await NativeAuthenticationAuthorityUser.getOne(query);
        const key = (user)
          ? await this.encryptToken({userId: user.id})
          : '';

        await options.onResendEmailConfirmation(user, key, req, res, domain);
        next();
      } catch (err) {

        locals.send(500, {error: 'internal_server_error'});

        if (options.onError) {
          options.onError(err);
        }
        next();
      }
    }

    /**
     * resets a forgotten password and sets email verified to true... a user should only be able to perform this task
     * if he/she received a token at their email that let to a portal that send that token back into this
     * endpoint... so, if the user's email verified was false, there's no reason to further pester them to verify their
     * email.
     */
    @Route({
      method: 'put',
      path: endpoints.resetPassword || 'auth/native/reset-password/:token'
    })
    async resetPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
      debug('.resetPassword called');

      const locals = res.locals as IRoutableLocals;

      const password = `${locals.reqBody.password}`;

      try {
        if (!locals.reqBody.password || typeof locals.reqBody.password !== 'string') {
          throw 400;
        }

        const tokenParts = req.params.token.split('.');
        if (tokenParts && tokenParts.length !== 3) {
          throw 403;
        }

        const token = await this.decryptToken(tokenParts);

        const elapsedTime = new Date().getTime() - token.issued;
        if (elapsedTime > 24 * 3600000) { // 24 * 1 hour
          throw 403;
        }

        const user = await NativeAuthenticationAuthorityUser.getById(token.userId, {
          [fields.passwordDb]: 1,
          [fields.passwordResetHashDb]: 1
        });

        if (!user || user[fields.passwordResetHashDb] !== this.hashToken(req.params.token)) {
          throw 403;
        }

        const pwHash = await bcryptHash(password, bcryptHashRounds);
        await user.save({
          [fields.emailVerifiedDb]: true, // in theory, the only way they got the token to do this was with their email
          [fields.passwordDb]: pwHash,
          [fields.passwordResetHashDb]: null,
          [fields.passwordSetDateDb]: new Date(),
          [fields.passwordStrengthDb]: pwStrength(password).score
        });

        next();
      } catch (err) {
        if (err === 400) {
          locals.send(400, {error: 'bad_request'});
          return next();
        }
        if (err === 403) {
          locals.send(403, {error: 'invalid_token'});
          return next();
        }
        locals.send(500, {error: 'internal_server_error'});

        if (options.onError) {
          options.onError(err);
        }

        next();
      }
    }

    private encryptToken(keyContent: { [key: string]: any }, encryptionKey?: string): Promise<string> {
      debug('.encryptToken called ');
      debug('encryptionkey1', encryptionKey);
      if (!encryptionKey) {
        if (!jwtAuthConfig.key) {
          throw new Error('no encryption key');
        } else {
          encryptionKey = jwtAuthConfig.key;
        }
      }
      return new Promise((resolve, reject) => {
        try {
          const iv = randomBytes(IV_LENGTH);
          let cipher;
          debug('encryptionkey2', encryptionKey);
          try {
            cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);
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

    private decryptToken(tokenParts: any[], decryptionKey?: string): Promise<any> {
      debug('.decryptToken called. key is ', decryptionKey);
      if (!decryptionKey) {
        if (!jwtAuthConfig.key) {
          throw new Error('no decryption key');
        } else {
          decryptionKey = jwtAuthConfig.key;
        }
      }

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
          const decipher = createDecipheriv('aes-256-gcm', decryptionKey, ivBuffer);
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

      /**
       * See: https://github.com/dropbox/zxcvbn
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
