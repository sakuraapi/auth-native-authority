import {
  Db,
  IRoutableLocals,
  Json,
  Model,
  Routable,
  Route,
  SakuraApi,
  SakuraApiModel,
  SakuraApiRoutable
} from '@sakuraapi/api';
import {
  Handler,
  NextFunction,
  Request,
  Response
} from 'express';
import {
  compare,
  hash
} from 'bcrypt';
import {
  decode as decodeToken,
  sign as signToken
} from 'jsonwebtoken';
import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes
} from 'crypto';
import {v4 as uuid} from 'uuid';
import {ObjectID} from 'mongodb';
import {
  decode as urlBase64Decode,
  encode as urlBase64Encode,
  validate as urlBase64Validate
} from 'urlsafe-base64';

/**
 * Various options that can be set for initializing the AuthNativeAuthorityApi Module
 */
export interface IAuthenticationAuthorityOptions {
  /**
   * The same database configuration that you're using for your model that represents the collection of MongoDB documents that
   * store your users.
   */
  userDbConfig: {
    collection: string
    db: string;
  }

  /**
   * The database where authTokens are stored so that you have a record of tokes that are issued.
   */
  authDbConfig: {
    collection: string
    db: string;
  }

  /**
   * If set, the system will require email & domain to login the user (a user can belong to multiple domains). If the domain
   * is not provided, this default value is substituted when looking up the user.
   */
  defaultDomain?: string;
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
    emailVerified: {
      dbField?: string;
      jsonField?: string;
    },
    emailVerificationKey: {
      dbField?: string;
      jsonField?: string;
    }
  }
  /**
   * Receives the current payload and the current db results from the user lookup. If you implement this, you should
   * modify the payload with whatever fields you need then resolve the promise with the new payload as the value. This
   * allows you to insert additional information in the resulting JWT token from whatever source you deem appropriate.
   * @param payload
   * @param dbResult
   */
  onJWTPayloadInject?: (payload: any, dbResult: any) => Promise<any>;

  /**
   * Accepts a Express Handler, or an array of them, to run before user creation. This is helpful if you want to do
   * custom validation.
   */
  onBeforeUserCreate?: Handler | Handler[];

  /**
   * Receives an object of the user just created. Of greatest importance here is validation key. You need to generate
   * an email and send that to the user in order for them to verify that they have access to the email address they're
   * claiming.
   * @param newUser an object of the user just created, minus the hashed password field.
   */
  onUserCreated: (newUser: any, emailVerificationKey: string, req?: Request, res?: Response) => Promise<any>;

  /**
   * Called when the user needs the email verification key resent.. note that
   * @param user note: if the requested user doesn't exist, this will be undefined
   * @param emailVerificationKey note: if the requested user doesn't exist, this will be undefined
   */
  onResendEmailConfirmation: (user: any, emailVerificationKey: string, req?: Request, res?: Response) => Promise<any>;
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
 * This will add several endpoints to your server (subordinate to sapi.baseUri):
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
export function addAuthenticationAuthority(sapi: SakuraApi, options: IAuthenticationAuthorityOptions) {

  if (!options.userDbConfig || !options.userDbConfig.db || !options.userDbConfig.collection) {
    throw new Error('auth-native-authority addAuthenticationAuthority options parameter must have a valid db configuration ' +
      ` - provided value ${JSON.stringify(options)}`);
  }

  // note, though sapi.config.native is overridden by the options parameter, and the dbConfig must always come from the
  // options parameter.
  const nativeAuthConfig = ((sapi.config.authentication || <any>{}).native || {}) as IAuthenticationAuthorityOptions;

  const jwtAuthConfig = (sapi.config.authentication || <any>{}).jwt || {};
  const bcryptHashRounds = options.bcryptHashRounds || nativeAuthConfig.bcryptHashRounds || 12;

  // Model Field Name Configuration
  const fields = {
    emailDb: ((options.model || <any>{}).email || <any>{}).dbField
    || ((nativeAuthConfig.model || <any>{}).email || <any>{}).dbField
    || 'email',

    emailJson: ((options.model || <any>{}).email || <any>{}).jsonField
    || ((nativeAuthConfig.model || <any>{}).email || <any>{}).jsonField
    || 'email',

    domainDb: ((options.model || <any>{}).domain || <any>{}).dbField
    || ((nativeAuthConfig.model || <any>{}).domain || <any>{}).dbField
    || 'domain',

    domainJson: ((options.model || <any>{}).domain || <any>{}).jsonField
    || ((nativeAuthConfig.model || <any>{}).domain || <any>{}).jsonField
    || 'domain',

    passwordDb: ((options.model || <any>{}).password || <any>{}).dbField
    || ((nativeAuthConfig.model || <any>{}).password || <any>{}).dbField
    || 'pw',

    emailVerifiedDb: ((options.model || <any>{}).emailVerified || <any>{}).dbField
    || ((nativeAuthConfig.model || <any>{}).emailVerified || <any>{}).dbField
    || 'emailVerified',

    emailValidatedJson: ((options.model || <any>{}).emailVerified || <any>{}).jsonField
    || ((nativeAuthConfig.model || <any>{}).emailVerified || <any>{}).jsonField
    || 'emailVerified',

  };

  @Model(sapi, {
    dbConfig: {
      collection: options.userDbConfig.collection,
      db: options.userDbConfig.db,
      promiscuous: true
    }
  })
  class User extends SakuraApiModel {
    @Db(fields.emailDb) @Json(fields.emailJson)
    email: string;

    @Db(fields.domainDb) @Json(fields.domainJson)
    domain: string = options.defaultDomain || nativeAuthConfig.defaultDomain || undefined;

    @Db({field: fields.passwordDb, private: true})
    password: string;

    @Db(fields.emailVerifiedDb) @Json(fields.emailValidatedJson)
    emailVerified = false;
  }

  @Model(sapi, {
    dbConfig: {
      db: options.authDbConfig.db,
      collection: options.authDbConfig.collection,
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

  @Routable(sapi, {baseUrl: 'auth/native', model: User, suppressApi: true})
  class AuthenticationAuthorityApi extends SakuraApiRoutable {

    /**
     * Login a user
     */
    @Route({method: 'post', path: '/login'})
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

      User
        .getCursor(query)
        .limit(1)
        .next()
        .then((result) => {
          dbDoc = result;
          userInfo = User.fromDb(dbDoc);

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
            [fields.domainJson]: domain,
          };

          // Allows the inclusion of other fields from the User collection
          const fieldInclusion = ((sapi.config.authentication || <any>{}).jwt || <any>{}).fields;
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
                return updatedPayload
              });
          } else {
            return payload;
          }
        })
        .then(buildJwtToken)
        .then((token) => locals.send(200, {token}))
        .then(() => next())
        .catch((err) => {
          if (err === 401 || err === 403) {
            return next();
          }
          locals.send(500, {error: 'internal_server_error'});
          return next(err);
        });

      //////////
      function buildJwtToken(payload) {
        const key = jwtAuthConfig.key;
        const issuer = jwtAuthConfig.issuer;
        const exp = jwtAuthConfig.exp || '48h';

        if (!key || key === '' || !issuer || issuer === '') {
          return Promise
            .reject(new Error(`unable to proceed, server misconfiguration. authentication.jwt.key value?: '${key}', `
              + `authentication.jwt.issuer value?: '${issuer}'. These are required fields.`));
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

        wait.push(generateToken(key, issuer, issuer, exp, payload, jti));
        audiences.push(issuer);

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

            const logAuth = new AuthenticationLog();
            logAuth.userId = userInfo.id;

            logAuth.token = decodeToken(jwtTokens[0]);
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
                return token
              });
          });
      }

      function generateToken(key: string, issuer: string, audience: string,
                             exp: string, payload: any, jti: string): Promise<string> {
        return new Promise((resolve, reject) => {
          signToken(payload, key, {
            audience: audience,
            expiresIn: exp,
            issuer: issuer,
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
     * Create a User
     */
    @Route({
      method: 'post', path: '/',
      before: (options.onBeforeUserCreate as any)
    })
    create(req: Request, res: Response, next: NextFunction) {
      const locals = res.locals as IRoutableLocals;
      const customFields = (options.create || <any>{}).acceptFields
        || (((sapi.config.authentication || <any>{}).native || <any>{}).create || <any>{}).acceptFields;

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
      let emailVerificationKey;
      User
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
        .then(() => hash(password, bcryptHashRounds))
        .then((pwHash) => {
          user = new User();

          user.email = email;
          user.password = pwHash;
          user.domain = domain;
          user.emailVerified = false;

          if (customFields) {
            for (let jsonField of Object.keys(customFields)) {
              if (locals.reqBody[jsonField] === undefined) {
                continue;
              }
              user[customFields[jsonField]] = locals.reqBody[jsonField];
            }
          }
        })
        .then(() => user.create())
        .then(() => this.getEmailVerificationToken(user.id))
        .then((emailVerificationKey) => options.onUserCreated(user.toJson(), emailVerificationKey, req, res))
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
    @Route({method: 'put', path: '/confirm/:encToken'})
    emailVerification(req: Request, res: Response, next: NextFunction) {
      const locals = res.locals as IRoutableLocals;
      const tokenParts = req.params.encToken.split('.');

      if (tokenParts && tokenParts.length !== 3) {
        locals.send(400, {error: 'invalid_key'});
        return next();
      }

      const tokenBase64 = tokenParts[0];
      const hmacBase64 = tokenParts[1];
      const ivBase64 = tokenParts[2];

      if (!urlBase64Validate(tokenBase64) || !urlBase64Validate(hmacBase64) || !urlBase64Validate(ivBase64)) {
        locals.send(400, {error: 'invalid_key'});
        return next();
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
      } catch (err) {
        locals.send(403, {error: 'invalid_token'});
        return next(err);
      }

      User
        .getById(token.userId)
        .then((user: any) => {
          if (!user) {
            return locals.send(403, {error: 'invalid_token'});
          }

          if (!user.emailVerified) {
            user.emailVerified = true;
            return user.save();
          }
        })
        .then(() => next())
        .catch((err) => {
          locals.send(500, {error: 'internal_server_error'});
          return next(err);
        });
    }

    /**
     * send a new email verification key
     */
    @Route({
      method: 'post', path: '/confirm'
    })
    newEmailVerificationKey(req: Request, res: Response, next: NextFunction) {
      const locals = res.locals as IRoutableLocals;

      const email = `${locals.reqBody.email}`;
      const password = `${locals.reqBody.password}`;
      const domain = `${locals.reqBody.domain || options.defaultDomain || nativeAuthConfig.defaultDomain}`;

      const query = {
        [fields.emailJson]: email,
        [fields.domainJson]: domain,
      };

      let user;
      User
        .getOne(query)
        .then((userFound) => {
          if (userFound) {
            user = userFound;
            return this.getEmailVerificationToken(user.id)
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
     * Reset password
     */
    @Route({
      method: 'put', path: '/change-password'
    })
    changePassword(req: Request, res: Response, next: NextFunction) {
      throw new Error('not implemented');
    }

    /**
     * Forgot password
     */
    @Route({
      method: 'put', path: '/forgot-password'
    })
    forgotPassword(req: Request, res: Response, next: NextFunction) {
      throw new Error('not implemented');
    }

    private getEmailVerificationToken(userId: string | ObjectID): Promise<string> {
      return new Promise((resolve, reject) => {
        try {
          const iv = randomBytes(16);
          const cipher = createCipheriv('aes-256-gcm', jwtAuthConfig.key, iv);
          const keyContent = {
            userId: userId
          };

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
  }
}
