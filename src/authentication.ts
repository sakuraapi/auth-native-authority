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
  NextFunction,
  Request,
  Response
} from 'express';
import {compare} from 'bcrypt';
import {
  decode as decodeToken,
  sign as signToken
} from 'jsonwebtoken';
import {createHmac} from 'crypto';
import {v4 as uuid} from 'uuid';
import {ObjectID} from 'mongodb';

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
    }
  }
  /**
   * Receives the current payload and the current db results from the user lookup. If you implement this, you should
   * modify the payload with whatever fields you need then resolve the promise with the new payload as the value. This
   * allows you to insert additional information in the resulting JWT token from whatever source you deem appropriate.
   * @param payload
   * @param dbResult
   */
  payloadInjector?: (payload: any, dbResult: any) => Promise<any>;
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
    || 'pw'
  };

  @Model(sapi, {dbConfig: options.userDbConfig})
  class User extends SakuraApiModel {
    @Db(fields.emailDb) @Json(fields.emailJson)
    email: string;

    @Db(fields.domainDb) @Json(fields.domainJson)
    domain: string = options.defaultDomain || nativeAuthConfig.defaultDomain || undefined;

    @Db({field: fields.passwordDb, private: true})
    password: string;
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

      User
        .getCursor(query)
        .limit(1)
        .next()
        .then((dbDoc) => {
          const userInfo = User.fromDb(dbDoc);

          if (!userInfo) {
            locals.send(401, {error: 'login failed'});
            return next();
          }

          return compare(password, userInfo.password)
            .then((pwMatch) => {
              if (!pwMatch) {
                locals.send(401, {error: 'login failed'});
                return next();
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
                    locals.send(500, {error: 'internal_error:server_misconfigured'});
                    return next(new Error('unable to proceed, server misconfiguration. authentication.jwt.fields must be' +
                      `a key value pair of strings. key '${dbbField}' has a value typeof '${typeof payloadField}'`));
                  }
                  payload[payloadField] = dbDoc[dbbField];
                }
              }

              // Integrator provided function that injects arbitrary fields into the payload from "other" sources
              if (options.payloadInjector) {
                options
                  .payloadInjector(payload, dbDoc)
                  .then((updatedPayload) => {
                    finalizeToken(updatedPayload, userInfo);
                  })
                  .catch((err) => {
                    locals.send(500, 'internal_error:payload_injection_failed');
                    next(err);
                  });
              } else {
                finalizeToken(payload, userInfo);
              }
            })
        })
        .catch((err) => {
          locals.send(500, {error: 'internal_server_error'});
          return next(err);
        });

      //////////
      function finalizeToken(payload, userInfo) {
        const key = ((sapi.config.authentication || <any>{}).jwt || <any>{}).key;
        const issuer = ((sapi.config.authentication || <any>{}).jwt || <any>{}).issuer;
        const exp = ((sapi.config.authentication || <any>{}).jwt || <any>{}).exp || '48h';

        if (!key || key === '' || !issuer || issuer === '') {
          locals.send(500, {error: 'internal_error:server_misconfigured'});
          return next(new Error(`unable to proceed, server misconfiguration. authentication.jwt.key value?: '${key}', `
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

        const audienceConfig = ((sapi.config.authentication || <any>{}).jwt || <any>{}).audiences;
        if (audienceConfig) {
          for (const jwtAudience of Object.keys(audienceConfig)) {
            const audienceKey = audienceConfig[jwtAudience];
            if (typeof audienceKey !== 'string') {
              locals.send(500, {error: 'internal_error:server_misconfigured'});
              return next(new Error('Invalid authentication.jwt.audiences key defined. The value must be a '
                + 'secret key in the form of a string.'));
            }

            wait.push(generateToken(audienceKey, issuer, jwtAudience, exp, payload, jti));
            audiences.push(jwtAudience);
          }
        }

        Promise
          .all(wait)
          .then((results) => {
            const token = {};

            let i = 0;
            for (const result of results) {
              token[audiences[i]] = results[i];
              i++;
            }

            const log = new AuthenticationLog();
            log.userId = userInfo.id;

            log.token = decodeToken(results[0]);
            log.ip = req.ip;
            log.port = req.connection.remotePort;
            log.url = req.originalUrl;
            log.hostName = req.hostname;

            log.jwTokenId = jti;
            log.created = new Date();

            return log
              .create()
              .then(() => {
                locals.send(200, {token});
                return next();
              });
          })
          .catch((err) => {
            locals.send(500, {error: 'internal_error'});
            return next(err);
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
    @Route({method: 'post', path: '/'})
    create(req: Request, res: Response, next: NextFunction) {
      res.locals.send(200, {
        itWorked: 'create'
      }, res);

      next();
    }

    @Route({method: 'put', path: '/:id/confirm-email'})
    emailConfirmation(req: Request, res: Response, next: NextFunction) {
      res.locals.send(200, {
        itWorked: 'confirmEmail'
      }, res);

      next();
    }
  }
}
