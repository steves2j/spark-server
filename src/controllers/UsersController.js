// @flow

import type { IUserRepository, UserCredentials } from '../types';
import type { Settings } from './types';

import basicAuthParser from 'basic-auth-parser';
import Controller from './Controller';
import HttpError from '../lib/HttpError';
import anonymous from '../decorators/anonymous';
import httpVerb from '../decorators/httpVerb';
import route from '../decorators/route';
import settings from '../settings';
import Logger from '../lib/logger';
const logger = Logger.createModuleLogger(module);

class UsersController extends Controller {
  _userRepository: IUserRepository;

  constructor(userRepository: IUserRepository) {
    super();
    this._userRepository = userRepository;
  }

  @httpVerb('post')
  @route('/v1/users')
  @anonymous()
  async createUser(userCredentials: UserCredentials): Promise<*> {
    logger.debug("createUser with ["+userCredentials.username+"]["+userCredentials.password+"]");
    try {
	  if (settings.DENY_PUBLIC_CREATE) {
		const { username, password } = basicAuthParser(
			this.request.get('authorization'),
		);
		const user = await this._userRepository.validateLogin(username, password);
	  }
      const isUserNameInUse = await this._userRepository.isUserNameInUse(
        userCredentials.username,
      );

      if (isUserNameInUse) {
		logger.debug("Username already exists");
        throw new HttpError('user with the username already exists');
      }

      await this._userRepository.createWithCredentials(userCredentials);

      return this.ok({ ok: true });
    } catch (error) {
      return this.bad(error.message);
    }
  }

  @httpVerb('delete')
  @route('/v1/access_tokens/:token')
  @anonymous()
  async deleteAccessToken(token: string): Promise<*> {
    const { username, password } = basicAuthParser(
      this.request.get('authorization'),
    );
	 logger.debug("Deleting token ["+token+"] for user ["+username+"]");
    const user = await this._userRepository.validateLogin(username, password);

    this._userRepository.deleteAccessToken(user.id, token);

    return this.ok({ ok: true });
  }

  @httpVerb('get')
  @route('/v1/access_tokens')
  @anonymous()
  async getAccessTokens(): Promise<*> {
    const { username, password } = basicAuthParser(
      this.request.get('authorization'),
    );
	logger.debug("getting token for user ["+username+"]");
    const user = await this._userRepository.validateLogin(username, password);
    return this.ok(user.accessTokens);
  }
}

export default UsersController;

