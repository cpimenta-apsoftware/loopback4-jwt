// Copyright IBM Corp. 2020. All Rights Reserved.
// Node module: @loopback/example-todo-jwt
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

import { authenticate, TokenService } from '@loopback/authentication';
import {
  Credentials,
  MyUserService,
  TokenServiceBindings,
  User,
  UserRepository,
  UserServiceBindings
} from '@loopback/authentication-jwt';
import { inject } from '@loopback/core';
import { model, property, repository } from '@loopback/repository';
import {
  get,
  getModelSchemaRef,
  post,
  requestBody,
  SchemaObject
} from '@loopback/rest';
import { SecurityBindings, securityId, UserProfile } from '@loopback/security';
import { genSalt, hash } from 'bcryptjs';
import _ from 'lodash';

@model()
export class RequisicaoNovoUsuario extends User {
  @property({
    type: 'string',
    required: true,
  })
  password: string;
}

const CredentialsSchema: SchemaObject = {
  type: 'object',
  required: ['email', 'password'],
  properties: {
    email: {
      type: 'string',
      format: 'email',
    },
    password: {
      type: 'string',
      minLength: 8,
    },
  },
};

export const CredentialsRequestBody = {
  description: 'The input of login function',
  required: true,
  content: {
    'application/json': { schema: CredentialsSchema },
  },
};

export class UsuarioController {
  constructor(
    @inject(TokenServiceBindings.TOKEN_SERVICE)
    public jwtService: TokenService,
    @inject(UserServiceBindings.USER_SERVICE)
    public usuarioService: MyUserService,
    @inject(SecurityBindings.USER, { optional: true })
    public usuario: UserProfile,
    @repository(UserRepository) protected usuarioRepository: UserRepository,
  ) { }

  @post('/usuarios/login', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                token: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  async login(
    @requestBody(CredentialsRequestBody) credentials: Credentials,
  ): Promise<{ token: string }> {
    // ensure the usuario exists, and the password is correct
    const usuario = await this.usuarioService.verifyCredentials(credentials);
    // convert a Usuario object into a UsuarioProfile object (reduced set of properties)
    const usuarioProfile = this.usuarioService.convertToUserProfile(usuario);

    // create a JSON Web Token based on the usuario profile
    const token = await this.jwtService.generateToken(usuarioProfile);
    return { token };
  }

  @authenticate('jwt')
  @get('/whoAmI', {
    responses: {
      '200': {
        description: 'Return current usuario',
        content: {
          'application/json': {
            schema: {
              type: 'string',
            },
          },
        },
      },
    },
  })
  async whoAmI(
    @inject(SecurityBindings.USER)
    currentUsuarioProfile: UserProfile,
  ): Promise<string> {
    return currentUsuarioProfile[securityId];
  }

  @post('/signup', {
    responses: {
      '200': {
        description: 'Usuario',
        content: {
          'application/json': {
            schema: {
              'x-ts-type': User,
            },
          },
        },
      },
    },
  })
  async signUp(
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(RequisicaoNovoUsuario, {
            title: 'NewUsuario',
          }),
        },
      },
    })
    requisicaoNovoUsuario: RequisicaoNovoUsuario,
  ): Promise<User> {
    const password = await hash(requisicaoNovoUsuario.password, await genSalt());
    const savedUsuario = await this.usuarioRepository.create(
      _.omit(requisicaoNovoUsuario, 'password'),
    );

    await this.usuarioRepository.userCredentials(savedUsuario.id).create({ password });

    return savedUsuario;
  }
}
