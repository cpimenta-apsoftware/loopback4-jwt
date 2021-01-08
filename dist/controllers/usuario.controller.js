"use strict";
// Copyright IBM Corp. 2020. All Rights Reserved.
// Node module: @loopback/example-todo-jwt
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT
Object.defineProperty(exports, "__esModule", { value: true });
exports.UsuarioController = exports.CredentialsRequestBody = exports.RequisicaoNovoUsuario = void 0;
const tslib_1 = require("tslib");
const authentication_1 = require("@loopback/authentication");
const authentication_jwt_1 = require("@loopback/authentication-jwt");
const core_1 = require("@loopback/core");
const repository_1 = require("@loopback/repository");
const rest_1 = require("@loopback/rest");
const security_1 = require("@loopback/security");
const bcryptjs_1 = require("bcryptjs");
const lodash_1 = tslib_1.__importDefault(require("lodash"));
let RequisicaoNovoUsuario = class RequisicaoNovoUsuario extends authentication_jwt_1.User {
};
tslib_1.__decorate([
    repository_1.property({
        type: 'string',
        required: true,
    }),
    tslib_1.__metadata("design:type", String)
], RequisicaoNovoUsuario.prototype, "password", void 0);
RequisicaoNovoUsuario = tslib_1.__decorate([
    repository_1.model()
], RequisicaoNovoUsuario);
exports.RequisicaoNovoUsuario = RequisicaoNovoUsuario;
const CredentialsSchema = {
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
exports.CredentialsRequestBody = {
    description: 'The input of login function',
    required: true,
    content: {
        'application/json': { schema: CredentialsSchema },
    },
};
let UsuarioController = class UsuarioController {
    constructor(jwtService, usuarioService, usuario, usuarioRepository) {
        this.jwtService = jwtService;
        this.usuarioService = usuarioService;
        this.usuario = usuario;
        this.usuarioRepository = usuarioRepository;
    }
    async login(credentials) {
        // ensure the usuario exists, and the password is correct
        const usuario = await this.usuarioService.verifyCredentials(credentials);
        // convert a Usuario object into a UsuarioProfile object (reduced set of properties)
        const usuarioProfile = this.usuarioService.convertToUserProfile(usuario);
        // create a JSON Web Token based on the usuario profile
        const token = await this.jwtService.generateToken(usuarioProfile);
        return { token };
    }
    async whoAmI(currentUsuarioProfile) {
        return currentUsuarioProfile[security_1.securityId];
    }
    async signUp(requisicaoNovoUsuario) {
        const password = await bcryptjs_1.hash(requisicaoNovoUsuario.password, await bcryptjs_1.genSalt());
        const savedUsuario = await this.usuarioRepository.create(lodash_1.default.omit(requisicaoNovoUsuario, 'password'));
        await this.usuarioRepository.userCredentials(savedUsuario.id).create({ password });
        return savedUsuario;
    }
};
tslib_1.__decorate([
    rest_1.post('/usuarios/login', {
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
    }),
    tslib_1.__param(0, rest_1.requestBody(exports.CredentialsRequestBody)),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [Object]),
    tslib_1.__metadata("design:returntype", Promise)
], UsuarioController.prototype, "login", null);
tslib_1.__decorate([
    authentication_1.authenticate('jwt'),
    rest_1.get('/whoAmI', {
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
    }),
    tslib_1.__param(0, core_1.inject(security_1.SecurityBindings.USER)),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [Object]),
    tslib_1.__metadata("design:returntype", Promise)
], UsuarioController.prototype, "whoAmI", null);
tslib_1.__decorate([
    rest_1.post('/signup', {
        responses: {
            '200': {
                description: 'Usuario',
                content: {
                    'application/json': {
                        schema: {
                            'x-ts-type': authentication_jwt_1.User,
                        },
                    },
                },
            },
        },
    }),
    tslib_1.__param(0, rest_1.requestBody({
        content: {
            'application/json': {
                schema: rest_1.getModelSchemaRef(RequisicaoNovoUsuario, {
                    title: 'NewUsuario',
                }),
            },
        },
    })),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [RequisicaoNovoUsuario]),
    tslib_1.__metadata("design:returntype", Promise)
], UsuarioController.prototype, "signUp", null);
UsuarioController = tslib_1.__decorate([
    tslib_1.__param(0, core_1.inject(authentication_jwt_1.TokenServiceBindings.TOKEN_SERVICE)),
    tslib_1.__param(1, core_1.inject(authentication_jwt_1.UserServiceBindings.USER_SERVICE)),
    tslib_1.__param(2, core_1.inject(security_1.SecurityBindings.USER, { optional: true })),
    tslib_1.__param(3, repository_1.repository(authentication_jwt_1.UserRepository)),
    tslib_1.__metadata("design:paramtypes", [Object, authentication_jwt_1.MyUserService, Object, authentication_jwt_1.UserRepository])
], UsuarioController);
exports.UsuarioController = UsuarioController;
//# sourceMappingURL=usuario.controller.js.map