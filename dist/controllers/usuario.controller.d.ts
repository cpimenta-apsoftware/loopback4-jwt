import { TokenService } from '@loopback/authentication';
import { Credentials, MyUserService, User, UserRepository } from '@loopback/authentication-jwt';
import { SchemaObject } from '@loopback/rest';
import { UserProfile } from '@loopback/security';
export declare class RequisicaoNovoUsuario extends User {
    password: string;
}
export declare const CredentialsRequestBody: {
    description: string;
    required: boolean;
    content: {
        'application/json': {
            schema: SchemaObject;
        };
    };
};
export declare class UsuarioController {
    jwtService: TokenService;
    usuarioService: MyUserService;
    usuario: UserProfile;
    protected usuarioRepository: UserRepository;
    constructor(jwtService: TokenService, usuarioService: MyUserService, usuario: UserProfile, usuarioRepository: UserRepository);
    login(credentials: Credentials): Promise<{
        token: string;
    }>;
    whoAmI(currentUsuarioProfile: UserProfile): Promise<string>;
    signUp(requisicaoNovoUsuario: RequisicaoNovoUsuario): Promise<User>;
}
