import { Module } from '@nestjs/common';
import {JwtModule} from "@nestjs/jwt";

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import {UserModule} from "../user/user.module";

import {JwtGuard} from "./guards/jwt.guard";
import {JwtStrategy} from "./guards/jwt.strategy";

@Module({
  imports: [
    UserModule,
    JwtModule.registerAsync({ useFactory: () => ({
      secret: 'secret',
        signOptions: {expiresIn: '3600s'}  // 1h
    })})
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtGuard, JwtStrategy]
})
export class AuthModule {}
