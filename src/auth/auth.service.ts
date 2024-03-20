import { ForbiddenException, Injectable } from "@nestjs/common";
import { User, Bookmark } from "@prisma/client";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService) { }

    async signup(dto: AuthDto) {
        try {
            const hash = await argon.hash(dto.password);
            const userData = {
                email: dto.email,
                password: hash,
                updatedAt: new Date(), // Thêm thuộc tính updatedAt vào dữ liệu người dùng
            };
            const user = await this.prisma.user.create({
                data: userData
            })
            return this.signToken(user.id, user.email);
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException('Email was used')
                }
            }
            throw error;
        }
    }

    async signin(dto: AuthDto) {
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email
            }
        })
        // if user doesn't exist
        if (!user) {
            throw new ForbiddenException(
                'User not found',
            );
        }
        const pw = await argon.verify(user.password, dto.password);
        if (!pw) {
            throw new ForbiddenException(
                'Wrong password',
            );
        }

        return this.signToken(user.id, user.email);
    }
    async signToken(userId: number, email: string): Promise<{ access_token: string }> {
        const payload = {
            sub: userId,
            email,
        };
        const secret = this.config.get('JWT_SECRET');
        const token = await this.jwt.signAsync(
            payload, 
            {
                expiresIn: '15m',
                secret: secret,
            }
        );
        return {
            access_token: token
        };
    }
}