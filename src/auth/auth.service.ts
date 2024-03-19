import { Injectable } from "@nestjs/common";
import { User, Bookmark } from "@prisma/client";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService) {}
   
    async signup(dto: AuthDto) {
        const hash = await argon.hash(dto.password);
        const userData = {
            email: dto.email,
            password: hash,
            updatedAt: new Date(), // Thêm thuộc tính updatedAt vào dữ liệu người dùng
        };
        const user = await this.prisma.user.create({
           data: userData
        })
        delete user.password
        return user;
    }

    signin() {
        return {
            msg: 'Sign in!!'
        }
    }
}