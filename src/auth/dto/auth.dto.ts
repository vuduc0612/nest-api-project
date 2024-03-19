import { IsEmail, IsNotEmpty, IsString, IsStrongPassword } from "class-validator"

export class AuthDto{
    @IsEmail()
    @IsNotEmpty()
    email: String

    @IsString()
    @IsNotEmpty()
    password: String
}