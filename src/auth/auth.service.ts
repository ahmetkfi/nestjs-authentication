import { BadRequestException, ForbiddenException, Injectable, Req, Res } from "@nestjs/common";
import { PrismaService } from "prisma/prisma.service";
import { AuthDto } from "./dto/auth.dto";
import * as bcrypt from 'bcrypt';
import { JwtService } from "@nestjs/jwt/dist";
import { jwtSecret } from "src/utils/constants";
import { Request,Response } from "express";
@Injectable()
export class AuthService{
    constructor(private prisma:PrismaService,private jwt:JwtService){}
    async signup(dto:AuthDto){
        const {email,password}=dto;
        const foundUser= await this.prisma.user.findUnique({where:{email}});
        if(foundUser){
            throw new BadRequestException('Email already exist');
        }
        const hashedPassword=await this.hashPassword(password);
        await this.prisma.user.create({
            data:{
                email,
                hashedPassword
            }
        });
        return `sign up was succesful -----> email : ${email}`
    }
    async signin(dto:AuthDto,req:Request,res:Response){
        const {email,password}=dto;
        const foundUser=await this.prisma.user.findUnique({where:{email}});
        if(!foundUser){
         throw new BadRequestException('Wrong credentials');
        }
        const isMatch=await bcrypt.compare(password,foundUser.hashedPassword);
        if(!isMatch){
            throw new BadRequestException('Wrong password');
        }
        const token=await this.signToken({
            id:foundUser.id,
            email:foundUser.email,
        });
        if(!token){
            throw new ForbiddenException();
        }
        res.cookie('token',token);
        return res.send({
            message:'Logged in succesfully'
        })
        
    }
    async signout(req:Request,res:Response){
        res.clearCookie('token');
        return res.send({
            message:'signout was succesfull'
        });
    }
    async hashPassword(password:string,){
        const saltOrRounds=10;
        const hashedPassword=await bcrypt.hash(password,saltOrRounds);
        return hashedPassword;
    } 
    async signToken(args:{id:string,email:string}){
        const payload=args;
       return this.jwt.signAsync(payload,{secret:jwtSecret});
    }
}