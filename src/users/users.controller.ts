import { Controller, Get, Param, Req, UseGuards } from "@nestjs/common";
import { UsersService } from "./users.service";
import { JwtAuthGuard } from "src/auth/jwt.guard";
import { Request } from "express";

@Controller('users')
export class UsersController{
    constructor(private userService:UsersService){}
    @UseGuards(JwtAuthGuard)
   @Get(':id')
   getMyUser(@Param() params:{id:string}, @Req() req:Request){
    return this.userService.getMyUser(params.id,req);
   }

   @Get()
   getAllUsers(){
    return this.userService.getAllUser();
   }
}