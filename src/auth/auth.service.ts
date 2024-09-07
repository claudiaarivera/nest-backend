import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto, LoginDto, UpdateAuthDto } from "./dto";
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt.payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}


  async login(loginDto: LoginDto): Promise<LoginResponse> {
    /**
     * TODO
     * Generate JWT
     */
    const { email, password } = loginDto;
    const userExist = await this.userModel.findOne({ email });
    if (!userExist) {
      throw new UnauthorizedException(
        `Does'nt exist a user with email ${email}`,
      );
    }
    if (!bcryptjs.compareSync(password, userExist.password)) {
      throw new UnauthorizedException(`Invalid password`);
    }
    const { password: _, ...user } = userExist.toJSON();
    console.log(user);
    return { user, token: this.getJwt({ id: userExist.id }) };
  }
  getJwt(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }
  async getUserById(id: string){
    try {
      const user = await this.userModel.findById(id);
      const { password, ...res} = user.toJSON();
      console.log(res);
      return res;
    } catch (error) {
      throw new UnauthorizedException('User doesnt exist.');
    }
  }
  async register(registerDto: CreateUserDto): Promise<LoginResponse>{
    const user = await this.create(registerDto);
    return {user, token: this.getJwt({ id: user._id})};
  }
  async create(createAuthDto: CreateUserDto): Promise<User> {
    /**
     * TODO
     * 1. Encrypt passord ✅
     * 2. Save user ✅
   
     * 4. Handle errors ✅
     */
    const { password, ...userData } = createAuthDto;
    try {
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData,
      });

      await newUser.save();
      const { password: _, ...user } = newUser.toJSON();
      return user;
    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException(`${createAuthDto.email} already exists.`);
      }
      throw new InternalServerErrorException('Server error');
    }
  }
  async getRefreshToken(user: User):Promise<LoginResponse>{
    return { user, token: this.getJwt({ id: user._id }) };
  }
  findAll() {
    return this.userModel.find();
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}
