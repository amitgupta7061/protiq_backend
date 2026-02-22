import {
    Controller,
    Post,
    Body,
    HttpCode,
    HttpStatus,
    Req,
    UseGuards,
    Patch,
    Param,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { RateLimit } from '../../common/guards/custom-throttle.guard';
import { Role } from '@prisma/client';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto, RefreshTokenDto, VerifyLoginOtpDto } from './dto';
import { VerifyOtpDto } from '../otp/dto';
import { Public } from '../../common/decorators/public.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Roles } from '../../common/decorators/roles.decorator';
import { RolesGuard } from '../../common/guards/roles.guard';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Public()
    @Post('register')
    @RateLimit({ limit: 3, windowSec: 60, keyPrefix: 'register' })
    @ApiOperation({ summary: 'Register a new user (sends OTP for email verification)' })
    async register(@Body() dto: RegisterDto) {
        return this.authService.register(dto);
    }

    @Public()
    @Post('verify-registration')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Verify registration OTP and complete signup' })
    async verifyRegistration(@Body() dto: VerifyOtpDto) {
        return this.authService.verifyRegistrationOtp(dto.email, dto.code);
    }

    @Public()
    @Post('login')
    @HttpCode(HttpStatus.OK)
    @RateLimit({ limit: 5, windowSec: 60, keyPrefix: 'login' })
    @ApiOperation({ summary: 'Login (may require OTP for 2FA or new device)' })
    async login(@Body() dto: LoginDto, @Req() req: any) {
        const ipAddress = (req.headers['x-forwarded-for'] as string) || req.ip;
        return this.authService.login(dto, ipAddress);
    }

    @Public()
    @Post('verify-login-otp')
    @HttpCode(HttpStatus.OK)
    @RateLimit({ limit: 3, windowSec: 60, keyPrefix: 'verify-otp' })
    @ApiOperation({ summary: 'Complete login with OTP verification' })
    async verifyLoginOtp(@Body() dto: VerifyLoginOtpDto, @Req() req: any) {
        const ipAddress = (req.headers['x-forwarded-for'] as string) || req.ip;
        return this.authService.verifyLoginOtp(dto, ipAddress);
    }

    @Public()
    @Post('refresh')
    @HttpCode(HttpStatus.OK)
    @ApiOperation({ summary: 'Refresh access token (with rotation and reuse detection)' })
    async refreshTokens(@Body() dto: RefreshTokenDto) {
        return this.authService.refreshTokens(dto);
    }

    @Post('logout')
    @HttpCode(HttpStatus.OK)
    @ApiBearerAuth()
    @ApiOperation({ summary: 'User logout' })
    async logout(@CurrentUser('id') userId: string) {
        await this.authService.logout(userId);
        return { message: 'Logged out successfully' };
    }

    @Patch('unlock/:userId')
    @UseGuards(RolesGuard)
    @Roles(Role.ADMIN)
    @ApiBearerAuth()
    @ApiOperation({ summary: 'Unlock a locked user account (Admin only)' })
    async unlockAccount(
        @Param('userId') userId: string,
        @CurrentUser('id') adminId: string,
    ) {
        return this.authService.unlockAccount(userId, adminId);
    }
}
