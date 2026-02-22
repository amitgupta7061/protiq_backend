import { Controller, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { RateLimit } from '../../common/guards/custom-throttle.guard';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { OtpService } from './otp.service';
import { SendOtpDto, VerifyOtpDto } from './dto';
import { Public } from '../../common/decorators/public.decorator';

@ApiTags('OTP')
@Controller('otp')
export class OtpController {
    constructor(private readonly otpService: OtpService) { }

    @Public()
    @Post('send')
    @HttpCode(HttpStatus.OK)
    @RateLimit({ limit: 3, windowSec: 60, keyPrefix: 'otp-send' })
    @ApiOperation({ summary: 'Send OTP to email' })
    async sendOtp(@Body() dto: SendOtpDto) {
        await this.otpService.sendOtp(dto.email);
        return { message: 'OTP sent successfully' };
    }

    @Public()
    @Post('verify')
    @HttpCode(HttpStatus.OK)
    @RateLimit({ limit: 3, windowSec: 60, keyPrefix: 'otp-verify' })
    @ApiOperation({ summary: 'Verify OTP code' })
    async verifyOtp(@Body() dto: VerifyOtpDto) {
        await this.otpService.verifyOtp(dto.email, dto.code);
        return { message: 'OTP verified successfully' };
    }
}
