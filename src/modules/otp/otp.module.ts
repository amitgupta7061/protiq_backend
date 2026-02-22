import { Global, Module } from '@nestjs/common';
import { OtpService } from './otp.service';
import { OtpController } from './otp.controller';
import { EmailService } from './email.service';

@Global()
@Module({
    controllers: [OtpController],
    providers: [OtpService, EmailService],
    exports: [OtpService, EmailService],
})
export class OtpModule { }
