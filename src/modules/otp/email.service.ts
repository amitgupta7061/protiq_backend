import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class EmailService {
    private readonly logger = new Logger(EmailService.name);

    async sendOtpEmail(email: string, otp: string): Promise<void> {
        // Mock email service — in production, replace with SendGrid/SES/Nodemailer
        this.logger.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        this.logger.log(`📧 OTP Email to: ${email}`);
        this.logger.log(`🔑 Your OTP code is: ${otp}`);
        this.logger.log(`⏰ Valid for 5 minutes`);
        this.logger.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    }

    async sendSecurityAlert(email: string, subject: string, message: string): Promise<void> {
        this.logger.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        this.logger.log(`🚨 Security Alert to: ${email}`);
        this.logger.log(`📌 Subject: ${subject}`);
        this.logger.log(`📝 ${message}`);
        this.logger.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    }
}
