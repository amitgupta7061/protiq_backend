import {
    Injectable,
    BadRequestException,
    ForbiddenException,
    Logger,
} from '@nestjs/common';
import { RedisService } from '../../redis/redis.service';
import { EmailService } from './email.service';
import { Role } from '@prisma/client';

interface OtpData {
    code: string;
    attempts: number;
    createdAt: number;
}

@Injectable()
export class OtpService {
    private readonly logger = new Logger(OtpService.name);
    private readonly OTP_TTL = 300;         // 5 minutes
    private readonly MAX_ATTEMPTS = 5;
    private readonly LOCKOUT_TTL = 600;     // 10 minutes lockout after max attempts

    constructor(
        private redisService: RedisService,
        private emailService: EmailService,
    ) { }

    /**
     * Generate and send OTP to the given email
     */
    async sendOtp(email: string): Promise<void> {
        // Check if locked out
        const isLocked = await this.redisService.exists(`otp:lock:${email}`);
        if (isLocked) {
            throw new ForbiddenException(
                'Too many OTP attempts. Please try again later.',
            );
        }

        // Generate 6-digit OTP
        const code = Math.floor(100000 + Math.random() * 900000).toString();

        // Store in Redis with TTL
        const otpData: OtpData = {
            code,
            attempts: 0,
            createdAt: Date.now(),
        };

        await this.redisService.setJson(`otp:${email}`, otpData, this.OTP_TTL);

        // Send email
        await this.emailService.sendOtpEmail(email, code);

        this.logger.log(`OTP sent to ${email}`);
    }

    /**
     * Verify OTP code for the given email
     */
    async verifyOtp(email: string, code: string): Promise<boolean> {
        // Check lockout
        const isLocked = await this.redisService.exists(`otp:lock:${email}`);
        if (isLocked) {
            throw new ForbiddenException(
                'Too many OTP attempts. Please try again later.',
            );
        }

        const otpData = await this.redisService.getJson<OtpData>(`otp:${email}`);

        if (!otpData) {
            throw new BadRequestException('OTP expired or not found. Request a new OTP.');
        }

        // Check max attempts
        if (otpData.attempts >= this.MAX_ATTEMPTS) {
            // Lock the email
            await this.redisService.set(`otp:lock:${email}`, '1', this.LOCKOUT_TTL);
            await this.redisService.del(`otp:${email}`);

            this.logger.warn(`OTP locked for ${email} after ${this.MAX_ATTEMPTS} failed attempts`);

            throw new ForbiddenException(
                'Maximum OTP verification attempts exceeded. Locked for 10 minutes.',
            );
        }

        // Verify code
        if (otpData.code !== code) {
            // Increment attempt counter
            otpData.attempts += 1;
            const remainingTtl = await this.redisService.ttl(`otp:${email}`);
            await this.redisService.setJson(
                `otp:${email}`,
                otpData,
                remainingTtl > 0 ? remainingTtl : this.OTP_TTL,
            );

            throw new BadRequestException(
                `Invalid OTP. ${this.MAX_ATTEMPTS - otpData.attempts} attempts remaining.`,
            );
        }

        // OTP valid — clean up
        await this.redisService.del(`otp:${email}`);
        this.logger.log(`OTP verified for ${email}`);

        return true;
    }

    /**
     * Check if OTP is required based on role
     */
    isOtpRequired(role: Role): boolean {
        return role === Role.COMPANY || role === Role.ADMIN;
    }
}
