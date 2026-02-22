import {
    Injectable,
    ConflictException,
    UnauthorizedException,
    ForbiddenException,
    Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { randomUUID, createHash } from 'crypto';
import { PrismaService } from '../../prisma/prisma.service';
import { RedisService } from '../../redis/redis.service';
import { OtpService } from '../otp/otp.service';
import { DeviceService } from '../device/device.service';
import { AuditService } from '../audit/audit.service';
import { EmailService } from '../otp/email.service';
import { RegisterDto, LoginDto, RefreshTokenDto, VerifyLoginOtpDto } from './dto';
import { Role } from '@prisma/client';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);
    private readonly MAX_LOGIN_ATTEMPTS = 5;
    private readonly LOCKOUT_DURATION_MS = 30 * 60 * 1000; // 30 minutes

    constructor(
        private prisma: PrismaService,
        private jwtService: JwtService,
        private configService: ConfigService,
        private redisService: RedisService,
        private otpService: OtpService,
        private deviceService: DeviceService,
        private auditService: AuditService,
        private emailService: EmailService,
    ) { }

    // ─────────────────────────────────────────────
    // REGISTER
    // ─────────────────────────────────────────────

    async register(dto: RegisterDto) {
        if (dto.role === Role.ADMIN) {
            throw new ForbiddenException('Cannot register as admin');
        }

        const existingUser = await this.prisma.user.findUnique({
            where: { email: dto.email },
        });

        if (existingUser) {
            throw new ConflictException('Email already registered');
        }

        const hashedPassword = await bcrypt.hash(dto.password, 12);

        const user = await this.prisma.user.create({
            data: {
                email: dto.email,
                password: hashedPassword,
                name: dto.name,
                role: dto.role,
                isEmailVerified: false,
                isTwoFactorEnabled: dto.role === Role.COMPANY, // Auto-enable 2FA for companies
            },
        });

        // Send OTP for email verification
        await this.otpService.sendOtp(user.email);

        this.logger.log(`User registered (pending OTP): ${user.email} (${user.role})`);

        return {
            requiresOtpVerification: true,
            message: 'Registration successful. Please verify your email with the OTP sent.',
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
            },
        };
    }

    /**
     * Complete registration by verifying OTP
     */
    async verifyRegistrationOtp(email: string, code: string) {
        await this.otpService.verifyOtp(email, code);

        const user = await this.prisma.user.update({
            where: { email },
            data: { isEmailVerified: true },
        });

        const tokens = await this.generateTokens(user.id, user.email, user.role);
        await this.updateRefreshToken(user.id, tokens.refreshToken);

        await this.auditService.createLog(user.id, 'EMAIL_VERIFIED', 'User', user.id);

        this.logger.log(`Email verified for ${email}`);

        return {
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
            },
            ...tokens,
        };
    }

    // ─────────────────────────────────────────────
    // LOGIN (with lockout, device check, OTP)
    // ─────────────────────────────────────────────

    async login(dto: LoginDto, ipAddress?: string) {
        const user = await this.prisma.user.findUnique({
            where: { email: dto.email },
        });

        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }

        if (!user.isActive) {
            throw new ForbiddenException('Account has been deactivated');
        }

        // ── Account lockout check ──
        if (user.lockedUntil && user.lockedUntil > new Date()) {
            const remainingMs = user.lockedUntil.getTime() - Date.now();
            const remainingMin = Math.ceil(remainingMs / 60000);
            throw new ForbiddenException(
                `Account locked. Try again in ${remainingMin} minute(s).`,
            );
        }

        // Auto-unlock if lockout expired
        if (user.lockedUntil && user.lockedUntil <= new Date()) {
            await this.prisma.user.update({
                where: { id: user.id },
                data: { failedLoginAttempts: 0, lockedUntil: null },
            });
        }

        // ── Validate password ──
        const isPasswordValid = await bcrypt.compare(dto.password, user.password);

        if (!isPasswordValid) {
            const attempts = user.failedLoginAttempts + 1;
            const updateData: Record<string, any> = { failedLoginAttempts: attempts };

            if (attempts >= this.MAX_LOGIN_ATTEMPTS) {
                updateData.lockedUntil = new Date(Date.now() + this.LOCKOUT_DURATION_MS);

                await this.auditService.createLog(
                    user.id, 'ACCOUNT_LOCKED', 'User', user.id,
                    { reason: 'max_failed_login', attempts },
                );

                await this.emailService.sendSecurityAlert(
                    user.email,
                    'Account Locked',
                    `Your account has been locked due to ${attempts} failed login attempts.`,
                );

                this.logger.warn(`Account locked: ${user.email} after ${attempts} failed attempts`);
            }

            await this.prisma.user.update({
                where: { id: user.id },
                data: updateData,
            });

            throw new UnauthorizedException('Invalid credentials');
        }

        // ── Email verification check ──
        if (!user.isEmailVerified) {
            await this.otpService.sendOtp(user.email);
            return {
                requiresOtpVerification: true,
                otpPurpose: 'email_verification',
                message: 'Please verify your email first. OTP has been sent.',
            };
        }

        // Reset failed login attempts on successful credentials
        if (user.failedLoginAttempts > 0) {
            await this.prisma.user.update({
                where: { id: user.id },
                data: { failedLoginAttempts: 0, lockedUntil: null },
            });
        }

        // ── Device fingerprint check ──
        const requiresOtp = await this.shouldRequireOtp(user, dto.deviceFingerprint);

        if (requiresOtp) {
            await this.otpService.sendOtp(user.email);

            // If device fingerprint provided, register as untrusted
            if (dto.deviceFingerprint) {
                await this.deviceService.registerDevice(
                    user.id,
                    dto.deviceFingerprint,
                    ipAddress,
                    dto.deviceName,
                    false,
                );

                await this.auditService.createLog(
                    user.id, 'NEW_DEVICE_LOGIN', 'TrustedDevice', undefined,
                    { ipAddress, deviceName: dto.deviceName },
                );
            }

            return {
                requiresOtpVerification: true,
                otpPurpose: user.isTwoFactorEnabled ? '2fa' : 'new_device',
                message: 'OTP verification required.',
            };
        }

        // ── No OTP needed — issue tokens directly ──
        if (dto.deviceFingerprint) {
            await this.deviceService.updateDeviceActivity(user.id, dto.deviceFingerprint);
        }

        return this.issueTokens(user);
    }

    /**
     * Complete login with OTP verification
     */
    async verifyLoginOtp(dto: VerifyLoginOtpDto, ipAddress?: string) {
        await this.otpService.verifyOtp(dto.email, dto.code);

        const user = await this.prisma.user.findUnique({
            where: { email: dto.email },
        });

        if (!user) {
            throw new UnauthorizedException('User not found');
        }

        // Mark email as verified if not already
        if (!user.isEmailVerified) {
            await this.prisma.user.update({
                where: { id: user.id },
                data: { isEmailVerified: true },
            });
        }

        // Trust the device after OTP verification
        if (dto.deviceFingerprint) {
            await this.deviceService.registerDevice(
                user.id,
                dto.deviceFingerprint,
                ipAddress,
                dto.deviceName,
                true, // trusted after OTP
            );
        }

        return this.issueTokens(user);
    }

    // ─────────────────────────────────────────────
    // TOKEN REFRESH (with family tracking + reuse detection)
    // ─────────────────────────────────────────────

    async refreshTokens(dto: RefreshTokenDto) {
        let payload: any;
        try {
            payload = await this.jwtService.verifyAsync(dto.refreshToken, {
                secret: this.configService.get<string>('jwt.refreshSecret'),
            });
        } catch {
            throw new UnauthorizedException('Invalid or expired refresh token');
        }

        const user = await this.prisma.user.findUnique({
            where: { id: payload.sub },
        });

        if (!user || !user.refreshToken) {
            throw new UnauthorizedException('Access denied');
        }

        // ── Check if token is blacklisted ──
        const tokenHash = createHash('sha256').update(dto.refreshToken).digest('hex');
        const isBlacklisted = await this.redisService.exists(`rt:blacklist:${tokenHash}`);
        if (isBlacklisted) {
            // Token reuse detected — force logout
            await this.forceLogout(user.id, 'Token reuse detected');
            throw new UnauthorizedException('Security violation: token reuse detected. All sessions invalidated.');
        }

        // ── Validate refresh token ──
        const isRefreshTokenValid = await bcrypt.compare(dto.refreshToken, user.refreshToken);
        if (!isRefreshTokenValid) {
            throw new UnauthorizedException('Access denied');
        }

        // ── Blacklist the old refresh token ──
        await this.redisService.set(`rt:blacklist:${tokenHash}`, '1', 604800); // 7 days

        // ── Generate new tokens with same family ──
        const tokens = await this.generateTokens(user.id, user.email, user.role);
        await this.updateRefreshToken(user.id, tokens.refreshToken);

        return tokens;
    }

    // ─────────────────────────────────────────────
    // LOGOUT
    // ─────────────────────────────────────────────

    async logout(userId: string) {
        const user = await this.prisma.user.findUnique({ where: { id: userId } });

        // Blacklist current refresh token
        if (user?.refreshToken) {
            // We can't reverse the hash, but we invalidate the stored token
            await this.prisma.user.update({
                where: { id: userId },
                data: { refreshToken: null, refreshTokenFamily: null },
            });
        }

        await this.redisService.del(`session:${userId}`);
        this.logger.log(`User logged out: ${userId}`);
    }

    /**
     * Force logout — invalidate all tokens and sessions (on security violations)
     */
    async forceLogout(userId: string, reason: string) {
        await this.prisma.user.update({
            where: { id: userId },
            data: { refreshToken: null, refreshTokenFamily: null },
        });

        await this.redisService.del(`session:${userId}`);

        await this.auditService.createLog(
            userId, 'TOKEN_REUSE_DETECTED', 'User', userId,
            { reason },
        );

        await this.emailService.sendSecurityAlert(
            (await this.prisma.user.findUnique({ where: { id: userId } }))?.email || '',
            'Security Alert: Forced Logout',
            `All sessions invalidated. Reason: ${reason}`,
        );

        this.logger.warn(`Force logout for user=${userId}: ${reason}`);
    }

    // ─────────────────────────────────────────────
    // ADMIN: UNLOCK ACCOUNT
    // ─────────────────────────────────────────────

    async unlockAccount(userId: string, adminId: string) {
        const user = await this.prisma.user.findUnique({ where: { id: userId } });
        if (!user) {
            throw new UnauthorizedException('User not found');
        }

        await this.prisma.user.update({
            where: { id: userId },
            data: { failedLoginAttempts: 0, lockedUntil: null },
        });

        await this.auditService.createLog(
            adminId, 'ACCOUNT_UNLOCKED', 'User', userId,
            { unlockedBy: adminId },
        );

        this.logger.log(`Account unlocked: ${userId} by admin=${adminId}`);

        return { message: 'Account unlocked successfully' };
    }

    // ─────────────────────────────────────────────
    // PRIVATE HELPERS
    // ─────────────────────────────────────────────

    private async shouldRequireOtp(
        user: { id: string; role: Role; isTwoFactorEnabled: boolean },
        deviceFingerprint?: string,
    ): Promise<boolean> {
        // 2FA always requires OTP
        if (user.isTwoFactorEnabled) {
            return true;
        }

        // If no fingerprint, require OTP for COMPANY/ADMIN
        if (!deviceFingerprint) {
            return this.otpService.isOtpRequired(user.role);
        }

        // If device is unknown, require OTP
        const isKnown = await this.deviceService.isKnownDevice(user.id, deviceFingerprint);
        if (!isKnown) {
            return true;
        }

        return false;
    }

    private async issueTokens(user: { id: string; email: string; name: string; role: Role }) {
        const tokens = await this.generateTokens(user.id, user.email, user.role);
        await this.updateRefreshToken(user.id, tokens.refreshToken);

        this.logger.log(`User logged in: ${user.email}`);

        return {
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
            },
            ...tokens,
        };
    }

    private async generateTokens(userId: string, email: string, role: Role) {
        const family = randomUUID();
        const payload = { sub: userId, email, role, family };

        const [accessToken, refreshToken] = await Promise.all([
            this.jwtService.signAsync(payload, {
                secret: this.configService.get<string>('jwt.accessSecret') ?? 'access-secret',
                expiresIn: 900,
            }),
            this.jwtService.signAsync(payload, {
                secret: this.configService.get<string>('jwt.refreshSecret') ?? 'refresh-secret',
                expiresIn: 604800,
            }),
        ]);

        // Store token family + session
        await Promise.all([
            this.redisService.set(
                `rt:family:${userId}`,
                family,
                604800,
            ),
            this.redisService.set(
                `session:${userId}`,
                JSON.stringify({ email, role }),
                604800,
            ),
        ]);

        // Update family on user record
        await this.prisma.user.update({
            where: { id: userId },
            data: { refreshTokenFamily: family },
        });

        return { accessToken, refreshToken };
    }

    private async updateRefreshToken(userId: string, refreshToken: string) {
        const hashedRefreshToken = await bcrypt.hash(refreshToken, 12);
        await this.prisma.user.update({
            where: { id: userId },
            data: { refreshToken: hashedRefreshToken },
        });
    }
}
