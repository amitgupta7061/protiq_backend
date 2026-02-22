import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { PrismaService } from '../../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RedisService } from '../../redis/redis.service';
import { OtpService } from '../otp/otp.service';
import { DeviceService } from '../device/device.service';
import { AuditService } from '../audit/audit.service';
import { EmailService } from '../otp/email.service';
import { ConflictException, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

describe('AuthService', () => {
    let service: AuthService;

    const mockPrismaService = {
        user: {
            findUnique: jest.fn(),
            create: jest.fn(),
            update: jest.fn(),
        },
    };

    const mockJwtService = {
        signAsync: jest.fn().mockResolvedValue('mock-token'),
        verifyAsync: jest.fn(),
    };

    const mockConfigService = {
        get: jest.fn((key: string) => {
            const config: Record<string, string> = {
                'jwt.accessSecret': 'test-access-secret',
                'jwt.refreshSecret': 'test-refresh-secret',
                'jwt.accessExpiry': '15m',
                'jwt.refreshExpiry': '7d',
            };
            return config[key];
        }),
    };

    const mockRedisService = {
        set: jest.fn(),
        del: jest.fn(),
        get: jest.fn(),
        exists: jest.fn().mockResolvedValue(false),
    };

    const mockOtpService = {
        sendOtp: jest.fn(),
        verifyOtp: jest.fn(),
        isOtpRequired: jest.fn().mockReturnValue(false),
    };

    const mockDeviceService = {
        isKnownDevice: jest.fn().mockResolvedValue(true),
        registerDevice: jest.fn(),
        updateDeviceActivity: jest.fn(),
        trustDevice: jest.fn(),
    };

    const mockAuditService = {
        createLog: jest.fn(),
    };

    const mockEmailService = {
        sendOtpEmail: jest.fn(),
        sendSecurityAlert: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                AuthService,
                { provide: PrismaService, useValue: mockPrismaService },
                { provide: JwtService, useValue: mockJwtService },
                { provide: ConfigService, useValue: mockConfigService },
                { provide: RedisService, useValue: mockRedisService },
                { provide: OtpService, useValue: mockOtpService },
                { provide: DeviceService, useValue: mockDeviceService },
                { provide: AuditService, useValue: mockAuditService },
                { provide: EmailService, useValue: mockEmailService },
            ],
        }).compile();

        service = module.get<AuthService>(AuthService);
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('register', () => {
        it('should register user and require OTP verification', async () => {
            const dto = {
                email: 'test@example.com',
                password: 'Test@123',
                name: 'Test User',
                role: 'CANDIDATE' as const,
            };

            mockPrismaService.user.findUnique.mockResolvedValue(null);
            mockPrismaService.user.create.mockResolvedValue({
                id: 'user-id',
                email: dto.email,
                name: dto.name,
                role: dto.role,
            });

            const result = await service.register(dto);

            expect(result).toHaveProperty('requiresOtpVerification', true);
            expect(result.user.email).toBe(dto.email);
            expect(mockOtpService.sendOtp).toHaveBeenCalledWith(dto.email);
        });

        it('should throw ConflictException if email already exists', async () => {
            mockPrismaService.user.findUnique.mockResolvedValue({
                id: 'existing-user',
            });

            await expect(
                service.register({
                    email: 'existing@example.com',
                    password: 'Test@123',
                    name: 'Test',
                    role: 'CANDIDATE' as const,
                }),
            ).rejects.toThrow(ConflictException);
        });
    });

    describe('login', () => {
        it('should throw UnauthorizedException for invalid email', async () => {
            mockPrismaService.user.findUnique.mockResolvedValue(null);

            await expect(
                service.login({
                    email: 'nonexistent@example.com',
                    password: 'Test@123',
                }),
            ).rejects.toThrow(UnauthorizedException);
        });

        it('should throw ForbiddenException for locked account', async () => {
            mockPrismaService.user.findUnique.mockResolvedValue({
                id: 'user-id',
                email: 'test@example.com',
                isActive: true,
                lockedUntil: new Date(Date.now() + 1000 * 60 * 30), // 30 min in future
                failedLoginAttempts: 5,
            });

            await expect(
                service.login({
                    email: 'test@example.com',
                    password: 'Test@123',
                }),
            ).rejects.toThrow(ForbiddenException);
        });

        it('should login successfully with known device', async () => {
            const hashedPassword = await bcrypt.hash('Test@123', 12);

            mockPrismaService.user.findUnique.mockResolvedValue({
                id: 'user-id',
                email: 'test@example.com',
                password: hashedPassword,
                name: 'Test User',
                role: 'CANDIDATE',
                isActive: true,
                isEmailVerified: true,
                isTwoFactorEnabled: false,
                failedLoginAttempts: 0,
                lockedUntil: null,
            });
            mockPrismaService.user.update.mockResolvedValue({});
            mockDeviceService.isKnownDevice.mockResolvedValue(true);

            const result = await service.login({
                email: 'test@example.com',
                password: 'Test@123',
                deviceFingerprint: 'known-fp',
            });

            expect(result).toHaveProperty('accessToken');
            expect(result).toHaveProperty('refreshToken');
        });

        it('should require OTP for new device', async () => {
            const hashedPassword = await bcrypt.hash('Test@123', 12);

            mockPrismaService.user.findUnique.mockResolvedValue({
                id: 'user-id',
                email: 'test@example.com',
                password: hashedPassword,
                name: 'Test User',
                role: 'CANDIDATE',
                isActive: true,
                isEmailVerified: true,
                isTwoFactorEnabled: false,
                failedLoginAttempts: 0,
                lockedUntil: null,
            });
            mockPrismaService.user.update.mockResolvedValue({});
            mockDeviceService.isKnownDevice.mockResolvedValue(false);

            const result = await service.login({
                email: 'test@example.com',
                password: 'Test@123',
                deviceFingerprint: 'new-fp',
            });

            expect(result).toHaveProperty('requiresOtpVerification', true);
            expect(mockOtpService.sendOtp).toHaveBeenCalled();
        });
    });
});
