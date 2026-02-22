import { Injectable, NotFoundException, Logger } from '@nestjs/common';
import { createHash } from 'crypto';
import { PrismaService } from '../../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class DeviceService {
    private readonly logger = new Logger(DeviceService.name);

    constructor(
        private prisma: PrismaService,
        private auditService: AuditService,
    ) { }

    /**
     * Hash the device fingerprint using SHA-256
     */
    hashFingerprint(fingerprint: string): string {
        return createHash('sha256').update(fingerprint).digest('hex');
    }

    /**
     * Check if a device fingerprint is known (trusted) for a user
     */
    async isKnownDevice(userId: string, fingerprint: string): Promise<boolean> {
        const hash = this.hashFingerprint(fingerprint);
        const device = await this.prisma.trustedDevice.findUnique({
            where: { userId_fingerprintHash: { userId, fingerprintHash: hash } },
        });
        return !!device && device.isTrusted;
    }

    /**
     * Register a new device for a user
     */
    async registerDevice(
        userId: string,
        fingerprint: string,
        ipAddress?: string,
        deviceName?: string,
        trusted = false,
    ) {
        const hash = this.hashFingerprint(fingerprint);

        const device = await this.prisma.trustedDevice.upsert({
            where: { userId_fingerprintHash: { userId, fingerprintHash: hash } },
            update: {
                lastUsedAt: new Date(),
                ipAddress,
                isTrusted: trusted,
            },
            create: {
                userId,
                fingerprintHash: hash,
                deviceName: deviceName || 'Unknown Device',
                ipAddress,
                isTrusted: trusted,
            },
        });

        if (!trusted) {
            this.logger.warn(`New untrusted device registered for user=${userId}`);
        }

        return device;
    }

    /**
     * Mark a device as trusted (after OTP verification)
     */
    async trustDevice(userId: string, fingerprint: string) {
        const hash = this.hashFingerprint(fingerprint);

        const device = await this.prisma.trustedDevice.findUnique({
            where: { userId_fingerprintHash: { userId, fingerprintHash: hash } },
        });

        if (!device) {
            throw new NotFoundException('Device not found');
        }

        return this.prisma.trustedDevice.update({
            where: { id: device.id },
            data: { isTrusted: true, lastUsedAt: new Date() },
        });
    }

    /**
     * Update last-used timestamp for a device
     */
    async updateDeviceActivity(userId: string, fingerprint: string) {
        const hash = this.hashFingerprint(fingerprint);
        await this.prisma.trustedDevice.updateMany({
            where: { userId, fingerprintHash: hash },
            data: { lastUsedAt: new Date() },
        });
    }

    /**
     * Get all devices for a user
     */
    async getUserDevices(userId: string) {
        return this.prisma.trustedDevice.findMany({
            where: { userId },
            select: {
                id: true,
                deviceName: true,
                ipAddress: true,
                isTrusted: true,
                lastUsedAt: true,
                createdAt: true,
            },
            orderBy: { lastUsedAt: 'desc' },
        });
    }

    /**
     * Revoke (delete) a device
     */
    async revokeDevice(userId: string, deviceId: string) {
        const device = await this.prisma.trustedDevice.findFirst({
            where: { id: deviceId, userId },
        });

        if (!device) {
            throw new NotFoundException('Device not found');
        }

        await this.prisma.trustedDevice.delete({ where: { id: deviceId } });

        await this.auditService.createLog(
            userId,
            'DEVICE_REVOKED',
            'TrustedDevice',
            deviceId,
            { fingerprintHash: device.fingerprintHash },
        );

        this.logger.log(`Device revoked: ${deviceId} for user=${userId}`);

        return { message: 'Device revoked successfully' };
    }
}
