import {
    Injectable,
    NotFoundException,
    BadRequestException,
    Logger,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { CreateProctoringLogDto } from './dto';
import { ProctoringEventType, AttemptStatus } from '@prisma/client';

// Suspicious score weights for each event type
const SCORE_WEIGHTS: Record<ProctoringEventType, number> = {
    TAB_SWITCH: 2,
    FULLSCREEN_EXIT: 3,
    SUSPICIOUS_ACTIVITY: 5,
};

const FLAG_THRESHOLD = 15;

@Injectable()
export class ProctoringService {
    private readonly logger = new Logger(ProctoringService.name);

    constructor(
        private prisma: PrismaService,
        private auditService: AuditService,
    ) { }

    async logEvent(candidateId: string, dto: CreateProctoringLogDto) {
        // Verify attempt belongs to candidate and is in progress
        const attempt = await this.prisma.attempt.findUnique({
            where: { id: dto.attemptId },
        });

        if (!attempt) {
            throw new NotFoundException('Attempt not found');
        }

        if (attempt.candidateId !== candidateId) {
            throw new BadRequestException('Not authorized');
        }

        if (attempt.status !== AttemptStatus.IN_PROGRESS) {
            throw new BadRequestException('Attempt is not in progress');
        }

        // Create proctoring log with enhanced fields
        const log = await this.prisma.proctoringLog.create({
            data: {
                attemptId: dto.attemptId,
                candidateId,
                type: dto.type,
                details: dto.details,
                ipAddress: dto.ipAddress,
                deviceFingerprint: dto.deviceFingerprint,
                geoLocation: dto.geoLocation ?? undefined,
            },
        });

        // ── Calculate suspicious score increment ──
        const scoreIncrement = SCORE_WEIGHTS[dto.type] || 1;
        const newScore = attempt.suspiciousScore + scoreIncrement;

        const updateData: Record<string, any> = {
            suspiciousScore: newScore,
        };

        // Increment tab switch count for TAB_SWITCH events
        if (dto.type === ProctoringEventType.TAB_SWITCH) {
            updateData.tabSwitchCount = { increment: 1 };
        }

        // Store device fingerprint and IP on the attempt if not already set
        if (dto.deviceFingerprint && !attempt.deviceFingerprint) {
            updateData.deviceFingerprint = dto.deviceFingerprint;
        }
        if (dto.ipAddress && !attempt.ipAddress) {
            updateData.ipAddress = dto.ipAddress;
        }
        if (dto.geoLocation && !attempt.geoLocation) {
            updateData.geoLocation = dto.geoLocation;
        }

        // ── Auto-flag attempt if threshold exceeded ──
        if (newScore >= FLAG_THRESHOLD && !attempt.isFlagged) {
            updateData.isFlagged = true;

            await this.auditService.createLog(
                candidateId,
                'SUSPICIOUS_ATTEMPT_FLAGGED',
                'Attempt',
                attempt.id,
                {
                    suspiciousScore: newScore,
                    threshold: FLAG_THRESHOLD,
                    triggerEvent: dto.type,
                },
            );

            this.logger.warn(
                `⚠️ ATTEMPT AUTO-FLAGGED: attempt=${attempt.id}, score=${newScore}, candidate=${candidateId}`,
            );
        }

        await this.prisma.attempt.update({
            where: { id: dto.attemptId },
            data: updateData,
        });

        this.logger.warn(
            `Proctoring event: ${dto.type} for attempt=${dto.attemptId}, candidate=${candidateId}, score=${newScore}`,
        );

        return log;
    }

    async getLogsByAttempt(attemptId: string, userId: string) {
        const attempt = await this.prisma.attempt.findUnique({
            where: { id: attemptId },
            include: { exam: { include: { company: true } } },
        });

        if (!attempt) {
            throw new NotFoundException('Attempt not found');
        }

        if (
            attempt.candidateId !== userId &&
            attempt.exam.company.userId !== userId
        ) {
            throw new BadRequestException('Not authorized to view these logs');
        }

        return this.prisma.proctoringLog.findMany({
            where: { attemptId },
            orderBy: { timestamp: 'asc' },
        });
    }

    async getFlaggedAttempts(companyUserId: string, page = 1, limit = 20) {
        const company = await this.prisma.company.findUnique({
            where: { userId: companyUserId },
        });

        if (!company) {
            throw new NotFoundException('Company not found');
        }

        const skip = (page - 1) * limit;

        const [attempts, total] = await Promise.all([
            this.prisma.attempt.findMany({
                where: {
                    isFlagged: true,
                    exam: { companyId: company.id },
                },
                skip,
                take: limit,
                orderBy: { suspiciousScore: 'desc' },
                include: {
                    candidate: { select: { id: true, email: true, name: true } },
                    exam: { select: { id: true, title: true } },
                    _count: { select: { proctoringLogs: true } },
                },
            }),
            this.prisma.attempt.count({
                where: {
                    isFlagged: true,
                    exam: { companyId: company.id },
                },
            }),
        ]);

        return {
            attempts,
            meta: { total, page, limit, totalPages: Math.ceil(total / limit) },
        };
    }
}
