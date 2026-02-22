import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class AuditService {
    private readonly logger = new Logger(AuditService.name);

    constructor(private prisma: PrismaService) { }

    async createLog(
        userId: string,
        action: string,
        entity: string,
        entityId?: string,
        metadata?: Record<string, any>,
    ) {
        const log = await this.prisma.auditLog.create({
            data: {
                userId,
                action,
                entity,
                entityId,
                metadata,
            },
        });

        this.logger.log(
            `Audit: ${action} on ${entity}${entityId ? `(${entityId})` : ''} by user=${userId}`,
        );

        return log;
    }

    async getLogs(page = 1, limit = 50) {
        const skip = (page - 1) * limit;

        const [logs, total] = await Promise.all([
            this.prisma.auditLog.findMany({
                skip,
                take: limit,
                orderBy: { timestamp: 'desc' },
                include: {
                    user: {
                        select: { id: true, email: true, name: true, role: true },
                    },
                },
            }),
            this.prisma.auditLog.count(),
        ]);

        return {
            logs,
            meta: { total, page, limit, totalPages: Math.ceil(total / limit) },
        };
    }

    async getLogsByEntity(entity: string, entityId: string) {
        return this.prisma.auditLog.findMany({
            where: { entity, entityId },
            orderBy: { timestamp: 'desc' },
            include: {
                user: {
                    select: { id: true, email: true, name: true },
                },
            },
        });
    }
}
