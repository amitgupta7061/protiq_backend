import {
    Controller,
    Get,
    Query,
    UseGuards,
    ParseIntPipe,
    DefaultValuePipe,
    Param,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { AuditService } from './audit.service';
import { Roles } from '../../common/decorators/roles.decorator';
import { RolesGuard } from '../../common/guards/roles.guard';

@ApiTags('Audit Logs')
@ApiBearerAuth()
@UseGuards(RolesGuard)
@Roles(Role.ADMIN)
@Controller('audit')
export class AuditController {
    constructor(private readonly auditService: AuditService) { }

    @Get('logs')
    @ApiOperation({ summary: 'Get all audit logs (Admin only)' })
    @ApiQuery({ name: 'page', required: false, type: Number })
    @ApiQuery({ name: 'limit', required: false, type: Number })
    async getLogs(
        @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number,
        @Query('limit', new DefaultValuePipe(50), ParseIntPipe) limit: number,
    ) {
        return this.auditService.getLogs(page, limit);
    }

    @Get('logs/:entity/:entityId')
    @ApiOperation({ summary: 'Get audit logs by entity (Admin only)' })
    async getLogsByEntity(
        @Param('entity') entity: string,
        @Param('entityId') entityId: string,
    ) {
        return this.auditService.getLogsByEntity(entity, entityId);
    }
}
