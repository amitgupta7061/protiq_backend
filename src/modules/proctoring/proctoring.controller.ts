import {
    Controller,
    Get,
    Post,
    Body,
    Param,
    Query,
    UseGuards,
    ParseIntPipe,
    DefaultValuePipe,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { ProctoringService } from './proctoring.service';
import { CreateProctoringLogDto } from './dto';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Roles } from '../../common/decorators/roles.decorator';
import { RolesGuard } from '../../common/guards/roles.guard';

@ApiTags('Proctoring')
@ApiBearerAuth()
@Controller('proctoring')
export class ProctoringController {
    constructor(private readonly proctoringService: ProctoringService) { }

    @Post('log')
    @UseGuards(RolesGuard)
    @Roles(Role.CANDIDATE)
    @ApiOperation({ summary: 'Log a proctoring event (tab switch, fullscreen exit, etc.)' })
    async logEvent(
        @CurrentUser('id') candidateId: string,
        @Body() dto: CreateProctoringLogDto,
    ) {
        return this.proctoringService.logEvent(candidateId, dto);
    }

    @Get('logs/:attemptId')
    @ApiOperation({ summary: 'Get proctoring logs for an attempt' })
    async getLogsByAttempt(
        @Param('attemptId') attemptId: string,
        @CurrentUser('id') userId: string,
    ) {
        return this.proctoringService.getLogsByAttempt(attemptId, userId);
    }

    @Get('flagged')
    @UseGuards(RolesGuard)
    @Roles(Role.COMPANY)
    @ApiOperation({ summary: 'Get all flagged attempts for company exams' })
    @ApiQuery({ name: 'page', required: false, type: Number })
    @ApiQuery({ name: 'limit', required: false, type: Number })
    async getFlaggedAttempts(
        @CurrentUser('id') userId: string,
        @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number,
        @Query('limit', new DefaultValuePipe(20), ParseIntPipe) limit: number,
    ) {
        return this.proctoringService.getFlaggedAttempts(userId, page, limit);
    }
}
