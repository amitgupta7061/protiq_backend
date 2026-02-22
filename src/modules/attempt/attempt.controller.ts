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
import { AttemptService } from './attempt.service';
import { SubmitAttemptDto } from './dto';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Roles } from '../../common/decorators/roles.decorator';
import { RolesGuard } from '../../common/guards/roles.guard';
import { RateLimit } from '../../common/guards/custom-throttle.guard';

@ApiTags('Attempts')
@ApiBearerAuth()
@Controller('attempts')
export class AttemptController {
    constructor(private readonly attemptService: AttemptService) { }

    @Post('start/:examId')
    @UseGuards(RolesGuard)
    @Roles(Role.CANDIDATE)
    @RateLimit({ limit: 3, windowSec: 60, keyPrefix: 'exam-start' })
    @ApiOperation({ summary: 'Start an exam attempt' })
    async startAttempt(
        @CurrentUser('id') candidateId: string,
        @Param('examId') examId: string,
    ) {
        return this.attemptService.startAttempt(candidateId, examId);
    }

    @Post(':id/submit')
    @UseGuards(RolesGuard)
    @Roles(Role.CANDIDATE)
    @ApiOperation({ summary: 'Submit exam attempt' })
    async submitAttempt(
        @Param('id') attemptId: string,
        @CurrentUser('id') candidateId: string,
        @Body() dto: SubmitAttemptDto,
    ) {
        return this.attemptService.submitAttempt(attemptId, candidateId, dto);
    }

    @Get('my-attempts')
    @UseGuards(RolesGuard)
    @Roles(Role.CANDIDATE)
    @ApiOperation({ summary: 'Get all my exam attempts' })
    async getMyAttempts(@CurrentUser('id') candidateId: string) {
        return this.attemptService.getMyCandidateAttempts(candidateId);
    }

    @Get(':id/result')
    @ApiOperation({ summary: 'Get attempt result' })
    async getAttemptResult(
        @Param('id') attemptId: string,
        @CurrentUser('id') userId: string,
    ) {
        return this.attemptService.getAttemptResult(attemptId, userId);
    }

    @Get('exam/:examId')
    @UseGuards(RolesGuard)
    @Roles(Role.COMPANY)
    @ApiOperation({ summary: 'Get all attempts for an exam (Company only)' })
    @ApiQuery({ name: 'page', required: false, type: Number })
    @ApiQuery({ name: 'limit', required: false, type: Number })
    async getAttemptsByExam(
        @Param('examId') examId: string,
        @CurrentUser('id') userId: string,
        @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number,
        @Query('limit', new DefaultValuePipe(20), ParseIntPipe) limit: number,
    ) {
        return this.attemptService.getAttemptsByExam(examId, userId, page, limit);
    }
}
