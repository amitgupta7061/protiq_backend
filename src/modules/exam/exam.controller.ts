import {
    Controller,
    Get,
    Post,
    Patch,
    Delete,
    Body,
    Param,
    Query,
    UseGuards,
    ParseIntPipe,
    DefaultValuePipe,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { ExamService } from './exam.service';
import { CreateExamDto, UpdateExamDto, AddQuestionsDto } from './dto';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Roles } from '../../common/decorators/roles.decorator';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Public } from '../../common/decorators/public.decorator';

@ApiTags('Exams')
@ApiBearerAuth()
@Controller('exams')
export class ExamController {
    constructor(private readonly examService: ExamService) { }

    @Post()
    @UseGuards(RolesGuard)
    @Roles(Role.COMPANY)
    @ApiOperation({ summary: 'Create a new exam' })
    async createExam(
        @CurrentUser('id') userId: string,
        @Body() dto: CreateExamDto,
    ) {
        return this.examService.createExam(userId, dto);
    }

    @Patch(':id')
    @UseGuards(RolesGuard)
    @Roles(Role.COMPANY)
    @ApiOperation({ summary: 'Update an exam' })
    async updateExam(
        @Param('id') examId: string,
        @CurrentUser('id') userId: string,
        @Body() dto: UpdateExamDto,
    ) {
        return this.examService.updateExam(examId, userId, dto);
    }

    @Post(':id/questions')
    @UseGuards(RolesGuard)
    @Roles(Role.COMPANY)
    @ApiOperation({ summary: 'Add questions to an exam' })
    async addQuestions(
        @Param('id') examId: string,
        @CurrentUser('id') userId: string,
        @Body() dto: AddQuestionsDto,
    ) {
        return this.examService.addQuestions(examId, userId, dto);
    }

    @Patch(':id/publish')
    @UseGuards(RolesGuard)
    @Roles(Role.COMPANY)
    @ApiOperation({ summary: 'Toggle publish status of an exam' })
    async publishExam(
        @Param('id') examId: string,
        @CurrentUser('id') userId: string,
    ) {
        return this.examService.publishExam(examId, userId);
    }

    @Get('published')
    @ApiOperation({ summary: 'Get all published exams' })
    @ApiQuery({ name: 'page', required: false, type: Number })
    @ApiQuery({ name: 'limit', required: false, type: Number })
    async getAllPublishedExams(
        @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number,
        @Query('limit', new DefaultValuePipe(20), ParseIntPipe) limit: number,
    ) {
        return this.examService.getAllPublishedExams(page, limit);
    }

    @Get('my-exams')
    @UseGuards(RolesGuard)
    @Roles(Role.COMPANY)
    @ApiOperation({ summary: 'Get all exams by company' })
    @ApiQuery({ name: 'page', required: false, type: Number })
    @ApiQuery({ name: 'limit', required: false, type: Number })
    async getExamsByCompany(
        @CurrentUser('id') userId: string,
        @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number,
        @Query('limit', new DefaultValuePipe(20), ParseIntPipe) limit: number,
    ) {
        return this.examService.getExamsByCompany(userId, page, limit);
    }

    @Get(':id')
    @ApiOperation({ summary: 'Get exam by ID (without correct answers)' })
    async getExamById(@Param('id') examId: string) {
        return this.examService.getExamById(examId);
    }

    @Get(':id/details')
    @UseGuards(RolesGuard)
    @Roles(Role.COMPANY)
    @ApiOperation({ summary: 'Get exam with answers (Company only)' })
    async getExamWithAnswers(
        @Param('id') examId: string,
        @CurrentUser('id') userId: string,
    ) {
        return this.examService.getExamWithAnswers(examId, userId);
    }

    @Delete(':id')
    @UseGuards(RolesGuard)
    @Roles(Role.COMPANY)
    @ApiOperation({ summary: 'Soft delete an exam' })
    async deleteExam(
        @Param('id') examId: string,
        @CurrentUser('id') userId: string,
    ) {
        return this.examService.deleteExam(examId, userId);
    }
}
