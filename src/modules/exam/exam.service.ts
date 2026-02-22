import {
    Injectable,
    NotFoundException,
    ForbiddenException,
    BadRequestException,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import {
    CreateExamDto,
    UpdateExamDto,
    AddQuestionsDto,
} from './dto';

@Injectable()
export class ExamService {
    constructor(private prisma: PrismaService) { }

    async createExam(companyId: string, dto: CreateExamDto) {
        const company = await this.prisma.company.findUnique({
            where: { userId: companyId },
        });

        if (!company) {
            throw new NotFoundException(
                'Company profile not found. Create a company profile first.',
            );
        }

        return this.prisma.exam.create({
            data: {
                title: dto.title,
                description: dto.description,
                duration: dto.duration,
                totalMarks: dto.totalMarks,
                allowMultipleAttempts: dto.allowMultipleAttempts ?? false,
                companyId: company.id,
            },
        });
    }

    async updateExam(examId: string, userId: string, dto: UpdateExamDto) {
        const exam = await this.findExamByOwner(examId, userId);

        if (exam.isPublished) {
            throw new BadRequestException(
                'Cannot update a published exam. Unpublish it first.',
            );
        }

        return this.prisma.exam.update({
            where: { id: examId },
            data: { ...dto },
        });
    }

    async addQuestions(examId: string, userId: string, dto: AddQuestionsDto) {
        await this.findExamByOwner(examId, userId);

        const questions = dto.questions.map((q) => ({
            examId,
            questionText: q.questionText,
            options: q.options,
            correctAnswer: q.correctAnswer,
            marks: q.marks,
        }));

        await this.prisma.question.createMany({ data: questions });

        return this.prisma.exam.findUnique({
            where: { id: examId },
            include: { questions: true },
        });
    }

    async publishExam(examId: string, userId: string) {
        const exam = await this.findExamByOwner(examId, userId);

        const questionCount = await this.prisma.question.count({
            where: { examId },
        });

        if (questionCount === 0) {
            throw new BadRequestException(
                'Cannot publish exam without questions',
            );
        }

        return this.prisma.exam.update({
            where: { id: examId },
            data: { isPublished: !exam.isPublished },
        });
    }

    async getExamById(examId: string) {
        const exam = await this.prisma.exam.findUnique({
            where: { id: examId, isDeleted: false },
            include: {
                questions: {
                    select: {
                        id: true,
                        questionText: true,
                        options: true,
                        marks: true,
                        // NOTE: correctAnswer excluded for candidates
                    },
                },
                company: {
                    select: { id: true, name: true },
                },
            },
        });

        if (!exam) {
            throw new NotFoundException('Exam not found');
        }

        return exam;
    }

    async getExamWithAnswers(examId: string, userId: string) {
        await this.findExamByOwner(examId, userId);

        return this.prisma.exam.findUnique({
            where: { id: examId },
            include: { questions: true, company: true },
        });
    }

    async getExamsByCompany(userId: string, page = 1, limit = 20) {
        const company = await this.prisma.company.findUnique({
            where: { userId },
        });

        if (!company) {
            throw new NotFoundException('Company profile not found');
        }

        const skip = (page - 1) * limit;

        const [exams, total] = await Promise.all([
            this.prisma.exam.findMany({
                where: { companyId: company.id, isDeleted: false },
                skip,
                take: limit,
                orderBy: { createdAt: 'desc' },
                include: {
                    _count: { select: { questions: true, attempts: true } },
                },
            }),
            this.prisma.exam.count({
                where: { companyId: company.id, isDeleted: false },
            }),
        ]);

        return {
            exams,
            meta: { total, page, limit, totalPages: Math.ceil(total / limit) },
        };
    }

    async getAllPublishedExams(page = 1, limit = 20) {
        const skip = (page - 1) * limit;

        const [exams, total] = await Promise.all([
            this.prisma.exam.findMany({
                where: { isPublished: true, isDeleted: false },
                skip,
                take: limit,
                orderBy: { createdAt: 'desc' },
                include: {
                    company: { select: { id: true, name: true } },
                    _count: { select: { questions: true } },
                },
            }),
            this.prisma.exam.count({
                where: { isPublished: true, isDeleted: false },
            }),
        ]);

        return {
            exams,
            meta: { total, page, limit, totalPages: Math.ceil(total / limit) },
        };
    }

    async deleteExam(examId: string, userId: string) {
        await this.findExamByOwner(examId, userId);

        return this.prisma.exam.update({
            where: { id: examId },
            data: { isDeleted: true },
        });
    }

    private async findExamByOwner(examId: string, userId: string) {
        const company = await this.prisma.company.findUnique({
            where: { userId },
        });

        if (!company) {
            throw new NotFoundException('Company profile not found');
        }

        const exam = await this.prisma.exam.findUnique({
            where: { id: examId, isDeleted: false },
        });

        if (!exam) {
            throw new NotFoundException('Exam not found');
        }

        if (exam.companyId !== company.id) {
            throw new ForbiddenException('Not authorized to modify this exam');
        }

        return exam;
    }
}
