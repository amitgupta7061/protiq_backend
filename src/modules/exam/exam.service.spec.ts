import { Test, TestingModule } from '@nestjs/testing';
import { ExamService } from './exam.service';
import { PrismaService } from '../../prisma/prisma.service';
import { NotFoundException, BadRequestException } from '@nestjs/common';

describe('ExamService', () => {
    let service: ExamService;

    const mockPrismaService = {
        company: {
            findUnique: jest.fn(),
        },
        exam: {
            create: jest.fn(),
            findUnique: jest.fn(),
            findMany: jest.fn(),
            update: jest.fn(),
            count: jest.fn(),
        },
        question: {
            createMany: jest.fn(),
            count: jest.fn(),
        },
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                ExamService,
                { provide: PrismaService, useValue: mockPrismaService },
            ],
        }).compile();

        service = module.get<ExamService>(ExamService);
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('createExam', () => {
        it('should create an exam successfully', async () => {
            const userId = 'user-id';
            const dto = {
                title: 'Test Exam',
                duration: 60,
                totalMarks: 100,
            };

            mockPrismaService.company.findUnique.mockResolvedValue({
                id: 'company-id',
                userId,
            });

            mockPrismaService.exam.create.mockResolvedValue({
                id: 'exam-id',
                ...dto,
                companyId: 'company-id',
                isPublished: false,
            });

            const result = await service.createExam(userId, dto);

            expect(result).toHaveProperty('id');
            expect(result.title).toBe(dto.title);
            expect(mockPrismaService.exam.create).toHaveBeenCalled();
        });

        it('should throw NotFoundException if company not found', async () => {
            mockPrismaService.company.findUnique.mockResolvedValue(null);

            await expect(
                service.createExam('no-company-user', {
                    title: 'Test',
                    duration: 60,
                    totalMarks: 100,
                }),
            ).rejects.toThrow(NotFoundException);
        });
    });

    describe('publishExam', () => {
        it('should throw BadRequestException if no questions', async () => {
            const userId = 'user-id';

            mockPrismaService.company.findUnique.mockResolvedValue({
                id: 'company-id',
                userId,
            });

            mockPrismaService.exam.findUnique.mockResolvedValue({
                id: 'exam-id',
                companyId: 'company-id',
                isPublished: false,
                isDeleted: false,
            });

            mockPrismaService.question.count.mockResolvedValue(0);

            await expect(
                service.publishExam('exam-id', userId),
            ).rejects.toThrow(BadRequestException);
        });
    });
});
