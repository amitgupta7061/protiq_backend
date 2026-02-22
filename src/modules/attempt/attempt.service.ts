import {
    Injectable,
    NotFoundException,
    BadRequestException,
    ConflictException,
    Logger,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { SubmitAttemptDto } from './dto';
import { AttemptStatus } from '@prisma/client';

@Injectable()
export class AttemptService {
    private readonly logger = new Logger(AttemptService.name);

    constructor(private prisma: PrismaService) { }

    async startAttempt(candidateId: string, examId: string) {
        // Verify exam exists, is published, and not deleted
        const exam = await this.prisma.exam.findUnique({
            where: { id: examId, isDeleted: false },
        });

        if (!exam) {
            throw new NotFoundException('Exam not found');
        }

        if (!exam.isPublished) {
            throw new BadRequestException('Exam is not published yet');
        }

        // Check for existing attempt
        const existingAttempt = await this.prisma.attempt.findUnique({
            where: {
                candidateId_examId: { candidateId, examId },
            },
        });

        if (existingAttempt) {
            if (!exam.allowMultipleAttempts) {
                if (existingAttempt.status === AttemptStatus.IN_PROGRESS) {
                    // Check if time expired server-side
                    const elapsed =
                        (Date.now() - existingAttempt.startedAt.getTime()) / 60000;
                    if (elapsed >= exam.duration) {
                        // Auto-submit expired attempt
                        return this.autoSubmitAttempt(existingAttempt.id);
                    }
                    return existingAttempt; // Return in-progress attempt
                }
                throw new ConflictException(
                    'You have already attempted this exam. Multiple attempts not allowed.',
                );
            } else {
                if (existingAttempt.status === AttemptStatus.IN_PROGRESS) {
                    const elapsed =
                        (Date.now() - existingAttempt.startedAt.getTime()) / 60000;
                    if (elapsed >= exam.duration) {
                        await this.autoSubmitAttempt(existingAttempt.id);
                    } else {
                        return existingAttempt;
                    }
                }
                // Delete previous completed attempt for new one (multiple allowed)
                await this.prisma.attempt.delete({
                    where: { id: existingAttempt.id },
                });
            }
        }

        const attempt = await this.prisma.attempt.create({
            data: {
                candidateId,
                examId,
                status: AttemptStatus.IN_PROGRESS,
            },
        });

        this.logger.log(
            `Attempt started: candidate=${candidateId}, exam=${examId}`,
        );

        return attempt;
    }

    async submitAttempt(attemptId: string, candidateId: string, dto: SubmitAttemptDto) {
        const attempt = await this.prisma.attempt.findUnique({
            where: { id: attemptId },
            include: { exam: true },
        });

        if (!attempt) {
            throw new NotFoundException('Attempt not found');
        }

        if (attempt.candidateId !== candidateId) {
            throw new BadRequestException('Not authorized to submit this attempt');
        }

        if (attempt.status !== AttemptStatus.IN_PROGRESS) {
            throw new ConflictException('This attempt has already been submitted');
        }

        // Server-side time validation
        const elapsedMinutes =
            (Date.now() - attempt.startedAt.getTime()) / 60000;

        let status: AttemptStatus = AttemptStatus.SUBMITTED;
        if (elapsedMinutes > attempt.exam.duration) {
            status = AttemptStatus.AUTO_SUBMITTED;
        }

        // Calculate score
        const score = await this.calculateScore(attempt.examId, dto.answers);

        const updatedAttempt = await this.prisma.attempt.update({
            where: { id: attemptId },
            data: {
                answers: dto.answers,
                score,
                status,
                submittedAt: new Date(),
            },
        });

        this.logger.log(
            `Attempt submitted: id=${attemptId}, score=${score}, status=${status}`,
        );

        return updatedAttempt;
    }

    async autoSubmitAttempt(attemptId: string) {
        const attempt = await this.prisma.attempt.findUnique({
            where: { id: attemptId },
        });

        if (!attempt || attempt.status !== AttemptStatus.IN_PROGRESS) {
            return attempt;
        }

        // Calculate score on whatever answers were saved
        const answers = (attempt.answers as Record<string, string>) || {};
        const score = await this.calculateScore(attempt.examId, answers);

        const updated = await this.prisma.attempt.update({
            where: { id: attemptId },
            data: {
                score,
                status: AttemptStatus.AUTO_SUBMITTED,
                submittedAt: new Date(),
            },
        });

        this.logger.log(`Attempt auto-submitted: id=${attemptId}, score=${score}`);

        return updated;
    }

    async getAttemptResult(attemptId: string, userId: string) {
        const attempt = await this.prisma.attempt.findUnique({
            where: { id: attemptId },
            include: {
                exam: {
                    select: {
                        id: true,
                        title: true,
                        totalMarks: true,
                        duration: true,
                        company: { select: { name: true } },
                    },
                },
            },
        });

        if (!attempt) {
            throw new NotFoundException('Attempt not found');
        }

        if (attempt.candidateId !== userId) {
            // Check if user is company owner
            const exam = await this.prisma.exam.findUnique({
                where: { id: attempt.examId },
                include: { company: true },
            });

            if (!exam || exam.company.userId !== userId) {
                throw new BadRequestException('Not authorized to view this result');
            }
        }

        return attempt;
    }

    async getAttemptsByExam(examId: string, userId: string, page = 1, limit = 20) {
        // Verify the user owns the exam's company
        const exam = await this.prisma.exam.findUnique({
            where: { id: examId },
            include: { company: true },
        });

        if (!exam || exam.company.userId !== userId) {
            throw new BadRequestException('Not authorized to view these attempts');
        }

        const skip = (page - 1) * limit;

        const [attempts, total] = await Promise.all([
            this.prisma.attempt.findMany({
                where: { examId },
                skip,
                take: limit,
                orderBy: { startedAt: 'desc' },
                include: {
                    candidate: {
                        select: { id: true, email: true, name: true },
                    },
                },
            }),
            this.prisma.attempt.count({ where: { examId } }),
        ]);

        return {
            attempts,
            meta: { total, page, limit, totalPages: Math.ceil(total / limit) },
        };
    }

    async getMyCandidateAttempts(candidateId: string) {
        return this.prisma.attempt.findMany({
            where: { candidateId },
            orderBy: { startedAt: 'desc' },
            include: {
                exam: {
                    select: {
                        id: true,
                        title: true,
                        totalMarks: true,
                        duration: true,
                        company: { select: { name: true } },
                    },
                },
            },
        });
    }

    private async calculateScore(
        examId: string,
        answers: Record<string, string>,
    ): Promise<number> {
        const questions = await this.prisma.question.findMany({
            where: { examId },
        });

        let totalScore = 0;
        for (const question of questions) {
            const submittedAnswer = answers[question.id];
            if (
                submittedAnswer &&
                submittedAnswer.trim().toLowerCase() ===
                question.correctAnswer.trim().toLowerCase()
            ) {
                totalScore += question.marks;
            }
        }

        return totalScore;
    }
}
